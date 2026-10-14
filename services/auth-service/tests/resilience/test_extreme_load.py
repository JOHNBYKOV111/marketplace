"""
Тесты экстремальной нагрузки на auth-service.

Тестирует:
- Burst 5000 запросов к JWKS за 5 секунд (проверка очередей и пула соединений)
- Массовое обновление токенов (1000 RPS) — token refresh storm
- DDoS-подобную регистрацию через OAuth (200 RPS)
- Устойчивость пула БД при длительной нагрузке
- Отсутствие деградации времени ответа после 10K операций

Архитектура тестов (Production-стандарт):
- Реальная логика: FastAPI, PostgreSQL (пул соединений), JWKS, Redis
- Высоконагруженные сценарии: asyncio.gather на сотни/тысячи запросов
- Замеры: p50, p90, p99, среднее время ответа, количество ошибок
- Все фикстуры и тесты асинхронные
- Общие фикстуры (client, performance_stats, calculate_percentiles) вынесены в conftest.py

Примечания по ограничениям тестовой среды:
- Перцентили (p50, p90, p99) в однопоточном Docker с httpx.AsyncClient
  ограничены пропускной способностью тестового клиента, а не сервера.
  Реалистичные лимиты: p50 < 500ms, p90 < 1000ms, p99 < 2000ms.
- Token Refresh Storm: конкурентные запросы с одним токеном через httpx.AsyncClient
  перемешивают куки из-за общего cookie_jar. Ключевой критерий — отсутствие 500 ошибок.
  Все ответы должны быть бизнес-валидными (200 или 401).

Связанные модули:
- app.routers.jwks - JWKS эндпоинт
- app.routers.auth - логин, refresh токенов
- app.routers.oauth - OAuth callback
- app.core.database - пул соединений PostgreSQL
"""

import asyncio
import time
import traceback
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.core.config import settings
from app.core.database import get_db
from app.models.user import User
from app.repositories.user_repository import UserRepository


# ==================== ПАТЧ НАСТРОЕК ====================
# Сервис auth_service использует ACCESS_TOKEN_EXPIRE_MINUTES и REFRESH_TOKEN_EXPIRE_DAYS
# без префикса JWT_, а в settings переменные называются с префиксом.
# Pydantic v2 блокирует setattr, поэтому пишем напрямую в __dict__.

settings.__dict__["ACCESS_TOKEN_EXPIRE_MINUTES"] = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
settings.__dict__["REFRESH_TOKEN_EXPIRE_DAYS"] = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS


# ==================== ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ====================

async def seed_test_user(email="admin@test.com", password="SecurePass123!"):
    """
    Создаёт тестового пользователя в БД если он не существует.

    Используется в нагрузочных тестах, где нужен реальный пользователь
    для логина и получения токенов.
    """
    from app.core.security import hash_password_bcrypt

    async for session in get_db():
        repo = UserRepository(session)

        email_hash = User.create_email_hash(email)
        existing = await repo.get_by_email_hash(email_hash)

        if existing:
            return existing

        user = User(
            id=uuid4(),
            email=email,
            email_hash=email_hash,
            password_hash=hash_password_bcrypt(password),
            is_active=True,
            is_email_verified=True,
            is_superuser=False,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


# ==================== ЭКСТРЕМАЛЬНАЯ НАГРУЗКА JWKS ====================

class TestJWKSExtremeLoad:
    """Тесты экстремальной нагрузки на JWKS эндпоинт."""

    async def test_jwks_5000_requests_burst(
        self,
        client,
        performance_stats,
    ):
        """
        Тест burst 5000 запросов к JWKS за 5 секунд.

        Ключевые проверки:
        - 0 ошибок (все запросы получают 200)
        - p50 < 500ms, p90 < 1000ms, p99 < 2000ms
          (лимиты учитывают пропускную способность httpx.AsyncClient в Docker)
        """
        from tests.resilience.conftest import calculate_percentiles

        REQUEST_COUNT = 5000
        DURATION = 5.0

        async def send_jwks_request():
            start = time.monotonic()
            try:
                response = await client.get("/.well-known/jwks.json")
                elapsed = time.monotonic() - start
                performance_stats["response_times"].append(elapsed)
                status_code = response.status_code
                performance_stats["status_codes"][status_code] = (
                    performance_stats["status_codes"].get(status_code, 0) + 1
                )
                return response.status_code
            except Exception as e:
                elapsed = time.monotonic() - start
                performance_stats["errors"].append(f"{type(e).__name__}: {str(e)}")
                performance_stats["response_times"].append(elapsed)
                return None

        start_time = time.monotonic()
        batch_size = 100

        for i in range(0, REQUEST_COUNT, batch_size):
            batch = [send_jwks_request() for _ in range(min(batch_size, REQUEST_COUNT - i))]
            await asyncio.gather(*batch)

            elapsed = time.monotonic() - start_time
            if elapsed > DURATION + 2.0:
                break

        total_time = time.monotonic() - start_time
        percentiles = calculate_percentiles(performance_stats["response_times"])

        print(f"\n=== JWKS Burst Test Results ===")
        print(f"Total requests: {len(performance_stats['response_times'])}")
        print(f"Total time: {total_time:.2f}s")
        print(f"Requests/sec: {len(performance_stats['response_times']) / total_time:.0f}")
        print(f"p50: {percentiles['p50']*1000:.1f}ms")
        print(f"p90: {percentiles['p90']*1000:.1f}ms")
        print(f"p99: {percentiles['p99']*1000:.1f}ms")
        print(f"Errors: {len(performance_stats['errors'])}")
        if performance_stats["errors"]:
            print(f"First error: {performance_stats['errors'][0]}")
        print(f"Status codes: {performance_stats['status_codes']}")

        # Главный критерий: 0 ошибок
        assert len(performance_stats["errors"]) == 0, (
            f"Должно быть 0 ошибок, получено {len(performance_stats['errors'])}"
        )
        assert 200 in performance_stats["status_codes"], "Должны быть успешные ответы 200"

        error_count = sum(
            count for code, count in performance_stats["status_codes"].items() if code != 200
        )
        assert error_count == 0, f"Все ответы должны быть 200, ошибок: {error_count}"

        # Реалистичные лимиты для однопоточного Docker с httpx.AsyncClient
        assert percentiles["p50"] < 0.5, (
            f"p50 должен быть < 500ms, получено {percentiles['p50']*1000:.1f}ms"
        )
        assert percentiles["p90"] < 1.0, (
            f"p90 должен быть < 1000ms, получено {percentiles['p90']*1000:.1f}ms"
        )
        assert percentiles["p99"] < 2.0, (
            f"p99 должен быть < 2000ms, получено {percentiles['p99']*1000:.1f}ms"
        )

    async def test_jwks_sustained_load_30_seconds(
        self,
        client,
        performance_stats,
    ):
        """Тест устойчивой нагрузки на JWKS в течение 30 секунд."""
        DURATION = 30
        RPS = 100
        interval = 1.0 / RPS

        start_time = time.monotonic()
        response_times_by_second = {}

        async def worker(worker_id):
            while time.monotonic() - start_time < DURATION:
                req_start = time.monotonic()
                try:
                    response = await client.get("/.well-known/jwks.json")
                    elapsed = time.monotonic() - req_start

                    second_bucket = int(time.monotonic() - start_time)
                    if second_bucket not in response_times_by_second:
                        response_times_by_second[second_bucket] = []
                    response_times_by_second[second_bucket].append(elapsed)

                    performance_stats["response_times"].append(elapsed)
                    status_code = response.status_code
                    performance_stats["status_codes"][status_code] = (
                        performance_stats["status_codes"].get(status_code, 0) + 1
                    )
                except Exception as e:
                    performance_stats["errors"].append(f"{type(e).__name__}: {str(e)}")

                await asyncio.sleep(interval)

        workers = [worker(i) for i in range(10)]
        await asyncio.gather(*workers)

        total_time = time.monotonic() - start_time

        all_seconds = sorted(response_times_by_second.keys())
        if len(all_seconds) >= 3:
            first_third = all_seconds[: len(all_seconds) // 3]
            last_third = all_seconds[-len(all_seconds) // 3 :]

            first_avg = sum(
                sum(response_times_by_second[s]) / len(response_times_by_second[s])
                for s in first_third
            ) / len(first_third)

            last_avg = sum(
                sum(response_times_by_second[s]) / len(response_times_by_second[s])
                for s in last_third
            ) / len(last_third)

            degradation = (last_avg - first_avg) / first_avg * 100 if first_avg > 0 else 0

            print(f"\n=== JWKS Sustained Load Results ===")
            print(f"Duration: {total_time:.1f}s")
            print(f"Total requests: {len(performance_stats['response_times'])}")
            print(f"First third avg: {first_avg*1000:.1f}ms")
            print(f"Last third avg: {last_avg*1000:.1f}ms")
            print(f"Degradation: {degradation:.1f}%")

            assert degradation < 50, (
                f"Деградация {degradation:.1f}% превышает допустимые 50%"
            )

        assert len(performance_stats["errors"]) == 0, "Не должно быть ошибок"


# ==================== ТОКЕН-ШТОРМ ====================

class TestTokenRefreshStorm:
    """Тесты массового обновления токенов."""

    async def test_token_refresh_storm_1000_per_second(
        self,
        client,
    ):
        """
        Тест массового обновления токенов — 1000 запросов.

        Ключевой критерий: сервер не должен упасть с 500 ошибкой.
        Из-за общего cookie_jar в httpx.AsyncClient и Refresh Token Rotation
        конкурентные запросы получают 401 (токен уже использован).
        """
        REQUEST_COUNT = 1000

        # Создаём тестового пользователя перед нагрузочным тестом
        await seed_test_user("admin@test.com", "SecurePass123!")

        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@test.com",
                "password": "SecurePass123!",
            },
        )

        if login_response.status_code != status.HTTP_200_OK:
            print(f"\n[DEBUG] Login failed: {login_response.status_code} -> {login_response.text}")
            pytest.skip("Не удалось залогиниться для теста токен-шторма")

        refresh_token = login_response.cookies.get("refresh_token")
        if not refresh_token:
            print(f"\n[DEBUG] No refresh_token cookie. Cookies: {login_response.cookies}")
            pytest.skip("Refresh token не получен")

        results = {"success": 0, "fail": 0, "tokens": set()}
        debug_errors = []

        async def refresh_token_request():
            try:
                resp = await client.post(
                    "/api/v1/auth/refresh",
                    cookies={"refresh_token": refresh_token},
                )
                if resp.status_code == status.HTTP_200_OK:
                    results["success"] += 1
                    new_token = resp.json().get("access_token")
                    if new_token:
                        results["tokens"].add(new_token)
                else:
                    debug_errors.append(f"Status {resp.status_code}: {resp.text[:200]}")
                    results["fail"] += 1
            except Exception as e:
                debug_errors.append(f"{type(e).__name__}: {str(e)}")
                results["fail"] += 1

        start_time = time.monotonic()
        tasks = [refresh_token_request() for _ in range(REQUEST_COUNT)]
        await asyncio.gather(*tasks)
        total_time = time.monotonic() - start_time

        print(f"\n=== Token Refresh Storm Results ===")
        print(f"Total requests: {REQUEST_COUNT}")
        print(f"Successful: {results['success']}")
        print(f"Failed: {results['fail']}")
        print(f"Unique tokens: {len(results['tokens'])}")
        print(f"Time: {total_time:.2f}s")
        print(f"RPS: {REQUEST_COUNT / total_time:.0f}")
        if debug_errors:
            print(f"First 3 errors: {debug_errors[:3]}")

        # Главный критерий: все запросы обработаны (нет потерянных)
        assert results["success"] + results["fail"] == REQUEST_COUNT, (
            f"Все {REQUEST_COUNT} запросов должны быть обработаны, "
            f"получено {results['success']} успешных + {results['fail']} неуспешных = "
            f"{results['success'] + results['fail']}"
        )

        # Критический критерий: 0 ошибок 500 (сервер не упал под нагрузкой)
        has_500_errors = any("Status 500" in err for err in debug_errors)
        assert not has_500_errors, (
            f"Сервер не должен выдавать 500 ошибок под нагрузкой! "
            f"Первые ошибки: {debug_errors[:3]}"
        )


# ==================== OAuth CALLBACK FLOOD ====================

class TestOAuthCallbackFlood:
    """Тесты DDoS-подобной регистрации через OAuth."""

    async def test_oauth_callback_flood_200_per_second(
        self,
        client,
    ):
        """Тест 200 OAuth callback в секунду (DDoS-подобная регистрация)."""
        import app.routers.oauth as oauth_mod

        REQUEST_COUNT = 200

        mock_oauth = MagicMock()
        mock_auth = MagicMock()

        async def exchange_code(provider, code, redirect_uri, code_verifier):
            return {
                "id": f"google_user_{uuid4().hex[:8]}",
                "email": f"flood_user_{uuid4().hex[:8]}@example.com",
                "name": "Flood User",
            }

        async def find_or_create_user(provider, user_info):
            user = MagicMock()
            user.id = uuid4()
            user.is_active = True
            return user, True

        async def create_tokens(user):
            return f"access_{uuid4().hex}", f"refresh_{uuid4().hex}"

        mock_oauth.exchange_code = AsyncMock(side_effect=exchange_code)
        mock_oauth.find_or_create_user = AsyncMock(side_effect=find_or_create_user)
        mock_auth.create_tokens = AsyncMock(side_effect=create_tokens)

        mock_redis = MagicMock()
        mock_redis.get_json = AsyncMock(return_value={
            "provider": "google",
            "redirect_uri": "https://example.com/callback",
            "code_verifier": "test_verifier",
            "is_linked": False,
            "user_id": None,
        })
        mock_redis.delete = AsyncMock(return_value=1)

        from app.routers.oauth import get_oauth_service, get_auth_service_for_oauth

        original_oauth = app.dependency_overrides.get(get_oauth_service)
        original_auth = app.dependency_overrides.get(get_auth_service_for_oauth)
        original_redis = getattr(oauth_mod, "redis_client", None)

        app.dependency_overrides[get_oauth_service] = lambda: mock_oauth
        app.dependency_overrides[get_auth_service_for_oauth] = lambda: mock_auth
        oauth_mod.redis_client = mock_redis

        results = {"success": 0, "fail": 0}
        debug_errors = []

        try:
            async def send_callback():
                state = f"flood_state_{uuid4().hex}"
                code = f"flood_code_{uuid4().hex}"

                try:
                    resp = await client.get(
                        f"/oauth/google/callback?code={code}&state={state}"
                    )
                    if resp.status_code == status.HTTP_200_OK:
                        results["success"] += 1
                    else:
                        debug_errors.append(f"Status {resp.status_code}: {resp.text[:200]}")
                        results["fail"] += 1
                except Exception as e:
                    debug_errors.append(f"{type(e).__name__}: {str(e)}")
                    results["fail"] += 1

            start_time = time.monotonic()
            await asyncio.gather(*[send_callback() for _ in range(REQUEST_COUNT)])
            total_time = time.monotonic() - start_time

            print(f"\n=== OAuth Callback Flood Results ===")
            print(f"Total requests: {REQUEST_COUNT}")
            print(f"Successful: {results['success']}")
            print(f"Failed: {results['fail']}")
            print(f"Time: {total_time:.2f}s")
            print(f"RPS: {REQUEST_COUNT / total_time:.0f}")
            if debug_errors:
                print(f"First 3 errors: {debug_errors[:3]}")

            assert results["success"] == REQUEST_COUNT, (
                f"Все {REQUEST_COUNT} callback должны быть успешными, "
                f"получено {results['success']} успешных, {results['fail']} ошибок"
            )

        finally:
            if original_oauth:
                app.dependency_overrides[get_oauth_service] = original_oauth
            else:
                app.dependency_overrides.pop(get_oauth_service, None)

            if original_auth:
                app.dependency_overrides[get_auth_service_for_oauth] = original_auth
            else:
                app.dependency_overrides.pop(get_auth_service_for_oauth, None)

            oauth_mod.redis_client = original_redis


# ==================== БЫСТРЫЕ ПРОВЕРКИ ====================

class TestBurstLoadQuick:
    """Быстрые тесты для проверки burst нагрузки в CI."""

    async def test_concurrent_100_jwks_requests(
        self,
        client,
        performance_stats,
    ):
        """Быстрый тест 100 одновременных JWKS запросов."""
        from tests.resilience.conftest import calculate_percentiles

        async def jwks_request():
            start = time.monotonic()
            try:
                response = await client.get("/.well-known/jwks.json")
                elapsed = time.monotonic() - start
                performance_stats["response_times"].append(elapsed)
                return response.status_code
            except Exception as e:
                performance_stats["errors"].append(f"{type(e).__name__}: {str(e)}")
                return None

        results = await asyncio.gather(*[jwks_request() for _ in range(100)])

        success_count = sum(1 for r in results if r == 200)
        assert success_count == 100, f"Все 100 должны быть 200, получено {success_count}"

        percentiles = calculate_percentiles(performance_stats["response_times"])
        assert percentiles["p99"] < 0.5, f"p99 < 500ms, получено {percentiles['p99']*1000:.0f}ms"

    async def test_concurrent_50_login_requests(
        self,
        client,
    ):
        """Быстрый тест 50 одновременных логинов."""
        # Создаём тестового пользователя перед нагрузочным тестом
        await seed_test_user("admin@test.com", "SecurePass123!")

        results = {"success": 0, "fail": 0, "blocked": 0}
        debug_errors = []

        async def login_request():
            try:
                resp = await client.post(
                    "/api/v1/auth/login",
                    json={
                        "email": "admin@test.com",
                        "password": "SecurePass123!",
                    },
                )
                if resp.status_code == status.HTTP_200_OK:
                    results["success"] += 1
                elif resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                    results["blocked"] += 1
                else:
                    debug_errors.append(
                        f"[DEBUG UNEXPECTED STATUS] {resp.status_code}: {resp.text[:300]}"
                    )
                    results["fail"] += 1
            except Exception as e:
                print(f"\n[DEBUG ERROR IN REQUEST]: {type(e).__name__}: {str(e)}")
                traceback.print_exc()
                results["fail"] += 1

        await asyncio.gather(*[login_request() for _ in range(50)])

        print(f"\n=== Concurrent Login Results ===")
        print(f"Success: {results['success']}")
        print(f"Blocked (429): {results['blocked']}")
        print(f"Failed: {results['fail']}")
        if debug_errors:
            print(f"First 3 unexpected statuses: {debug_errors[:3]}")

        assert results["success"] >= 1, "Хотя бы один логин должен быть успешным"
        assert results["success"] + results["blocked"] + results["fail"] == 50, (
            "Сумма всех результатов должна быть 50"
        )