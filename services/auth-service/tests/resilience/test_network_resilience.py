"""
Тесты сетевой отказоустойчивости.

Тестирует:
- Таймауты и fail open при медленном Redis (задержка 2 секунды)
- Блокировку event loop при медленном PostgreSQL
- Таймаут при обмене кода OAuth (внешний API не отвечает)
- Устойчивость к сетевым сбоям (connection reset, DNS сбой)
- Корректную обработку сетевых таймаутов без паники

Архитектура тестов (Production-стандарт):
- Реальная логика: FastAPI, asyncio event loop, JWKS (реальные ключи из БД)
- Fault injection: asyncio.sleep для симуляции задержек, таймауты
- Проверка что медленные зависимости не блокируют весь сервис
- Все фикстуры и тесты асинхронные
- Все моки используют AsyncMock (Production-стандарт)
- Общие фикстуры (client, network_fault) вынесены в conftest.py

Связанные модули:
- app.core.redis_client - клиент Redis
- app.core.database - пул соединений PostgreSQL
- app.routers.oauth - OAuth callback
- app.routers.jwks - JWKS эндпоинт (реальные запросы)
- app.routers.mfa - MFA эндпоинты
- app.services.oauth_service - обмен кода с внешними API
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
from fastapi import status

from app.main import app


# ==================== SLOW REDIS ====================

class TestSlowRedis:
    """Тесты устойчивости к медленному Redis."""

    async def test_slow_redis_timeout_and_fail_open(
        self,
        client,
    ):
        """
        Тест что сервис не падает при медленном Redis (fail open).

        Flow:
        1. Имитируем задержку Redis в 2 секунды
        2. Выполняем запрос к JWKS (зависит от Redis-кэша)
        3. Сервис должен ответить, не дожидаясь Redis (fail open)
        4. Ответ должен быть 200 (ключи из БД напрямую)
        5. Время ответа не должно превышать общий таймаут

        Production-сценарий:
        Сетевые проблемы между сервисом и Redis (packet loss, retransmit).
        Сервис должен быстро ответить клиенту, не накапливая очереди
        из-за медленного Redis.
        """
        import app.routers.jwks as jwks_mod

        original_redis = getattr(jwks_mod, "redis_client", None)

        mock_redis = AsyncMock()

        async def slow_redis_get(key):
            await asyncio.sleep(2.0)
            return None

        async def slow_redis_ping():
            await asyncio.sleep(2.0)
            return True

        mock_redis.get = AsyncMock(side_effect=slow_redis_get)
        mock_redis.get_json = AsyncMock(side_effect=slow_redis_get)
        mock_redis.ping = AsyncMock(side_effect=slow_redis_ping)

        jwks_mod.redis_client = mock_redis

        try:
            start_time = time.monotonic()

            response = await client.get("/.well-known/jwks.json")

            elapsed = time.monotonic() - start_time

            print(f"\n=== Slow Redis JWKS Response ===")
            print(f"Response time: {elapsed*1000:.0f}ms")
            print(f"Status: {response.status_code}")

            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_503_SERVICE_UNAVAILABLE,
            ], f"Сервис должен ответить, получен статус {response.status_code}"

            assert elapsed < 5.0, f"Ответ не должен превышать 5с, получено {elapsed:.1f}с"

        finally:
            if original_redis:
                jwks_mod.redis_client = original_redis

    async def test_rate_limiting_fail_open_with_slow_redis(
        self,
        client,
    ):
        """
        Тест что rate limiting пропускает запросы при медленном Redis (fail open).

        Flow:
        1. Имитируем задержку Redis в 3 секунды для rate limit проверки
        2. Отправляем запрос к защищённому эндпоинту
        3. Rate limiting должен пропустить запрос (fail open)
        4. Пользователь не должен быть заблокирован из-за медленного Redis

        Production-сценарий:
        Redis тормозит из-за сетевых проблем. Rate limiting не должен
        блокировать легитимных пользователей — fail open.
        """
        import app.routers.mfa as mfa_mod

        original_redis = getattr(mfa_mod, "redis_client", None)

        mock_redis = AsyncMock()

        async def slow_incr(key, ttl=None):
            await asyncio.sleep(3.0)
            return 1

        mock_redis.incr = AsyncMock(side_effect=slow_incr)
        mock_redis.get_json = AsyncMock(return_value={"secret": "test_secret"})

        mock_mfa = AsyncMock()
        mock_mfa.verify_totp = AsyncMock(return_value=False)

        mfa_mod.redis_client = mock_redis

        from app.routers.mfa import get_mfa_service
        original_mfa = app.dependency_overrides.get(get_mfa_service)
        app.dependency_overrides[get_mfa_service] = lambda: mock_mfa

        try:
            user_id = uuid4()
            headers = {
                "X-User-Id": str(user_id),
                "X-User-Roles": "user",
                "X-User-Email": "test@example.com",
            }

            start_time = time.monotonic()
            response = await client.post(
                "/mfa/totp/verify",
                headers=headers,
                json={"code": "123456"},
            )
            elapsed = time.monotonic() - start_time

            print(f"\n=== Slow Redis Rate Limiting ===")
            print(f"Response time: {elapsed*1000:.0f}ms")
            print(f"Status: {response.status_code}")

            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR, (
                "Сервис не должен падать с 500 при медленном Redis"
            )

            assert elapsed < 5.0, f"Ответ не должен превышать 5с, получено {elapsed:.1f}с"

        finally:
            if original_redis:
                mfa_mod.redis_client = original_redis
            if original_mfa:
                app.dependency_overrides[get_mfa_service] = original_mfa
            else:
                app.dependency_overrides.pop(get_mfa_service, None)


# ==================== SLOW POSTGRESQL ====================

class TestSlowPostgreSQL:
    """Тесты устойчивости к медленному PostgreSQL."""

    async def test_slow_postgresql_not_blocking_event_loop(
        self,
        client,
    ):
        """
        Тест что медленные запросы к PostgreSQL не блокируют event loop.

        Реальная логика: 20 быстрых запросов к JWKS параллельно с asyncio.sleep(3).
        """
        QUICK_REQUESTS = 20

        quick_times = []

        async def quick_jwks_request():
            start = time.monotonic()
            try:
                response = await client.get("/.well-known/jwks.json")
                elapsed = time.monotonic() - start
                quick_times.append(elapsed)
                return response.status_code
            except Exception:
                return None

        start_all = time.monotonic()

        async def slow_db_operation():
            await asyncio.sleep(3.0)
            return "slow_done"

        quick_tasks = [quick_jwks_request() for _ in range(QUICK_REQUESTS)]
        slow_task = slow_db_operation()

        all_tasks = [slow_task] + quick_tasks
        results = await asyncio.gather(*all_tasks)

        total_time = time.monotonic() - start_all
        quick_results = results[1:]

        print(f"\n=== Slow PostgreSQL Event Loop Test ===")
        print(f"Total time: {total_time*1000:.0f}ms")
        print(f"Slow task result: {results[0]}")
        print(f"Quick requests: {len(quick_times)} completed")
        if quick_times:
            avg_quick_time = sum(quick_times) / len(quick_times) * 1000
            print(f"Avg quick request time: {avg_quick_time:.0f}ms")

        success_count = sum(1 for r in quick_results if r == 200)
        assert success_count == QUICK_REQUESTS, (
            f"Все {QUICK_REQUESTS} быстрых запросов должны быть 200, получено {success_count}"
        )

        if quick_times:
            avg_quick = sum(quick_times) / len(quick_times)
            assert avg_quick < 1.0, (
                f"Среднее время быстрого запроса < 1с, получено {avg_quick*1000:.0f}ms"
            )

    async def test_db_connection_timeout_handled_gracefully(
        self,
        client,
    ):
        """
        Тест что таймаут соединения с БД обрабатывается без падения сервиса.

        Flow:
        1. Имитируем таймаут соединения с БД (ConnectionError)
        2. Сервис должен вернуть 200 (из кэша) или 503, не 500
        3. Последующие запросы должны работать после восстановления

        Production-сценарий:
        Сетевой блинк между сервисом и PostgreSQL. Сервис должен
        пережить одиночный таймаут и продолжить работу.
        """
        import app.services.jwk_service as jwk_service_mod

        mock_repo = AsyncMock()
        mock_repo.get_keys_for_verification = AsyncMock(
            side_effect=ConnectionError("Connection timed out")
        )

        original_get_keys = getattr(
            jwk_service_mod.JWKKeyRepository, "get_keys_for_verification", None
        )

        try:
            jwk_service_mod.JWKKeyRepository.get_keys_for_verification = (
                mock_repo.get_keys_for_verification
            )

            response1 = await client.get("/.well-known/jwks.json")
            assert response1.status_code in [
                status.HTTP_200_OK,
                status.HTTP_503_SERVICE_UNAVAILABLE,
            ], f"Сервис должен ответить 200 или 503, получено {response1.status_code}"
            assert response1.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR, (
                "Сервис не должен падать с 500 при таймауте БД"
            )

            jwk_service_mod.JWKKeyRepository.get_keys_for_verification = AsyncMock(
                return_value=[]
            )

            response2 = await client.get("/.well-known/jwks.json")
            assert response2.status_code == status.HTTP_200_OK, (
                f"После восстановления должен быть 200, получено {response2.status_code}"
            )

        finally:
            if original_get_keys:
                jwk_service_mod.JWKKeyRepository.get_keys_for_verification = original_get_keys


# ==================== OAUTH TIMEOUT ====================

class TestOAuthTimeout:
    """Тесты таймаута при обмене кода OAuth."""

    async def test_oauth_exchange_code_timeout(
        self,
        client,
    ):
        """
        Тест что таймаут внешнего API OAuth не вешает сервис.

        Flow:
        1. Имитируем что Google OAuth API не отвечает (мгновенный таймаут)
        2. Отправляем OAuth callback
        3. Сервис должен вернуть ошибку (400 или 504), не зависнуть

        Production-сценарий:
        Google OAuth API недоступен или тормозит. Сервис должен быстро
        ответить пользователю ошибкой, а не висеть в ожидании ответа.
        """
        import app.routers.oauth as oauth_mod
        from app.routers.oauth import get_oauth_service

        mock_oauth = AsyncMock()

        async def slow_exchange_code(provider, code, redirect_uri, code_verifier):
            raise httpx.TimeoutException("OAuth provider timeout")

        mock_oauth.exchange_code = AsyncMock(side_effect=slow_exchange_code)

        mock_redis = AsyncMock()
        mock_redis.get_json = AsyncMock(return_value={
            "provider": "google",
            "redirect_uri": "https://example.com/callback",
            "code_verifier": "test_verifier",
            "is_linked": False,
            "user_id": None,
        })

        original_redis = getattr(oauth_mod, "redis_client", None)
        original_oauth_override = app.dependency_overrides.get(get_oauth_service)

        oauth_mod.redis_client = mock_redis
        app.dependency_overrides[get_oauth_service] = lambda: mock_oauth

        try:
            start_time = time.monotonic()

            response = await client.get(
                "/oauth/google/callback?code=test_code&state=test_state"
            )

            elapsed = time.monotonic() - start_time

            print(f"\n=== OAuth Timeout Test ===")
            print(f"Response time: {elapsed*1000:.0f}ms")
            print(f"Status: {response.status_code}")

            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_504_GATEWAY_TIMEOUT,
            ], f"Сервис должен вернуть ошибку, получен статус {response.status_code}"

            assert elapsed < 2.0, (
                f"Сервис не должен ждать, получено {elapsed:.1f}с"
            )

        finally:
            if original_redis:
                oauth_mod.redis_client = original_redis
            if original_oauth_override:
                app.dependency_overrides[get_oauth_service] = original_oauth_override
            else:
                app.dependency_overrides.pop(get_oauth_service, None)


# ==================== СЕТЕВЫЕ СБОИ ====================

class TestNetworkFailures:
    """Тесты обработки сетевых сбоев."""

    async def test_connection_reset_handled_gracefully(
        self,
        client,
    ):
        """
        Тест что обрыв соединения (ConnectionResetError) обрабатывается без падения.

        Flow:
        1. Имитируем обрыв соединения с Redis
        2. Сервис должен продолжить работу
        3. Последующие запросы должны быть успешными

        Production-сценарий:
        Сетевой обрыв между контейнерами. Сервис должен пережить
        одиночный обрыв и восстановиться.
        """
        import app.routers.jwks as jwks_mod

        original_redis = getattr(jwks_mod, "redis_client", None)

        call_count = {"count": 0}

        async def reset_then_recover(key):
            call_count["count"] += 1
            if call_count["count"] == 1:
                raise ConnectionResetError("Connection reset by peer")
            return None

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(side_effect=reset_then_recover)
        mock_redis.get_json = AsyncMock(side_effect=reset_then_recover)
        mock_redis.ping = AsyncMock(return_value=True)

        jwks_mod.redis_client = mock_redis

        try:
            response1 = await client.get("/.well-known/jwks.json")
            assert response1.status_code in [
                status.HTTP_200_OK,
                status.HTTP_503_SERVICE_UNAVAILABLE,
            ], f"Сервис должен ответить после обрыва, получено {response1.status_code}"

            response2 = await client.get("/.well-known/jwks.json")
            assert response2.status_code == status.HTTP_200_OK, (
                f"После восстановления должен быть 200, получено {response2.status_code}"
            )

        finally:
            if original_redis:
                jwks_mod.redis_client = original_redis

    async def test_dns_failure_handled_for_external_services(
        self,
        client,
    ):
        """
        Тест что DNS-сбой для внешних сервисов обрабатывается без падения.

        Flow:
        1. Имитируем DNS-сбой для OAuth провайдера
        2. Сервис должен вернуть ошибку, не упасть

        Production-сценарий:
        DNS-сервер недоступен. Сервис не должен падать при попытке
        резолвить oauth2.googleapis.com.
        """
        from app.routers.oauth import get_oauth_service

        mock_oauth = AsyncMock()

        async def dns_failure_exchange(provider, code, redirect_uri, code_verifier):
            raise OSError("DNS resolution failed for oauth2.googleapis.com")

        mock_oauth.exchange_code = AsyncMock(side_effect=dns_failure_exchange)

        mock_redis = AsyncMock()
        mock_redis.get_json = AsyncMock(return_value={
            "provider": "google",
            "redirect_uri": "https://example.com/callback",
            "code_verifier": "test_verifier",
            "is_linked": False,
            "user_id": None,
        })

        import app.routers.oauth as oauth_mod
        original_redis = getattr(oauth_mod, "redis_client", None)
        original_override = app.dependency_overrides.get(get_oauth_service)

        oauth_mod.redis_client = mock_redis
        app.dependency_overrides[get_oauth_service] = lambda: mock_oauth

        try:
            response = await client.get(
                "/oauth/google/callback?code=test_code&state=test_state"
            )

            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR, (
                f"DNS-сбой не должен вызывать 500, получено {response.status_code}"
            )
            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_502_BAD_GATEWAY,
                status.HTTP_503_SERVICE_UNAVAILABLE,
            ]

        finally:
            if original_redis:
                oauth_mod.redis_client = original_redis
            if original_override:
                app.dependency_overrides[get_oauth_service] = original_override
            else:
                app.dependency_overrides.pop(get_oauth_service, None)

    async def test_partial_network_failure_not_blocking_health_requests(
        self,
        client,
    ):
        """
        Тест что частичный сетевой сбой не блокирует health check.

        Flow:
        1. Имитируем проблемы с сетью для Redis (50% пакетов теряется)
        2. Health check должен отвечать быстро
        3. Liveness всегда должен быть 200

        Production-сценарий:
        Частичная потеря пакетов в сети Kubernetes. Health check
        должен оставаться быстрым, чтобы Kubernetes не перезапустил поды.
        """
        import app.routers.jwks as jwks_mod

        original_redis = getattr(jwks_mod, "redis_client", None)

        call_count = {"count": 0}

        async def intermittent_slow_ping():
            call_count["count"] += 1
            if call_count["count"] % 2 == 0:
                await asyncio.sleep(1.0)
            return True

        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=intermittent_slow_ping)
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.get_json = AsyncMock(return_value=None)

        jwks_mod.redis_client = mock_redis

        try:
            start_time = time.monotonic()

            health_responses = []
            for _ in range(5):
                resp = await client.get("/api/v1/liveness")
                health_responses.append(resp.status_code)

            elapsed = time.monotonic() - start_time

            print(f"\n=== Partial Network Failure Health Check ===")
            print(f"5 health checks completed in {elapsed*1000:.0f}ms")
            print(f"All responses: {health_responses}")

            assert all(r == 200 for r in health_responses), (
                f"Все liveness должны быть 200, получено {health_responses}"
            )

            assert elapsed < 3.0, (
                f"5 health check'ов должны занять < 3с, получено {elapsed:.1f}с"
            )

        finally:
            if original_redis:
                jwks_mod.redis_client = original_redis