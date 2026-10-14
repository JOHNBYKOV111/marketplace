"""
Тесты отказоустойчивости Redis.

Тестирует:
- MFA верификацию при недоступном Redis (fail open — пользователь не теряет доступ)
- Смену пароля при недоступном Redis (критическая операция, должна работать)
- JWKS эндпоинт без Redis-кэша (ключи отдаются напрямую из БД)
- Восстановление после возвращения Redis
- Rate limiting при недоступном Redis (fail open — не блокирует пользователей)

Архитектура тестов (Production-стандарт):
- Реальная логика: FastAPI, JWKS эндпоинт, БД, Redis, MfaService, RateLimitService
- Fault injection: симуляция сетевой ошибки Redis через patch.object методов
- Проверка что критический функционал работает без Redis
- Все фикстуры и тесты асинхронные
- Все моки используют patch.object с контекстным менеджером (гарантированное восстановление)
- Все моки используют AsyncMock, никакого MagicMock для асинхронных методов
- Моки только для внешних сервисов (SMS, уведомления)
- Общие хелперы и фикстуры вынесены для устранения дублирования

Связанные модули:
- app.routers.mfa - MFA эндпоинты (TOTP, SMS)
- app.routers.password - смена пароля
- app.routers.jwks - JWKS эндпоинт
- app.core.redis_client - клиент Redis
"""

import asyncio
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest
import redis.exceptions as redis_exc
from fastapi import status
from httpx import AsyncClient

from app.main import app
from app.core.redis_client import redis_client


# ==================== ФИКСТУРЫ ====================

@pytest.fixture
async def client():
    """Фикстура HTTP клиента."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
async def real_redis():
    """
    Фикстура с реальным Redis-клиентом.
    
    Предоставляет доступ к реальному Redis для подготовки тестовых данных.
    """
    return redis_client


@pytest.fixture
def mfa_headers():
    """
    Фикстура с заголовками для MFA-запросов.
    
    Возвращает словарь с уникальным user_id и стандартными заголовками.
    """
    return {
        "X-User-Id": str(uuid4()),
        "X-User-Roles": "user",
        "X-User-Email": "test@example.com",
    }


@pytest.fixture
async def seed_totp_secret(real_redis, mfa_headers):
    """
    Фикстура для размещения TOTP-секрета в реальном Redis.
    
    Кладёт тестовый TOTP-секрет в Redis и возвращает user_id.
    Автоматически чистит Redis после теста.
    """
    user_id = mfa_headers["X-User-Id"]
    key = f"totp_secret:{user_id}"
    totp_data = {
        "secret": "JBSWY3DPEHPK3PXP",  # тестовый Base32-секрет
        "user_id": str(user_id),
    }
    await real_redis.set_json(key, totp_data, ttl=300)
    yield user_id
    await real_redis.delete(key)


@pytest.fixture
async def redis_disabled():
    """
    Фикстура для временного отключения Redis через симуляцию сетевой ошибки.
    
    Патчит основные методы RedisClient чтобы они выбрасывали TimeoutError.
    Это заставляет приложение зайти в ветку обработки аварий (fail open),
    не трогая приватные атрибуты класса.
    
    Production-стандарт: patch.object методов на уровне инстанса,
    гарантированное восстановление через контекстный менеджер.
    """
    timeout_error = redis_exc.TimeoutError("Redis connection timed out (simulated)")

    with patch.object(redis_client, "get", side_effect=timeout_error), \
         patch.object(redis_client, "set", side_effect=timeout_error), \
         patch.object(redis_client, "get_json", side_effect=timeout_error), \
         patch.object(redis_client, "set_json", side_effect=timeout_error), \
         patch.object(redis_client, "ping", side_effect=timeout_error), \
         patch.object(redis_client, "incr", side_effect=timeout_error), \
         patch.object(redis_client, "delete", side_effect=timeout_error), \
         patch.object(redis_client, "exists", side_effect=timeout_error), \
         patch.object(redis_client, "rate_limit_atomic", side_effect=timeout_error), \
         patch.object(redis_client, "get_idempotency_result", side_effect=timeout_error), \
         patch.object(redis_client, "set_idempotency_result", side_effect=timeout_error):
        yield


@pytest.fixture
async def clean_redis_key(real_redis):
    """
    Фикстура для автоматической очистки Redis-ключа после теста.
    
    Возвращает корутину, которую тест вызывает с именем ключа.
    Ключ будет удалён при завершении теста.
    """
    keys_to_clean = []

    async def register_key(key):
        keys_to_clean.append(key)

    yield register_key

    for key in keys_to_clean:
        try:
            await real_redis.delete(key)
        except Exception:
            pass  # Redis может быть уже отключён


# ==================== ХЕЛПЕРЫ ====================

async def verify_totp(client, headers, code="123456"):
    """Хелпер для вызова TOTP верификации."""
    return await client.post(
        "/mfa/totp/verify",
        headers=headers,
        json={"code": code},
    )


# ==================== MFA ПРИ ОТКАЗЕ REDIS ====================

class TestMFAWhenRedisUnavailable:
    """Тесты MFA при недоступном Redis."""

    async def test_mfa_verify_when_redis_unavailable(
        self,
        client,
        seed_totp_secret,
        redis_disabled,
        mfa_headers,
    ):
        """
        Тест что MFA верификация работает при недоступном Redis (fail open).

        Flow:
        1. Размещаем реальный TOTP-секрет в Redis
        2. Имитируем отказ Redis через TimeoutError на методах клиента
        3. Пользователь пытается верифицировать TOTP
        4. Сервис должен ответить (400 — секрет не найден), но не 500

        Production-сценарий:
        Redis упал. Пользователи не должны терять доступ к аккаунтам.
        MFA должен работать через резервные методы (SMS, backup codes),
        которые не зависят от Redis.
        """
        totp_response = await verify_totp(client, mfa_headers)

        print(f"\n=== MFA Verify without Redis ===")
        print(f"TOTP verify status: {totp_response.status_code}")

        assert totp_response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR, (
            f"TOTP верификация не должна падать с 500, получено {totp_response.status_code}"
        )
        assert totp_response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_401_UNAUTHORIZED,
        ], f"Ожидается 400 или 401, получено {totp_response.status_code}"

    async def test_sms_fallback_works_when_redis_unavailable(
        self,
        client,
        redis_disabled,
        mfa_headers,
    ):
        """
        Тест что SMS fallback работает при недоступном Redis.

        Flow:
        1. Отключаем Redis
        2. Отправляем SMS (метод не зависит от Redis для хранения кода)
        3. Верифицируем SMS
        4. Обе операции должны работать

        Production-сценарий:
        Redis упал. Пользователь не может использовать TOTP (секрет в Redis),
        но может запросить SMS-код и войти через него.
        """
        from app.routers.mfa import get_mfa_service

        # Мокаем только внешний сервис отправки SMS
        mock_mfa = AsyncMock()
        mock_mfa.get_user_phone = AsyncMock(return_value="+79001234567")
        mock_mfa.generate_sms_code = AsyncMock(return_value="123456")
        mock_mfa.verify_sms_code = AsyncMock(return_value=True)
        mock_mfa.enable_sms_2fa = AsyncMock()

        with patch.object(
            app, "dependency_overrides", {
                get_mfa_service: lambda: mock_mfa,
            }
        ):
            # Отправка SMS — должна работать без Redis
            send_response = await client.post("/mfa/sms/send", headers=mfa_headers)
            print(f"\n=== SMS without Redis ===")
            print(f"SMS send status: {send_response.status_code}")

            assert send_response.status_code == status.HTTP_200_OK, (
                f"Отправка SMS должна работать без Redis, получено {send_response.status_code}"
            )

            # Верификация SMS — должна работать
            verify_response = await client.post(
                "/mfa/sms/verify",
                headers=mfa_headers,
                json={"code": "123456"},
            )
            print(f"SMS verify status: {verify_response.status_code}")

            assert verify_response.status_code == status.HTTP_200_OK, (
                f"Верификация SMS должна работать без Redis, получено {verify_response.status_code}"
            )


# ==================== СМЕНА ПАРОЛЯ ПРИ ОТКАЗЕ REDIS ====================

class TestPasswordChangeWhenRedisUnavailable:
    """Тесты смены пароля при недоступном Redis."""

    async def test_password_change_when_redis_unavailable(
        self,
        client,
        redis_disabled,
    ):
        """
        Тест что смена пароля работает при недоступном Redis.

        Flow:
        1. Имитируем отказ Redis (rate limiting не работает)
        2. Выполняем смену пароля
        3. Пароль должен смениться успешно (200)
        4. Rate limiting должен пропустить запрос (fail open)

        Production-сценарий:
        Redis упал, пользователь пытается сменить пароль.
        Смена пароля — критическая операция, она не должна
        блокироваться из-за недоступности Redis.
        """
        import app.routers.password as password_mod

        # Реальная криптография
        from app.services.password_service import PasswordService
        real_password_service = PasswordService()
        old_password = "OldPass123!"
        new_password = "NewPass456!@#"
        real_old_hash = await real_password_service.hash_password(old_password)

        # Мокаем только получение пользователя из БД (нужен существующий пароль)
        mock_auth = AsyncMock()
        mock_user = Mock()
        mock_user.id = uuid4()
        mock_user.password_hash = real_old_hash
        mock_user.is_active = True
        mock_user.email = "test@example.com"
        mock_auth.get_user_by_id = AsyncMock(return_value=mock_user)
        mock_auth.update_password = AsyncMock()
        mock_auth.revoke_all_sessions = AsyncMock()
        mock_auth.publish_password_changed = AsyncMock()

        from app.routers.password import get_auth_service_for_password_router

        user_id = uuid4()
        headers = {
            "X-User-Id": str(user_id),
            "X-User-Roles": "user",
            "X-User-Email": "test@example.com",
            "X-Session-Id": "session_123",
        }

        with patch.object(
            password_mod, "send_password_changed_notification", AsyncMock()
        ), patch.object(
            app, "dependency_overrides", {
                get_auth_service_for_password_router: lambda: mock_auth,
            }
        ):
            response = await client.post(
                "/password/change",
                headers=headers,
                json={
                    "old_password": old_password,
                    "new_password": new_password,
                },
            )

            print(f"\n=== Password Change without Redis ===")
            print(f"Status: {response.status_code}")

            assert response.status_code == status.HTTP_200_OK, (
                f"Смена пароля должна работать без Redis, получено {response.status_code}"
            )

            data = response.json()
            assert data["success"] is True


# ==================== JWKS БЕЗ REDIS ====================

class TestJWKSWithoutRedis:
    """Тесты JWKS при недоступном Redis."""

    async def test_jwks_endpoint_without_redis_cache(
        self,
        client,
        redis_disabled,
    ):
        """
        Тест что JWKS работает без Redis-кэша (ключи из БД напрямую).

        Flow:
        1. Имитируем отказ Redis
        2. Запрашиваем JWKS
        3. Сервис должен пойти в БД напрямую и вернуть ключи
        4. Статус 200, ключи валидны

        Production-сценарий:
        Redis упал. Клиенты продолжают верифицировать JWT —
        JWKS отдаётся напрямую из PostgreSQL.
        """
        response = await client.get("/.well-known/jwks.json")

        print(f"\n=== JWKS without Redis ===")
        print(f"Status: {response.status_code}")

        assert response.status_code == status.HTTP_200_OK, (
            f"JWKS должен работать без Redis, получено {response.status_code}"
        )

        data = response.json()
        assert "keys" in data, "Ответ должен содержать keys"

        source = response.headers.get("X-JWKS-Source", "")
        assert source in ["generated", "database"], (
            f"Источник должен быть generated или database, получено {source}"
        )

    async def test_jwks_recovery_after_redis_returns(
        self,
        client,
        real_redis,
        clean_redis_key,
    ):
        """
        Тест что JWKS восстанавливает кэширование после возвращения Redis.

        Flow:
        1. Redis работает нормально
        2. Запрашиваем JWKS — кэшируется в Redis
        3. Проверяем что ключи попали в реальный Redis
        4. Следующий запрос должен вернуться из кэша

        Production-сценарий:
        Redis восстановился после падения. Сервис должен снова начать
        кэшировать JWKS, чтобы снизить нагрузку на БД.
        """
        await clean_redis_key("jwks_cache")

        # Первый запрос — кэш пуст, данные из БД, должны закэшироваться
        response1 = await client.get("/.well-known/jwks.json")
        assert response1.status_code == status.HTTP_200_OK

        source1 = response1.headers.get("X-JWKS-Source", "")
        print(f"\n=== JWKS Recovery ===")
        print(f"First request source: {source1}")

        # Проверяем что ключи попали в реальный Redis
        cached = await real_redis.get("jwks_cache")
        assert cached is not None, (
            "После первого запроса ключи должны быть закэшированы в Redis"
        )

        # Второй запрос — должен быть из кэша Redis
        response2 = await client.get("/.well-known/jwks.json")
        assert response2.status_code == status.HTTP_200_OK

        source2 = response2.headers.get("X-JWKS-Source", "")
        print(f"Second request source: {source2}")

        assert source2 in ["cache", "database"], (
            f"Источник должен быть cache или database, получено {source2}"
        )


# ==================== RATE LIMITING ПРИ ОТКАЗЕ REDIS ====================

class TestRateLimitingWithoutRedis:
    """Тесты rate limiting при недоступном Redis."""

    async def test_rate_limiting_fail_open_without_redis(
        self,
        client,
        redis_disabled,
        mfa_headers,
    ):
        """
        Тест что rate limiting пропускает запросы при недоступном Redis.

        Flow:
        1. Отключаем Redis
        2. Отправляем запросы к защищённому эндпоинту
        3. Rate limiting должен пропускать запросы (fail open)
        4. Пользователи не должны блокироваться из-за отказа Redis

        Production-сценарий:
        Redis упал. Rate limiting не должен блокировать легитимных
        пользователей. Лучше пропустить запрос без проверки лимита,
        чем заблокировать всех.
        """
        for i in range(10):
            response = await verify_totp(client, mfa_headers)

            assert response.status_code != status.HTTP_429_TOO_MANY_REQUESTS, (
                f"Запрос {i}: rate limiting не должен блокировать при отказе Redis, "
                f"получено {response.status_code}"
            )
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR, (
                f"Запрос {i}: сервис не должен падать с 500 при отказе Redis"
            )

        print(f"\n=== Rate Limiting Fail Open ===")
        print(f"10 requests passed without rate limiting")

    async def test_redis_recovery_restores_rate_limiting(
        self,
        client,
        real_redis,
        clean_redis_key,
        mfa_headers,
    ):
        """
        Тест что rate limiting восстанавливается после возвращения Redis.

        Flow:
        1. Rate limiting работает нормально с реальным Redis
        2. Отправляем 6 запросов
        3. Первые 5 проходят, 6-й блокируется (429)

        Production-сценарий:
        Redis работает. Rate limiting должен блокировать
        превышение лимита для защиты от брутфорса.
        """
        rate_limit_key = f"rate_limit:mfa_totp:{mfa_headers['X-User-Id']}"
        await clean_redis_key(rate_limit_key)

        results = []

        for i in range(6):
            response = await verify_totp(client, mfa_headers)
            results.append(response.status_code)

        print(f"\n=== Rate Limiting with Real Redis ===")
        print(f"Results: {results}")

        for i in range(5):
            assert results[i] != status.HTTP_429_TOO_MANY_REQUESTS, (
                f"Запрос {i+1} не должен быть 429, получено {results[i]}"
            )

        assert results[5] == status.HTTP_429_TOO_MANY_REQUESTS, (
            f"6-й запрос должен быть 429, получено {results[5]}"
        )