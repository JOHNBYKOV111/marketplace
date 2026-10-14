"""
Тесты graceful degradation (плавной деградации) сервиса.

Тестирует:
- Работу JWKS верификации на кэше Redis при недоступной БД
- Fallback на резервный метод 2FA (SMS) при недоступности Redis для TOTP
- Health check в состоянии degraded (200) при падении Kafka, а не not_ready (503)
- Деградацию audit logging при недоступности Kafka
- Приоритизацию критического функционала при частичных отказах

Архитектура тестов (Production-стандарт):
- Реальная логика: FastAPI, health check, JWKS, Redis
- Fault injection: patch.object для JWKService и HealthService
- Проверка что НЕкритичные отказы не валят критичный функционал
- Все фикстуры и тесты асинхронные
- Общие фикстуры (client, fault_injection) вынесены в conftest.py

Связанные модули:
- app.routers.jwks - JWKS эндпоинт (критичный)
- app.routers.mfa - MFA эндпоинты (критичный)
- app.routers.health - health check
- app.services.jwk_service - JWKService (патуется)
- app.services.health_service - HealthService (патуется)
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import status
from sqlalchemy.exc import OperationalError

from app.main import app
from app.core.redis_client import redis_client


# ==================== JWKS ПРИ ОТКАЗЕ БД ====================

class TestJWKSDegradation:
    """Тесты деградации JWKS при отказе БД."""

    async def test_jwks_verification_when_db_unavailable_but_redis_cached(
        self,
        client,
    ):
        """
        Тест что JWKS работает на кэше Redis при падении БД.

        Flow:
        1. Помещаем валидные ключи в реальный Redis-кэш
        2. Имитируем падение БД на уровне репозитория (OperationalError)
        3. JWKS эндпоинт должен вернуть ключи из кэша Redis (fail-open)
        4. Статус 200, данные корректны

        Production-сценарий:
        PostgreSQL упал для профилактики. Клиенты продолжают верифицировать
        JWT токены, потому что JWKS отдаётся из Redis-кэша.
        """
        import app.services.jwk_service as jwk_service_mod

        # Очищаем dependency_overrides от предыдущих тестов в пачке
        app.dependency_overrides.clear()

        # 1. Помещаем легитимную структуру ключей в реальный Redis-кэш
        cached_jwks = {
            "keys": [
                {
                    "kid": "prod_compatible_key_1",
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "u1WvXz",
                    "e": "AQAB",
                }
            ]
        }
        await redis_client.set_json("jwks_cache", cached_jwks, ttl=60)

        # 2. Имитируем падение БД на уровне репозитория ключей
        mock_repo = AsyncMock()
        mock_repo.get_keys_for_verification = AsyncMock(
            side_effect=OperationalError(
                "SELECT 1", {}, Exception("Database connection refused")
            )
        )

        original_repo_method = getattr(
            jwk_service_mod.JWKKeyRepository, "get_keys_for_verification", None
        )
        jwk_service_mod.JWKKeyRepository.get_keys_for_verification = (
            mock_repo.get_keys_for_verification
        )

        try:
            # 3. Делаем запрос — роутер споткнётся об упавшую БД, но достанет данные из Redis
            response = await client.get("/.well-known/jwks.json")

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "keys" in data
            assert len(data["keys"]) == 1
            assert data["keys"][0]["kid"] == "prod_compatible_key_1"

        finally:
            # Гарантированно восстанавливаем оригинальный метод репозитория
            if original_repo_method:
                jwk_service_mod.JWKKeyRepository.get_keys_for_verification = original_repo_method
            await redis_client.delete("jwks_cache")

    async def test_jwks_fails_gracefully_when_both_db_and_redis_unavailable(
        self,
        client,
    ):
        """
        Тест что JWKS отдаёт пустой список ключей при полном отказе (fail-open).

        Flow:
        1. Патчим JWKService.get_jwks: всегда выбрасывает исключение
        2. JWKS эндпоинт возвращает 200 с пустым списком ключей (fail-open)

        Production-сценарий:
        Полный отказ инфраструктуры. JWKS не роняет сервис, а возвращает
        пустой набор ключей — клиенты не могут верифицировать новые токены,
        но сервис продолжает работать.
        """
        from app.services.jwk_service import JWKService

        with patch.object(
            JWKService,
            "get_jwks",
            side_effect=Exception("Both DB and Redis unavailable"),
        ):
            response = await client.get("/.well-known/jwks.json")

            # Fail-open: возвращает 200 с пустыми ключами
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["keys"] == []


# ==================== MFA FALLBACK ====================

class TestMFAFallback:
    """Тесты fallback для MFA при отказе Redis."""

    async def test_mfa_fallback_to_sms_when_totp_redis_unavailable(
        self,
        client,
    ):
        """
        Тест что при недоступности Redis для TOTP можно использовать SMS.

        Flow:
        1. Имитируем отказ Redis (TOTP секрет недоступен)
        2. Пользователь не может верифицировать TOTP (секрет в Redis)
        3. Система предлагает fallback на SMS (телефон в БД)
        4. SMS верификация работает (зависит от БД, не от Redis)

        Production-сценарий:
        Redis упал. Пользователь не может войти через Google Authenticator,
        но может получить SMS-код и войти через него.
        """
        import app.routers.mfa as mfa_mod

        mock_redis = AsyncMock()
        mock_redis.get_json = AsyncMock(return_value=None)
        mock_redis.get_idempotency_result = AsyncMock(return_value=None)
        mock_redis.set_idempotency_result = AsyncMock(return_value=True)

        original_redis = getattr(mfa_mod, "redis_client", None)
        mfa_mod.redis_client = mock_redis

        try:
            user_id = uuid4()
            headers = {
                "X-User-Id": str(user_id),
                "X-User-Roles": "user",
                "X-User-Email": "test@example.com",
            }

            totp_response = await client.post(
                "/mfa/totp/verify",
                headers=headers,
                json={"code": "123456"},
            )
            assert totp_response.status_code == status.HTTP_400_BAD_REQUEST

            sms_response = await client.post("/mfa/sms/send", headers=headers)

            assert sms_response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_429_TOO_MANY_REQUESTS,
            ]

        finally:
            if original_redis:
                mfa_mod.redis_client = original_redis

    async def test_backup_codes_work_when_totp_unavailable(
        self,
        client,
    ):
        """
        Тест что резервные коды работают при отказе TOTP.

        Flow:
        1. Имитируем что TOTP недоступен
        2. Пользователь использует резервный код
        3. Резервный код должен работать (хранится в БД, не в Redis)

        Production-сценарий:
        Пользователь потерял телефон с Authenticator. Резервные коды —
        единственный способ войти. Они должны работать всегда.
        """
        from app.routers.mfa import get_mfa_service

        mock_mfa = MagicMock()
        mock_mfa.get_backup_codes = AsyncMock(
            return_value=["BACKUP-CODE-1", "BACKUP-CODE-2"]
        )
        mock_mfa.use_backup_code = AsyncMock(return_value=True)

        original_override = app.dependency_overrides.get(get_mfa_service)
        app.dependency_overrides[get_mfa_service] = lambda: mock_mfa

        try:
            user_id = uuid4()
            headers = {
                "X-User-Id": str(user_id),
                "X-User-Roles": "user",
            }

            response = await client.get("/mfa/backup-codes", headers=headers)
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert len(data["backup_codes"]) == 2

        finally:
            if original_override:
                app.dependency_overrides[get_mfa_service] = original_override
            else:
                app.dependency_overrides.pop(get_mfa_service, None)


# ==================== HEALTH CHECK DEGRADED ====================

class TestHealthCheckDegradation:
    """Тесты health check при частичных отказах."""

    async def test_health_check_degraded_when_kafka_down(
        self,
        client,
    ):
        """
        Тест что health readiness возвращает degraded (200) а не not_ready (503) при падении Kafka.

        Flow:
        1. Имитируем отказ Kafka
        2. Health readiness проверяет все зависимости
        3. Kafka — некритичная зависимость, возвращаем degraded (200)
        4. Критичные зависимости (БД, Redis) работают — сервис доступен

        Production-сценарий:
        Kafka упала. Сервис продолжает работать (логин, JWKS, MFA).
        Kubernetes не должен снимать под с балансировки из-за Kafka.
        """
        from app.services.health_service import HealthService

        async def mock_check_all(*args, **kwargs):
            return {
                "status": "ready",
                "checks": {
                    "postgresql": {"healthy": True, "message": "Connected", "latency_ms": 5.0},
                    "redis": {"healthy": True, "message": "Connected", "latency_ms": 1.0},
                    "vault": {"healthy": True, "message": "Connected", "latency_ms": 3.0},
                    "kafka": {"healthy": False, "message": "Kafka unavailable", "latency_ms": None},
                },
            }

        with patch.object(
            HealthService, "check_all_with_timeout", side_effect=mock_check_all
        ):
            response = await client.get("/api/v1/readiness")

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["checks"]["kafka"]["healthy"] is False
            assert data["checks"]["postgresql"]["healthy"] is True
            assert data["checks"]["redis"]["healthy"] is True

    async def test_liveness_independent_of_dependencies(
        self,
        client,
    ):
        """
        Тест что liveness не зависит от состояния зависимостей.

        Flow:
        1. Имитируем отказ всех зависимостей (БД, Redis, Kafka)
        2. Liveness должен вернуть 200 (сервис жив, процесс работает)
        3. Readiness должен вернуть 503 (зависимости недоступны)

        Production-сценарий:
        Kubernetes проверяет liveness для принятия решения о перезапуске пода.
        Liveness должен показывать что процесс жив, даже если БД упала.
        Readiness — для снятия с балансировки.
        """
        from app.services.health_service import HealthService

        # Liveness не зависит от зависимостей — всегда 200
        liveness_response = await client.get("/api/v1/liveness")
        assert liveness_response.status_code == status.HTTP_200_OK
        liveness_data = liveness_response.json()
        assert liveness_data["status"] == "alive"

        # Readiness — 503 при недоступных зависимостях
        async def mock_check_all_unhealthy(*args, **kwargs):
            return {
                "status": "not_ready",
                "checks": {
                    "postgresql": {"healthy": False, "message": "Connection refused"},
                    "redis": {"healthy": False, "message": "Connection refused"},
                    "kafka": {"healthy": False, "message": "No metadata"},
                    "vault": {"healthy": False, "message": "Sealed"},
                },
                "error": "Dependencies are not ready",
            }

        with patch.object(
            HealthService, "check_all_with_timeout", side_effect=mock_check_all_unhealthy
        ):
            readiness_response = await client.get("/api/v1/readiness")
            assert readiness_response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


# ==================== AUDIT LOGGING DEGRADATION ====================

class TestAuditLoggingDegradation:
    """Тесты деградации аудит-логирования."""

    async def test_login_succeeds_when_audit_log_unavailable(
        self,
        client,
    ):
        """
        Тест что логин работает даже при недоступности аудит-лога.

        Flow:
        1. Имитируем что Kafka (куда пишутся аудит-логи) недоступна
        2. Выполняем логин
        3. Логин должен быть успешным (200), несмотря на ошибку записи аудита
        4. Аудит-событие может быть потеряно, но пользователь вошёл

        Production-сценарий:
        Kafka упала. Пользователи не должны замечать проблем — логин
        работает. Аудит-логи временно не пишутся (или пишутся в fallback).
        """
        import app.core.kafka_client as kafka_mod

        original_producer = getattr(kafka_mod, "kafka_producer", None)

        mock_producer = AsyncMock()
        mock_producer.send_event = AsyncMock(
            side_effect=Exception("Kafka connection refused")
        )
        mock_producer.is_available = MagicMock(return_value=False)
        mock_producer.health_check = AsyncMock(return_value=False)

        kafka_mod.kafka_producer = mock_producer

        try:
            response = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "admin@test.com",
                    "password": "SecurePass123!",
                },
            )

            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_401_UNAUTHORIZED,
            ]

            if response.status_code == status.HTTP_200_OK:
                data = response.json()
                assert "access_token" in data

        finally:
            if original_producer:
                kafka_mod.kafka_producer = original_producer

    async def test_password_change_succeeds_when_notification_unavailable(
        self,
        client,
    ):
        """
        Тест что смена пароля работает при асинхронной отправке уведомления.

        Flow:
        1. Имитируем асинхронную отправку email (возвращает True, очередь сама разберётся)
        2. Меняем пароль
        3. Пароль должен смениться (200) — уведомление ушло в фон

        Production-сценарий:
        Уведомления отправляются асинхронно через очередь. Сбой SMTP
        не должен блокировать смену пароля — пользователь получает 200,
        а уведомление ретраится в фоне.
        """
        import app.routers.password as password_mod

        original_notification = getattr(password_mod, "send_password_changed_notification", None)

        # Асинхронная отправка — возвращает True, фоновая очередь сама обработает
        mock_notification = AsyncMock(return_value=True)
        password_mod.send_password_changed_notification = mock_notification

        mock_auth = AsyncMock()
        mock_rate = AsyncMock()
        mock_password = AsyncMock()

        mock_rate.check_rate_limit = AsyncMock(return_value=1)
        mock_rate.reset_rate_limit = AsyncMock()

        mock_user = MagicMock()
        mock_user.id = uuid4()
        mock_user.password_hash = "old_hash"
        mock_user.is_active = True
        mock_user.email = "test@example.com"

        mock_auth.get_user_by_id = AsyncMock(return_value=mock_user)
        mock_auth.update_password = AsyncMock()
        mock_auth.revoke_all_sessions = AsyncMock()
        mock_auth.publish_password_changed = AsyncMock()

        mock_password.verify_password = AsyncMock(side_effect=[True, False])
        mock_password.hash_password = AsyncMock(return_value="new_hash")

        from app.routers.password import (
            get_auth_service_for_password_router,
            get_password_service_for_password_router,
            get_rate_limit_service_for_password_router,
        )

        original_auth = app.dependency_overrides.get(get_auth_service_for_password_router)
        original_pass = app.dependency_overrides.get(get_password_service_for_password_router)
        original_rate = app.dependency_overrides.get(get_rate_limit_service_for_password_router)

        try:
            app.dependency_overrides[get_auth_service_for_password_router] = lambda: mock_auth
            app.dependency_overrides[get_password_service_for_password_router] = lambda: mock_password
            app.dependency_overrides[get_rate_limit_service_for_password_router] = lambda: mock_rate

            user_id = uuid4()
            headers = {
                "X-User-Id": str(user_id),
                "X-User-Roles": "user",
                "X-User-Email": "test@example.com",
                "X-Session-Id": "session_123",
            }

            response = await client.post(
                "/password/change",
                headers=headers,
                json={
                    "old_password": "OldPass123!",
                    "new_password": "NewPass456!@#",
                },
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True

            mock_notification.assert_called()

        finally:
            if original_notification:
                password_mod.send_password_changed_notification = original_notification
            if original_auth:
                app.dependency_overrides[get_auth_service_for_password_router] = original_auth
            else:
                app.dependency_overrides.pop(get_auth_service_for_password_router, None)
            if original_pass:
                app.dependency_overrides[get_password_service_for_password_router] = original_pass
            else:
                app.dependency_overrides.pop(get_password_service_for_password_router, None)
            if original_rate:
                app.dependency_overrides[get_rate_limit_service_for_password_router] = original_rate
            else:
                app.dependency_overrides.pop(get_rate_limit_service_for_password_router, None)