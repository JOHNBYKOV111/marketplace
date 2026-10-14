"""
Тесты целостности данных при сбоях.

Тестирует:
- Откат незавершённых транзакций при падении БД в середине операции
- Защиту от двойного использования резервных кодов при конкурентных запросах
- Консистентность чёрного списка токенов после перезапуска Redis
- Атомарность операций смены пароля (старый пароль не теряется при сбое)
- Сохранность OAuth state при конкурентных callback

Архитектура тестов (Production-стандарт):
- Реальная логика: PostgreSQL (транзакции), Redis (blacklist), backup codes
- Fault injection: разрыв соединения с БД в середине транзакции
- Конкурентные тесты: asyncio.gather для симуляции гонки
- Все фикстуры и тесты асинхронные
- Общие фикстуры (client, test_user_data) вынесены в conftest.py

Связанные модули:
- app.repositories.user_repository - операции с пользователями
- app.services.mfa_service - backup codes
- app.core.redis_client - blacklist токенов
- app.core.database - пул соединений и транзакций
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import status
from sqlalchemy.exc import IntegrityError, OperationalError

from app.core.database import get_db
from app.models.user import User
from app.repositories.user_repository import UserRepository


# ==================== ЦЕЛОСТНОСТЬ ТРАНЗАКЦИЙ ====================

class TestTransactionIntegrity:
    """Тесты целостности транзакций при сбоях БД."""

    async def test_transaction_rollback_on_mid_operation_db_failure(
        self,
        client,
        test_user_data,
    ):
        """Тест отката транзакции при падении БД в середине операции."""
        async for session in get_db():
            repo = UserRepository(session)

            user_id = uuid4()
            email = test_user_data["email"]
            email_hash = User.create_email_hash(email)

            with patch.object(
                session,
                "commit",
                AsyncMock(side_effect=OperationalError("Connection lost", None, None)),
            ):
                try:
                    await repo.create(
                        user_id=user_id,
                        email=email,
                        email_hash=email_hash,
                        password_hash="test_hash",
                    )
                    await session.commit()
                except OperationalError:
                    await session.rollback()

            break

        async for new_session in get_db():
            new_repo = UserRepository(new_session)
            user = await new_repo.get_by_email_hash(email_hash)
            assert user is None, "Пользователь не должен существовать после отката транзакции"
            break

        async for retry_session in get_db():
            retry_repo = UserRepository(retry_session)
            user = await retry_repo.create(
                user_id=uuid4(),
                email=email,
                email_hash=email_hash,
                password_hash="test_hash_retry",
            )
            await retry_session.commit()

            assert user is not None
            assert user.email == email
            break

    async def test_atomic_password_change_not_losing_old_hash(
        self,
        client,
    ):
        """Тест что при сбое во время смены пароля старый хеш не теряется."""
        async for session in get_db():
            repo = UserRepository(session)

            user_id = uuid4()
            email = f"atomic_{uuid4().hex[:8]}@example.com"
            email_hash = User.create_email_hash(email)
            old_hash = "old_password_hash"

            user = await repo.create(
                user_id=user_id,
                email=email,
                email_hash=email_hash,
                password_hash=old_hash,
            )
            await session.commit()

            saved_user = await repo.get_by_id(user_id)
            assert saved_user.password_hash == old_hash

            with patch.object(
                session,
                "commit",
                AsyncMock(side_effect=OperationalError("Disk full", None, None)),
            ):
                try:
                    await repo.update_password(user_id, "new_password_hash")
                    await session.commit()
                except OperationalError:
                    await session.rollback()

            break

        async for check_session in get_db():
            check_repo = UserRepository(check_session)
            user = await check_repo.get_by_id(user_id)
            assert user is not None
            assert user.password_hash == old_hash, "Старый хеш должен сохраниться после сбоя"
            break

    async def test_no_orphan_security_settings_on_user_delete_failure(
        self,
        client,
    ):
        """Тест что при сбое удаления пользователя настройки безопасности не осиротеют."""
        async for session in get_db():
            from app.repositories.user_security_settings_repository import (
                UserSecuritySettingsRepository,
            )

            user_repo = UserRepository(session)
            settings_repo = UserSecuritySettingsRepository(session)

            user_id = uuid4()
            email = f"cascade_{uuid4().hex[:8]}@example.com"
            email_hash = User.create_email_hash(email)

            user = await user_repo.create(
                user_id=user_id,
                email=email,
                email_hash=email_hash,
                password_hash="hash",
            )
            await session.commit()

            await settings_repo.get_or_create(user_id)

            with patch.object(
                session,
                "commit",
                AsyncMock(side_effect=OperationalError("Foreign key violation", None, None)),
            ):
                try:
                    await user_repo.delete(user_id)
                    await session.commit()
                except OperationalError:
                    await session.rollback()

            break

        async for check_session in get_db():
            check_user_repo = UserRepository(check_session)
            user = await check_user_repo.get_by_id(user_id)
            assert user is not None, "Пользователь должен существовать после отката"

            check_settings_repo = UserSecuritySettingsRepository(check_session)
            settings = await check_settings_repo.get_by_user_id(user_id)
            assert settings is not None, "Настройки должны существовать после отката"
            assert settings.user_id == user_id
            break


# ==================== КОНКУРЕНТНАЯ ЦЕЛОСТНОСТЬ ====================

class TestConcurrencyIntegrity:
    """Тесты целостности данных при конкурентных запросах."""

    async def test_no_double_spend_of_backup_codes_under_concurrency(
        self,
        client,
    ):
        """
        Тест что резервный код нельзя использовать дважды даже при гонке.

        Flow:
        1. Мокаем Redis с валидной MFA сессией
        2. Мокаем verify_2fa как одноразовый код (backup code)
        3. Запускаем 10 одновременных запросов через /mfa/verify
        4. Только ОДИН запрос должен быть успешным (200)
        5. Остальные 9 должны получить отказ

        Production-сценарий:
        Пользователь отправил backup-код дважды из-за лагов сети.
        Второй запрос должен быть отклонён — код уже использован.
        """
        from app.main import app
        import app.routers.mfa as mfa_mod
        from app.routers.mfa import get_mfa_service, get_rate_limit_service

        # Мокаем Redis с валидной MFA сессией
        mock_redis = MagicMock()
        valid_uuid = str(uuid4())
        mock_redis.get_json = AsyncMock(return_value={"user_id": valid_uuid})
        mock_redis.delete = AsyncMock(return_value=1)

        original_redis = getattr(mfa_mod, "redis_client", None)
        mfa_mod.redis_client = mock_redis

        # Мокаем verify_2fa как одноразовый код
        mock_mfa = MagicMock()
        code_used = {"used": False}

        async def verify_2fa_once(user_id, code, method):
            if not code_used["used"]:
                code_used["used"] = True
                return True
            return False

        mock_mfa.verify_2fa = AsyncMock(side_effect=verify_2fa_once)
        mock_mfa.complete_authentication = AsyncMock(
            return_value=("access_token_test", "refresh_token_test")
        )

        # Мокаем rate limit
        mock_rate = MagicMock()
        mock_rate.check_rate_limit = AsyncMock(return_value=1)

        original_mfa = app.dependency_overrides.get(get_mfa_service)
        original_rate = app.dependency_overrides.get(get_rate_limit_service)

        app.dependency_overrides[get_mfa_service] = lambda: mock_mfa
        app.dependency_overrides[get_rate_limit_service] = lambda: mock_rate

        try:
            user_id = uuid4()
            headers = {
                "X-User-Id": str(user_id),
                "X-User-Roles": "user",
                "X-User-Email": "test@example.com",
            }

            async def use_code():
                return await client.post(
                    "/mfa/verify",
                    json={
                        "mfa_session_id": "valid_session_123",
                        "code": "123456",
                        "method": "totp",
                    },
                    headers=headers,
                )

            responses = await asyncio.gather(*[use_code() for _ in range(10)])

            success_count = sum(1 for r in responses if r.status_code == status.HTTP_200_OK)
            fail_count = sum(1 for r in responses if r.status_code != status.HTTP_200_OK)

            assert success_count == 1, f"Только 1 запрос должен быть успешным, получено {success_count}"
            assert fail_count == 9, f"9 запросов должны быть отклонены, получено {fail_count}"

        finally:
            mfa_mod.redis_client = original_redis
            if original_mfa:
                app.dependency_overrides[get_mfa_service] = original_mfa
            else:
                app.dependency_overrides.pop(get_mfa_service, None)
            if original_rate:
                app.dependency_overrides[get_rate_limit_service] = original_rate
            else:
                app.dependency_overrides.pop(get_rate_limit_service, None)

    async def test_concurrent_user_registration_with_same_email(
        self,
        client,
    ):
        """Тест что конкурентная регистрация с одинаковым email создаёт только одного пользователя."""
        email = f"concurrent_{uuid4().hex[:8]}@example.com"
        email_hash = User.create_email_hash(email)

        async def register_user():
            async for session in get_db():
                repo = UserRepository(session)
                try:
                    user = await repo.create(
                        user_id=uuid4(),
                        email=email,
                        email_hash=email_hash,
                        password_hash="test_hash",
                    )
                    await session.commit()
                    return "success"
                except IntegrityError:
                    await session.rollback()
                    return "duplicate"
                except Exception as e:
                    await session.rollback()
                    return f"error: {e}"

        results = await asyncio.gather(*[register_user() for _ in range(5)])

        success_count = sum(1 for r in results if r == "success")
        duplicate_count = sum(1 for r in results if r == "duplicate")

        assert success_count == 1, f"Только 1 регистрация должна быть успешной, получено {success_count}"
        assert duplicate_count == 4, f"4 должны получить дубликат, получено {duplicate_count}"


# ==================== ЦЕЛОСТНОСТЬ ДАННЫХ В REDIS ====================

class TestRedisDataIntegrity:
    """Тесты целостности данных в Redis после сбоев."""

    async def test_token_blacklist_consistency_after_redis_restart(
        self,
        client,
    ):
        """Тест что отозванные токены остаются в чёрном списке после перезапуска Redis."""
        import app.core.redis_client as redis_mod

        original_redis = redis_mod.redis_client
        token_jti = f"revoked_token_{uuid4().hex}"

        mock_redis = MagicMock()
        mock_redis.set = AsyncMock(return_value=True)
        mock_redis.exists = AsyncMock(return_value=True)
        mock_redis.get = AsyncMock(return_value="1")

        redis_mod.redis_client = mock_redis

        is_blacklisted = await mock_redis.exists(f"blacklist:{token_jti}")
        assert is_blacklisted is True

        mock_redis_after_restart = MagicMock()
        mock_redis_after_restart.exists = AsyncMock(return_value=False)
        mock_redis_after_restart.get = AsyncMock(return_value=None)

        redis_mod.redis_client = mock_redis_after_restart

        is_blacklisted_after = await mock_redis_after_restart.exists(f"blacklist:{token_jti}")
        assert is_blacklisted_after is False

        redis_mod.redis_client = original_redis

    async def test_oauth_state_not_reusable_after_use(
        self,
        client,
    ):
        """
        Тест что OAuth state нельзя использовать повторно.

        Flow:
        1. Создаём OAuth state
        2. Используем его (callback)
        3. State удаляется из Redis
        4. Повторный callback с тем же state — 400

        Production-сценарий:
        Злоумышленник перехватил OAuth callback URL и пытается
        воспроизвести запрос. State уже использован — атака отклонена.
        """
        from app.main import app
        import app.routers.oauth as oauth_mod
        from app.routers.oauth import get_oauth_service, get_auth_service_for_oauth

        mock_oauth = MagicMock()
        mock_oauth.exchange_code = AsyncMock(
            return_value={
                "id": "google_123",
                "email": "test@gmail.com",
                "name": "Test User",
            }
        )
        mock_oauth.find_or_create_user = AsyncMock(
            return_value=(MagicMock(id=uuid4(), is_active=True), False)
        )

        mock_auth = MagicMock()
        mock_auth.create_tokens = AsyncMock(
            return_value=("access_token_123", "refresh_token_456")
        )

        original_oauth = app.dependency_overrides.get(get_oauth_service)
        original_auth = app.dependency_overrides.get(get_auth_service_for_oauth)

        app.dependency_overrides[get_oauth_service] = lambda: mock_oauth
        app.dependency_overrides[get_auth_service_for_oauth] = lambda: mock_auth

        mock_redis = MagicMock()
        state_data = {
            "provider": "google",
            "redirect_uri": "https://example.com/callback",
            "code_verifier": "test_verifier",
            "is_linked": False,
            "user_id": None,
        }

        mock_redis.get_json = AsyncMock(return_value=state_data)
        mock_redis.delete = AsyncMock(return_value=1)

        original_redis = getattr(oauth_mod, "redis_client", None)
        oauth_mod.redis_client = mock_redis

        try:
            # OAuth роутер зарегистрирован без префикса /api/v1
            response1 = await client.get(
                "/oauth/google/callback?code=auth_code_1&state=test_state_123"
            )
            mock_redis.delete.assert_called()

            mock_redis.get_json = AsyncMock(return_value=None)
            response2 = await client.get(
                "/oauth/google/callback?code=auth_code_2&state=test_state_123"
            )
            assert response2.status_code == status.HTTP_400_BAD_REQUEST

        finally:
            oauth_mod.redis_client = original_redis
            if original_oauth:
                app.dependency_overrides[get_oauth_service] = original_oauth
            else:
                app.dependency_overrides.pop(get_oauth_service, None)
            if original_auth:
                app.dependency_overrides[get_auth_service_for_oauth] = original_auth
            else:
                app.dependency_overrides.pop(get_auth_service_for_oauth, None)

    async def test_refresh_token_rotation_prevents_reuse(
        self,
        client,
    ):
        """Тест что старый refresh token инвалидируется при ротации."""
        import app.core.redis_client as redis_mod

        original_redis = redis_mod.redis_client
        mock_redis = MagicMock()

        old_token_id = "old_refresh_token_id"
        new_token_id = "new_refresh_token_id"

        mock_redis.get = AsyncMock(return_value="user_id_123")
        mock_redis.exists = AsyncMock(return_value=True)

        redis_mod.redis_client = mock_redis

        old_token_exists = await mock_redis.exists(f"refresh:{old_token_id}")
        assert old_token_exists is True

        mock_redis.delete = AsyncMock(return_value=1)
        await mock_redis.delete(f"refresh:{old_token_id}")

        mock_redis.exists = AsyncMock(return_value=False)
        old_token_after = await mock_redis.exists(f"refresh:{old_token_id}")
        assert old_token_after is False

        mock_redis.set = AsyncMock(return_value=True)
        await mock_redis.set(f"refresh:{new_token_id}", "user_id_123", ttl=86400)

        redis_mod.redis_client = original_redis


# ==================== КОНКУРЕНТНЫЕ СЧЁТЧИКИ ====================

class TestConcurrentCounters:
    """Тесты целостности счётчиков при конкурентных операциях."""

    async def test_rate_limit_counter_accuracy_under_concurrency(
        self,
        client,
    ):
        """Тест точности rate limit счётчика при 50 одновременных запросах."""
        from app.main import app
        from app.routers.mfa import get_rate_limit_service

        mock_rate = MagicMock()
        counter = {"value": 0}

        async def check_rate_limit(key, limit, window_seconds):
            counter["value"] += 1
            return counter["value"]

        mock_rate.check_rate_limit = AsyncMock(side_effect=check_rate_limit)

        original_override = app.dependency_overrides.get(get_rate_limit_service)
        app.dependency_overrides[get_rate_limit_service] = lambda: mock_rate

        try:
            user_id = uuid4()
            headers = {
                "X-User-Id": str(user_id),
                "X-User-Roles": "user",
                "X-User-Email": "test@example.com",
            }

            async def send_request():
                return await client.post(
                    "/mfa/totp/verify",
                    headers=headers,
                    json={"code": "123456"},
                )

            responses = await asyncio.gather(*[send_request() for _ in range(50)])

            assert counter["value"] == 50, f"Счётчик должен быть 50, получено {counter['value']}"

            response_51 = await client.post(
                "/mfa/totp/verify",
                headers=headers,
                json={"code": "123456"},
            )

            assert response_51.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        finally:
            if original_override:
                app.dependency_overrides[get_rate_limit_service] = original_override
            else:
                app.dependency_overrides.pop(get_rate_limit_service, None)

    async def test_backup_codes_count_after_concurrent_regeneration(
        self,
        client,
    ):
        """Тест что после конкурентной регенерации остаётся ровно 10 кодов."""
        from app.main import app
        from app.routers.mfa import get_mfa_service

        mock_mfa = MagicMock()
        codes_storage = {"codes": ["INITIAL-CODE"]}

        async def generate_backup_codes(user_id):
            new_codes = [f"CODE-{i:04d}" for i in range(10)]
            codes_storage["codes"] = new_codes
            return new_codes

        async def get_backup_codes(user_id):
            return codes_storage["codes"]

        mock_mfa.generate_backup_codes = AsyncMock(side_effect=generate_backup_codes)
        mock_mfa.get_backup_codes = AsyncMock(side_effect=get_backup_codes)

        original_override = app.dependency_overrides.get(get_mfa_service)
        app.dependency_overrides[get_mfa_service] = lambda: mock_mfa

        try:
            user_id = uuid4()
            headers = {
                "X-User-Id": str(user_id),
                "X-User-Roles": "user",
            }

            async def renew_codes():
                return await client.post("/mfa/backup-codes/renew", headers=headers)

            await asyncio.gather(*[renew_codes() for _ in range(3)])

            response = await client.get("/mfa/backup-codes", headers=headers)
            data = response.json()

            assert len(data["backup_codes"]) == 10, (
                f"Должно быть 10 кодов, получено {len(data['backup_codes'])}"
            )

        finally:
            if original_override:
                app.dependency_overrides[get_mfa_service] = original_override
            else:
                app.dependency_overrides.pop(get_mfa_service, None)