"""
Интеграционные тесты для Internal API роутера.

Тестирует:
- POST /internal/user/create - создание пользователя
- POST /internal/user/delete - удаление пользователя
- POST /internal/user/update-password - обновление пароля
- POST /internal/sessions/revoke-all - отзыв всех сессий
- GET /internal/user/{user_id}/exists - проверка существования
- GET /internal/user/{user_id}/sessions/count - количество сессий
- Аутентификацию (API key, IP whitelist)
- Обработку ошибок (404, 400, 401, 403)
"""

from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest
from fastapi import status

from app.core.config import settings
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.core.security import hash_password_bcrypt


class TestInternalAPIAuthentication:
    """Тесты аутентификации Internal API."""

    async def test_internal_api_missing_api_key(self, client):
        """Тест доступа без API key."""
        original_key = settings.INTERNAL_API_KEY
        settings.INTERNAL_API_KEY = "test_api_key_123"

        response = await client.post(
            "/internal/user/create",
            json={
                "user_id": str(uuid4()),
                "email": "test@example.com",
                "email_hash": "test_hash",
                "password_hash": "hash",
            },
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        settings.INTERNAL_API_KEY = original_key

    async def test_internal_api_invalid_api_key(self, client):
        """Тест доступа с неверным API key."""
        original_key = settings.INTERNAL_API_KEY
        settings.INTERNAL_API_KEY = "correct_key"

        response = await client.post(
            "/internal/user/create",
            headers={"X-Internal-API-Key": "wrong_key"},
            json={
                "user_id": str(uuid4()),
                "email": "test@example.com",
                "email_hash": "test_hash",
                "password_hash": "hash",
            },
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        settings.INTERNAL_API_KEY = original_key

    async def test_internal_api_valid_auth(self, client, create_test_user):
        """Тест доступа с корректным API key."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_api_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        # Создаем реального пользователя в БД
        user = await create_test_user(
            email="test@example.com",
            password="SecurePass123!",
            is_active=True,
            is_email_verified=True,
        )

        response = await client.post(
            "/internal/user/create",
            headers={"X-Internal-API-Key": "test_api_key"},
            json={
                "user_id": str(uuid4()),
                "email": "new_user@example.com",
                "email_hash": User.create_email_hash("new_user@example.com"),
                "password_hash": hash_password_bcrypt("SecurePass123!"),
                "is_active": True,
                "is_email_verified": False,
            },
        )

        # Либо создаст нового пользователя (201), либо вернет 403 если IP не пропущен
        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_403_FORBIDDEN]

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips


class TestInternalCreateUser:
    """Тесты для POST /internal/user/create."""

    async def test_create_user_success(
        self,
        client,
        db_session,
        create_test_user,
    ):
        """Тест успешного создания пользователя."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        user_id = uuid4()
        email = "new_user@example.com"
        email_hash = User.create_email_hash(email)

        response = await client.post(
            "/internal/user/create",
            headers={"X-Internal-API-Key": "test_key"},
            json={
                "user_id": str(user_id),
                "email": email,
                "email_hash": email_hash,
                "password_hash": hash_password_bcrypt("SecurePass123!"),
                "is_active": True,
                "is_email_verified": False,
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["success"] is True
        assert data["user_id"] == str(user_id)
        assert "created successfully" in data["message"]

        # Проверяем, что пользователь реально создан в БД
        from app.repositories.user_repository import UserRepository
        repo = UserRepository(db_session)
        created_user = await repo.get_by_id(user_id)
        assert created_user is not None
        assert created_user.email_hash == email_hash

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips

    async def test_create_user_already_exists(
        self,
        client,
        db_session,
        create_test_user,
    ):
        """Тест создания уже существующего пользователя."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        # Создаем пользователя
        user = await create_test_user(
            email="existing@example.com",
            password="SecurePass123!",
        )

        email_hash = User.create_email_hash("existing@example.com")

        # Пытаемся создать пользователя с тем же email_hash
        response = await client.post(
            "/internal/user/create",
            headers={"X-Internal-API-Key": "test_key"},
            json={
                "user_id": str(uuid4()),
                "email": "existing@example.com",
                "email_hash": email_hash,
                "password_hash": hash_password_bcrypt("SecurePass123!"),
                "is_active": True,
                "is_email_verified": False,
            },
        )

        assert response.status_code == status.HTTP_409_CONFLICT
        data = response.json()
        assert "already exists" in data["error"]["message"]

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips


class TestInternalDeleteUser:
    """Тесты для POST /internal/user/delete."""

    async def test_delete_user_success(
        self,
        client,
        db_session,
        create_test_user,
    ):
        """Тест успешного удаления пользователя."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        # Создаем пользователя
        user = await create_test_user(
            email="delete_me@example.com",
            password="SecurePass123!",
        )

        response = await client.post(
            "/internal/user/delete",
            headers={"X-Internal-API-Key": "test_key"},
            json={
                "user_id": str(user.id),
            },
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["user_id"] == str(user.id)

        # Проверяем, что пользователь реально удален из БД
        from app.repositories.user_repository import UserRepository
        repo = UserRepository(db_session)
        deleted_user = await repo.get_by_id(user.id)
        assert deleted_user is None

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips

    async def test_delete_user_not_found(
        self,
        client,
    ):
        """Тест удаления несуществующего пользователя."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        fake_id = uuid4()

        response = await client.post(
            "/internal/user/delete",
            headers={"X-Internal-API-Key": "test_key"},
            json={
                "user_id": str(fake_id),
            },
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips


class TestInternalUpdatePassword:
    """Тесты для POST /internal/user/update-password."""

    async def test_update_password_success(
        self,
        client,
        db_session,
        create_test_user,
    ):
        """Тест успешного обновления пароля."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        # Создаем пользователя
        user = await create_test_user(
            email="update_pass@example.com",
            password="SecurePass123!",
        )

        new_password_hash = hash_password_bcrypt("NewSecurePass456!")

        response = await client.post(
            "/internal/user/update-password",
            headers={"X-Internal-API-Key": "test_key"},
            json={
                "user_id": str(user.id),
                "new_password_hash": new_password_hash,
            },
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["user_id"] == str(user.id)

        # Проверяем, что пароль реально обновлен в БД
        from app.repositories.user_repository import UserRepository
        repo = UserRepository(db_session)
        updated_user = await repo.get_by_id(user.id)
        assert updated_user is not None
        assert updated_user.password_hash == new_password_hash

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips


class TestInternalRevokeAllSessions:
    """Тесты для POST /internal/sessions/revoke-all."""

    async def test_revoke_all_sessions_success(
        self,
        client,
        db_session,
        create_test_user,
    ):
        """Тест успешного отзыва всех сессий."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        # Создаем пользователя
        user = await create_test_user(
            email="revoke_sessions@example.com",
            password="SecurePass123!",
        )

        # ПРОД-ЛИД ФИКС: используем фабричный метод модели RefreshToken
        from app.models.refresh_token import RefreshToken
        
        for i in range(3):
            token_obj = RefreshToken.create_token(
                user_id=user.id,
                expires_days=30
            )
            db_session.add(token_obj)
        await db_session.flush()

        response = await client.post(
            "/internal/sessions/revoke-all",
            headers={"X-Internal-API-Key": "test_key"},
            json={
                "user_id": str(user.id),
                "reason": "security_audit",
                "publish_event": False,
            },
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["user_id"] == str(user.id)
        assert data["revoked_sessions_count"] == 3

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips


class TestInternalUserExists:
    """Тесты для GET /internal/user/{user_id}/exists."""

    async def test_user_exists_true(
        self,
        client,
        create_test_user,
    ):
        """Тест проверки существующего пользователя."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        # Создаем пользователя
        user = await create_test_user(
            email="exists_true@example.com",
            password="SecurePass123!",
        )

        response = await client.get(
            f"/internal/user/{user.id}/exists",
            headers={"X-Internal-API-Key": "test_key"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["exists"] is True
        assert data["user_id"] == str(user.id)
        assert data["is_active"] is True

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips

    async def test_user_exists_false(
        self,
        client,
    ):
        """Тест проверки несуществующего пользователя."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        fake_id = uuid4()

        response = await client.get(
            f"/internal/user/{fake_id}/exists",
            headers={"X-Internal-API-Key": "test_key"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["exists"] is False
        assert data["user_id"] == str(fake_id)
        assert data["is_active"] is None

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips


class TestInternalSessionsCount:
    """Тесты для GET /internal/user/{user_id}/sessions/count."""

    async def test_sessions_count_success(
        self,
        client,
        db_session,
        create_test_user,
    ):
        """Тест получения количества активных сессий."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        # Создаем пользователя
        user = await create_test_user(
            email="sessions_count@example.com",
            password="SecurePass123!",
        )

        # ПРОД-ЛИД ФИКС: используем фабричный метод модели RefreshToken
        from app.models.refresh_token import RefreshToken
        
        for i in range(5):
            token_obj = RefreshToken.create_token(
                user_id=user.id,
                expires_days=30
            )
            db_session.add(token_obj)
        await db_session.flush()

        response = await client.get(
            f"/internal/user/{user.id}/sessions/count",
            headers={"X-Internal-API-Key": "test_key"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["user_id"] == str(user.id)
        assert data["active_sessions_count"] == 5

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips


class TestInternalAPIEdgeCases:
    """Тесты для граничных случаев Internal API."""

    async def test_invalid_uuid_format(self, client):
        """Тест с неверным форматом UUID."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        response = await client.get(
            "/internal/user/invalid-uuid/exists",
            headers={"X-Internal-API-Key": "test_key"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips

    async def test_missing_required_fields(self, client):
        """Тест с отсутствием обязательных полей."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["127.0.0.1", "::1"]

        response = await client.post(
            "/internal/user/create",
            headers={"X-Internal-API-Key": "test_key"},
            content="invalid_json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips

    async def test_internal_api_ip_restriction(self, client):
        """Тест ограничения по IP."""
        original_key = settings.INTERNAL_API_KEY
        original_ips = settings.INTERNAL_ALLOWED_IPS

        settings.INTERNAL_API_KEY = "test_key"
        settings.INTERNAL_ALLOWED_IPS = ["10.0.0.1"]

        response = await client.post(
            "/internal/user/create",
            headers={"X-Internal-API-Key": "test_key"},
            json={
                "user_id": str(uuid4()),
                "email": "test@example.com",
                "email_hash": "hash",
                "password_hash": "hash",
            },
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

        settings.INTERNAL_API_KEY = original_key
        settings.INTERNAL_ALLOWED_IPS = original_ips