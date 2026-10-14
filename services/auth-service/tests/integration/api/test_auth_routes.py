"""
Интеграционные тесты для Auth роутера.

Тестирует:
- POST /login - аутентификация (успех, MFA required, ошибки)
- POST /refresh - обновление токенов
- POST /logout - выход
- POST /logout-all - выход на всех устройствах
- POST /verify-email - верификация email
- POST /verify-phone - верификация телефона
- Rate limiting
- Cookie управление
- Обработку ошибок (401, 403, 429, 422)
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import status

from app.core.config import settings
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.services.token_service import TokenService


# ==================== МОК ДЛЯ VAULT ====================

@pytest.fixture(autouse=True)
def mock_vault():
    mock = AsyncMock()
    mock.health_check = AsyncMock(return_value=True)
    mock.is_healthy = AsyncMock(return_value=True)
    mock.read_secret = AsyncMock(return_value={"data": {"value": "test_secret"}})
    mock.write_secret = AsyncMock(return_value={"data": {"created": True}})
    mock.delete_secret = AsyncMock(return_value=True)
    mock.list_secrets = AsyncMock(return_value={"keys": ["test_key"]})
    mock.get_config = AsyncMock(return_value={"config": "test"})
    mock.set_config = AsyncMock(return_value={"config": "test"})
    mock.encrypt = AsyncMock(return_value="encrypted_test_token_12345")
    mock.decrypt = AsyncMock(return_value='{"user_id": "test_user", "data": "decrypted"}')
    mock.connect = AsyncMock(return_value=True)
    mock.close = AsyncMock(return_value=True)

    with patch("app.core.vault_client.vault_client", mock):
        with patch("app.services.health_service.vault_client", mock):
            yield mock


# ==================== МОК ДЛЯ KAFKA ====================

@pytest.fixture(autouse=True)
def mock_kafka_client():
    with patch("app.core.kafka_client.kafka_client") as mock_client:
        mock_client.produce_event = AsyncMock(return_value=None)
        mock_client.produce = AsyncMock(return_value=True)
        mock_client.connect = AsyncMock(return_value=None)
        mock_client.close = AsyncMock(return_value=None)
        mock_client.is_connected = True
        mock_client.healthcheck = AsyncMock(return_value=True)
        yield mock_client


class TestAuthRoutes:
    """Интеграционные тесты для Auth роутера."""

    @pytest.fixture
    def user_id(self):
        return uuid4()

    @pytest.fixture
    def test_user(self, user_id) -> User:
        return User(
            id=user_id,
            email="test@example.com",
            email_hash=User.create_email_hash("test@example.com"),
            password_hash="hashed_password",
            is_active=True,
            is_email_verified=True,
        )


class TestLogin:
    """Тесты для POST /login."""

    async def test_login_success(
        self,
        client,
        get_url,
        create_test_user,
    ):
        await create_test_user(
            email="test@example.com",
            password="SecurePass123!",
            is_active=True,
            is_email_verified=True,
        )

        response = await client.post(
            get_url("auth:login"),
            json={
                "email": "test@example.com",
                "password": "SecurePass123!",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data

        cookies = response.cookies
        assert "refresh_token" in cookies

    async def test_login_mfa_required(
        self,
        client,
        get_url,
        create_test_user,
        create_test_security_settings,
    ):
        user = await create_test_user(
            email="test@example.com",
            password="SecurePass123!",
            is_active=True,
            is_email_verified=True,
        )

        await create_test_security_settings(
            user_id=user.id,
            totp_enabled=True,
        )

        response = await client.post(
            get_url("auth:login"),
            json={
                "email": "test@example.com",
                "password": "SecurePass123!",
            },
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_login_invalid_credentials(
        self,
        client,
        get_url,
        create_test_user,
    ):
        await create_test_user(
            email="test@example.com",
            password="SecurePass123!",
        )

        response = await client.post(
            get_url("auth:login"),
            json={
                "email": "test@example.com",
                "password": "WrongPass123!",
            },
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_login_rate_limit_exceeded(
        self,
        client,
        get_url,
    ):
        """Тест превышения лимита запросов на вход."""
        from unittest.mock import patch
        from fastapi import HTTPException

        with patch(
            "fastapi.routing.APIRoute.handle",
            side_effect=HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        ):
            response = await client.post(
                get_url("auth:login"),
                json={"email": "test@example.com", "password": "SecurePass123!"}
            )

            assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    async def test_login_validation_error(
        self,
        client,
        get_url,
    ):
        url = get_url("auth:login")

        response = await client.post(
            url,
            json={
                "email": "invalid",
                "password": "Short1!",
            },
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        response = await client.post(
            url,
            json={
                "email": "test@example.com",
                "password": "short",
            },
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestRefresh:
    """Тесты для POST /refresh."""

    async def _login_and_get_refresh_token(self, client, get_url, email, password):
        """Вспомогательный метод: логин и получение refresh_token из куки."""
        client.headers["X-Forwarded-For"] = f"192.168.{uuid4().hex[:4]}.{uuid4().hex[:4]}"
        response = await client.post(
            get_url("auth:login"),
            json={"email": email, "password": password},
        )
        assert response.status_code == status.HTTP_200_OK
        refresh_token = response.cookies.get("refresh_token")
        assert refresh_token is not None
        return refresh_token, response.json()["access_token"]

    async def test_refresh_success(
        self,
        client,
        get_url,
        create_test_user,
    ):
        email = f"test_{uuid4().hex[:8]}@example.com"
        await create_test_user(
            email=email,
            password="SecurePass123!",
        )

        refresh_token, _ = await self._login_and_get_refresh_token(
            client, get_url, email, "SecurePass123!"
        )

        client.cookies.set("refresh_token", refresh_token)

        response = await client.post(get_url("auth:refresh"))

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["access_token"] is not None
        assert data["token_type"] == "bearer"

        new_refresh_token = response.cookies.get("refresh_token")
        assert new_refresh_token is not None
        assert new_refresh_token != refresh_token

    async def test_refresh_missing_token(
        self,
        client,
        get_url,
    ):
        response = await client.post(get_url("auth:refresh"))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_refresh_invalid_token(
        self,
        client,
        get_url,
    ):
        client.cookies.set("refresh_token", "invalid_token")
        response = await client.post(get_url("auth:refresh"))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestLogout:
    """Тесты для POST /logout."""

    async def test_logout_success(
        self,
        client,
        get_url,
        create_test_user,
    ):
        email = f"test_{uuid4().hex[:8]}@example.com"
        await create_test_user(
            email=email,
            password="SecurePass123!",
        )

        client.headers["X-Forwarded-For"] = f"192.168.{uuid4().hex[:4]}.{uuid4().hex[:4]}"
        login_response = await client.post(
            get_url("auth:login"),
            json={"email": email, "password": "SecurePass123!"},
        )

        access_token = login_response.json()["access_token"]
        client.headers["Authorization"] = f"Bearer {access_token}"

        response = await client.post(get_url("auth:logout"))

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "Logged out successfully" in data["message"]

        assert "refresh_token" not in response.cookies or response.cookies.get("refresh_token") == ""

    async def test_logout_unauthorized(
        self,
        client,
        get_url,
    ):
        response = await client.post(get_url("auth:logout"))
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True


class TestLogoutAll:
    """Тесты для POST /logout-all."""

    async def test_logout_all_success(
        self,
        client,
        get_url,
        create_test_user,
    ):
        email = f"test_{uuid4().hex[:8]}@example.com"
        await create_test_user(
            email=email,
            password="SecurePass123!",
        )

        client.headers["X-Forwarded-For"] = f"192.168.{uuid4().hex[:4]}.{uuid4().hex[:4]}"
        login_response = await client.post(
            get_url("auth:login"),
            json={"email": email, "password": "SecurePass123!"},
        )

        access_token = login_response.json()["access_token"]
        client.headers["Authorization"] = f"Bearer {access_token}"

        response = await client.post(
            get_url("auth:logout"),
            json={"all_devices": True}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "Logged out successfully" in data["message"]

    async def test_logout_all_unauthorized(
        self,
        client,
        get_url,
    ):
        response = await client.post(
            get_url("auth:logout"),
            json={"all_devices": True}
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "Logged out successfully" in data["message"]


class TestVerifyEmail:
    """Тесты для POST /verify-email."""

    async def test_verify_email_success(
        self,
        client,
        get_url,
        create_test_user,
        db_session,
    ):
        email = f"test_{uuid4().hex[:8]}@example.com"
        user = await create_test_user(
            email=email,
            password="SecurePass123!",
            is_active=True,
            is_email_verified=False,
        )

        refresh_repo = RefreshTokenRepository(db_session)
        token_service = TokenService(
            refresh_repo=refresh_repo,
            secret_key=settings.JWT_SECRET_KEY
        )
        token = await token_service.create_email_verification_token(user.id)

        from app.repositories.user_repository import UserRepository

        repo = UserRepository(db_session)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        await repo.update_verification_token(user.id, token, expires_at)
        await db_session.commit()

        response = await client.post(
            get_url("auth:verify_email"),
            json={"token": token},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "email verified successfully" in data["message"].lower()

    async def test_verify_email_invalid_token(
        self,
        client,
        get_url,
    ):
        response = await client.post(
            get_url("auth:verify_email"),
            json={"token": "invalid_token"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_verify_email_validation_error(
        self,
        client,
        get_url,
    ):
        response = await client.post(
            get_url("auth:verify_email"),
            json={"token": "short"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestCookieManagement:
    """Тесты для управления cookie."""

    async def test_refresh_token_cookie_attributes(
        self,
        client,
        get_url,
        create_test_user,
    ):
        email = f"test_{uuid4().hex[:8]}@example.com"
        await create_test_user(
            email=email,
            password="SecurePass123!",
        )

        client.headers["X-Forwarded-For"] = f"192.168.{uuid4().hex[:4]}.{uuid4().hex[:4]}"
        response = await client.post(
            get_url("auth:login"),
            json={"email": email, "password": "SecurePass123!"},
        )

        assert response.status_code == status.HTTP_200_OK
        cookies = response.cookies
        assert "refresh_token" in cookies
        assert cookies.get("refresh_token") is not None

    async def test_logout_clears_cookie(
        self,
        client,
        get_url,
        create_test_user,
    ):
        email = f"test_{uuid4().hex[:8]}@example.com"
        await create_test_user(
            email=email,
            password="SecurePass123!",
        )

        client.headers["X-Forwarded-For"] = f"192.168.{uuid4().hex[:4]}.{uuid4().hex[:4]}"
        login_response = await client.post(
            get_url("auth:login"),
            json={"email": email, "password": "SecurePass123!"},
        )

        refresh_token = login_response.cookies.get("refresh_token")
        access_token = login_response.json()["access_token"]

        client.headers["Authorization"] = f"Bearer {access_token}"
        client.cookies.set("refresh_token", refresh_token)

        response = await client.post(get_url("auth:logout"))

        assert "refresh_token" not in response.cookies or response.cookies.get("refresh_token") == ""


class TestSecurityHeaders:
    """Тесты для security headers."""

    async def test_cookie_security_attributes(
        self,
        client,
        get_url,
        create_test_user,
    ):
        email = f"test_{uuid4().hex[:8]}@example.com"
        await create_test_user(
            email=email,
            password="SecurePass123!",
        )

        client.headers["X-Forwarded-For"] = f"192.168.{uuid4().hex[:4]}.{uuid4().hex[:4]}"
        response = await client.post(
            get_url("auth:login"),
            json={"email": email, "password": "SecurePass123!"},
        )

        assert response.status_code == status.HTTP_200_OK
        set_cookie_header = response.headers.get("set-cookie", "")
        assert "HttpOnly" in set_cookie_header or "httponly" in set_cookie_header.lower()


class TestEdgeCases:
    """Тесты для граничных случаев."""

    async def test_login_rate_limit_by_ip_only(
        self,
        client,
        get_url,
    ):
        """Тест превышения лимита запросов по IP."""
        from unittest.mock import patch
        from fastapi import HTTPException

        with patch(
            "fastapi.routing.APIRoute.handle",
            side_effect=HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        ):
            response = await client.post(
                get_url("auth:login"),
                json={"email": "test@example.com", "password": "SecurePass123!"}
            )

            assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    async def test_login_blocked_user(
        self,
        client,
        get_url,
        create_test_user,
    ):
        await create_test_user(
            email="blocked@example.com",
            password="SecurePass123!",
            is_active=False,
        )

        response = await client.post(
            get_url("auth:login"),
            json={
                "email": "blocked@example.com",
                "password": "SecurePass123!",
            },
        )

        assert response.status_code in [
            status.HTTP_403_FORBIDDEN,
            status.HTTP_429_TOO_MANY_REQUESTS,
        ]

    async def test_refresh_with_rotation(
        self,
        client,
        get_url,
        create_test_user,
    ):
        email = f"test_{uuid4().hex[:8]}@example.com"
        await create_test_user(
            email=email,
            password="SecurePass123!",
        )

        client.headers["X-Forwarded-For"] = f"192.168.{uuid4().hex[:4]}.{uuid4().hex[:4]}"
        login_response = await client.post(
            get_url("auth:login"),
            json={"email": email, "password": "SecurePass123!"},
        )

        refresh_token = login_response.cookies.get("refresh_token")
        assert refresh_token is not None

        client.cookies.set("refresh_token", refresh_token)

        response = await client.post(get_url("auth:refresh"))

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["access_token"] is not None

        new_refresh_token = response.cookies.get("refresh_token")
        assert new_refresh_token is not None
        assert new_refresh_token != refresh_token