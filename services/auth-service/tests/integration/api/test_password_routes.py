"""
Интеграционные тесты для Password роутера с реальной логикой.

Тестирует:
- POST /password/change - смена пароля авторизованным пользователем
- POST /password/reset-request - запрос сброса пароля (email)
- POST /password/reset-confirm - подтверждение сброса пароля с токеном
- Валидацию паролей (сложность, длина, отличие от старого)
- Rate limiting
- Проверку авторизации
- Обработку ошибок (неверный пароль, истекший токен)
- Отзыв сессий при смене пароля

Архитектура тестов:
- Реальная логика: PasswordService (bcrypt), AuthService (БД), RateLimitService (Redis), Pydantic-валидация
- Моки: email-уведомления (внешний SMTP)
- Использует глобальные фикстуры из conftest.py (client, db_session, create_test_user, Redis)
- create_test_user делает commit() — пользователь виден всем сессиям роутеров
- Все фикстуры и тесты асинхронные
"""

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import status

from app.services.password_service import PasswordService


# ==================== ФИКСТУРЫ ====================

@pytest_asyncio.fixture
async def test_user(create_test_user):
    """Тестовый пользователь с известным паролем."""
    password = "OldPass123!"
    user = await create_test_user(
        email=f"pw_test_{uuid4().hex[:8]}@example.com",
        password=password,
        is_active=True,
        is_email_verified=True,
    )
    return {"id": user.id, "email": user.email, "password": password}


@pytest_asyncio.fixture
async def auth_headers(test_user):
    """Заголовки авторизации через Gateway."""
    return {
        "X-User-Id": str(test_user["id"]),
        "X-User-Roles": "user",
        "X-User-Email": test_user["email"],
        "X-Session-Id": "test_session",
    }


@pytest_asyncio.fixture
async def password_client(client):
    """HTTP клиент с реальным приложением, мокаем только email-уведомления."""
    import app.routers.password as password_mod

    original_send_reset = password_mod.send_password_reset_email
    original_send_changed = password_mod.send_password_changed_notification

    password_mod.send_password_reset_email = AsyncMock()
    password_mod.send_password_changed_notification = AsyncMock()

    yield client

    password_mod.send_password_reset_email = original_send_reset
    password_mod.send_password_changed_notification = original_send_changed


# ==================== ТЕСТЫ СМЕНЫ ПАРОЛЯ ====================

class TestChangePassword:

    @pytest.mark.asyncio
    async def test_change_password_success(self, password_client, test_user, auth_headers):
        """Успешная смена пароля с реальной криптографией и БД."""
        new_password = "NewPass456!"

        response = await password_client.post(
            "/password/change",
            headers=auth_headers,
            json={
                "old_password": test_user["password"],
                "new_password": new_password,
            },
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "changed successfully" in data["message"]
        assert data["sessions_revoked"] is True

    @pytest.mark.asyncio
    async def test_change_password_invalid_old_password(self, password_client, test_user, auth_headers):
        """Неверный старый пароль."""
        response = await password_client.post(
            "/password/change",
            headers=auth_headers,
            json={
                "old_password": "WrongPass123!",
                "new_password": "NewPass456!",
            },
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_change_password_same_as_old(self, password_client, test_user, auth_headers):
        """Новый пароль совпадает со старым."""
        response = await password_client.post(
            "/password/change",
            headers=auth_headers,
            json={
                "old_password": test_user["password"],
                "new_password": test_user["password"],
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_change_password_rate_limit_exceeded(self, password_client, test_user, auth_headers):
        """Превышение rate limit (6 запросов с неверным паролем)."""
        for _ in range(5):
            await password_client.post(
                "/password/change",
                headers=auth_headers,
                json={
                    "old_password": "WrongPass123!",
                    "new_password": "NewPass456!",
                },
            )

        response = await password_client.post(
            "/password/change",
            headers=auth_headers,
            json={
                "old_password": "WrongPass123!",
                "new_password": "NewPass456!",
            },
        )

        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    @pytest.mark.asyncio
    async def test_change_password_unauthorized(self, password_client):
        """Без авторизации."""
        response = await password_client.post(
            "/password/change",
            json={
                "old_password": "OldPass123!",
                "new_password": "NewPass456!",
            },
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_change_password_invalid_new_password(self, password_client, auth_headers):
        """Слабый новый пароль — Pydantic-валидация."""
        response = await password_client.post(
            "/password/change",
            headers=auth_headers,
            json={
                "old_password": "OldPass123!",
                "new_password": "weak",
            },
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ==================== ТЕСТЫ ЗАПРОСА СБРОСА ПАРОЛЯ ====================

class TestResetPasswordRequest:

    @pytest.mark.asyncio
    async def test_reset_request_success_existing_user(self, password_client, test_user):
        """Запрос сброса для существующего пользователя."""
        response = await password_client.post(
            "/password/reset-request",
            json={"email": test_user["email"]},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "reset link" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_reset_request_non_existent_user(self, password_client):
        """Запрос сброса для несуществующего пользователя — всегда 200."""
        response = await password_client.post(
            "/password/reset-request",
            json={"email": "nonexistent@example.com"},
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["success"] is True

    @pytest.mark.asyncio
    async def test_reset_request_rate_limit_exceeded(self, password_client):
        """Превышение rate limit (4 запроса)."""
        for _ in range(3):
            await password_client.post(
                "/password/reset-request",
                json={"email": "ratelimit@example.com"},
            )

        response = await password_client.post(
            "/password/reset-request",
            json={"email": "ratelimit@example.com"},
        )

        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    @pytest.mark.asyncio
    async def test_reset_request_invalid_email(self, password_client):
        """Неверный формат email — Pydantic-валидация."""
        response = await password_client.post(
            "/password/reset-request",
            json={"email": "invalid-email"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_reset_request_blocked_user(self, password_client, create_test_user):
        """Запрос сброса для заблокированного пользователя — всегда 200."""
        user = await create_test_user(
            email=f"blocked_{uuid4().hex[:8]}@example.com",
            password="Pass123!",
            is_active=False,
            is_email_verified=True,
        )

        response = await password_client.post(
            "/password/reset-request",
            json={"email": user.email},
        )

        assert response.status_code == status.HTTP_200_OK


# ==================== ТЕСТЫ ПОДТВЕРЖДЕНИЯ СБРОСА ПАРОЛЯ ====================

class TestResetPasswordConfirm:

    @pytest.mark.asyncio
    async def test_reset_confirm_success(self, password_client, test_user):
        """Успешный сброс пароля с реальным токеном в Redis."""
        ps = PasswordService()
        reset_token = ps.generate_reset_token()
        await ps.save_reset_token(test_user["id"], reset_token, ttl_minutes=30)

        new_password = "NewPass456!"

        response = await password_client.post(
            "/password/reset-confirm",
            json={
                "token": reset_token,
                "new_password": new_password,
            },
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "reset successfully" in data["message"]
        assert data["sessions_revoked"] is True

    @pytest.mark.asyncio
    async def test_reset_confirm_invalid_token(self, password_client):
        """Неверный токен сброса."""
        response = await password_client.post(
            "/password/reset-confirm",
            json={
                "token": "a" * 32,
                "new_password": "NewPass456!",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_reset_confirm_same_password(self, password_client, test_user):
        """Новый пароль совпадает с текущим."""
        ps = PasswordService()
        reset_token = ps.generate_reset_token()
        await ps.save_reset_token(test_user["id"], reset_token, ttl_minutes=30)

        response = await password_client.post(
            "/password/reset-confirm",
            json={
                "token": reset_token,
                "new_password": test_user["password"],
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_reset_confirm_rate_limit_exceeded(self, password_client):
        """Превышение rate limit (11 запросов)."""
        for _ in range(10):
            await password_client.post(
                "/password/reset-confirm",
                json={
                    "token": "a" * 32,
                    "new_password": "NewPass456!",
                },
            )

        response = await password_client.post(
            "/password/reset-confirm",
            json={
                "token": "a" * 32,
                "new_password": "NewPass456!",
            },
        )

        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    @pytest.mark.asyncio
    async def test_reset_confirm_invalid_token_format(self, password_client):
        """Короткий токен — Pydantic-валидация."""
        response = await password_client.post(
            "/password/reset-confirm",
            json={
                "token": "short",
                "new_password": "NewPass456!",
            },
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_reset_confirm_invalid_new_password(self, password_client):
        """Слабый пароль — Pydantic-валидация."""
        response = await password_client.post(
            "/password/reset-confirm",
            json={
                "token": "a" * 32,
                "new_password": "weak",
            },
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ==================== ТЕСТЫ ГРАНИЧНЫХ СЛУЧАЕВ ====================

class TestPasswordValidationEdgeCases:

    @pytest.mark.asyncio
    async def test_change_password_missing_fields(self, password_client, auth_headers):
        """Отсутствуют обязательные поля."""
        response = await password_client.post(
            "/password/change",
            headers=auth_headers,
            json={},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_reset_request_missing_email(self, password_client):
        """Отсутствует email."""
        response = await password_client.post("/password/reset-request", json={})

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_reset_confirm_missing_fields(self, password_client):
        """Отсутствуют обязательные поля."""
        response = await password_client.post("/password/reset-confirm", json={})

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY