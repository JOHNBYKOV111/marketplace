"""
Интеграционные тесты зависимостей с реальным FastAPI приложением.

Тестирует:
- Аутентификацию через JWT (реальный логин)
- Ролевую модель (админ/пользователь)
- Доступ к админским эндпоинтам
- Метрики и аудит-логи

Архитектура:
- Реальная логика: JWT, AuthService, БД, зависимости
- Без моков авторизации (admin_client/regular_client)
- Использует глобальные фикстуры из conftest.py (client, db_session, create_test_user)
"""

from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import status


@pytest_asyncio.fixture
async def admin_user(create_test_user):
    """Реальный администратор в тестовой БД."""
    return await create_test_user(
        email=f"admin_{uuid4().hex[:8]}@example.com",
        password="Admin123!",
        is_active=True,
        is_email_verified=True,
        is_superuser=True,
    )


@pytest_asyncio.fixture
async def regular_user(create_test_user):
    """Реальный обычный пользователь в тестовой БД."""
    return await create_test_user(
        email=f"user_{uuid4().hex[:8]}@example.com",
        password="User123!",
        is_active=True,
        is_email_verified=True,
        is_superuser=False,
    )


@pytest_asyncio.fixture
async def admin_token(client, admin_user):
    """JWT токен администратора через реальный логин."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": admin_user.email,
            "password": "Admin123!",
        },
    )
    assert response.status_code == status.HTTP_200_OK
    return response.json()["access_token"]


@pytest_asyncio.fixture
async def regular_token(client, regular_user):
    """JWT токен обычного пользователя через реальный логин."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": regular_user.email,
            "password": "User123!",
        },
    )
    assert response.status_code == status.HTTP_200_OK
    return response.json()["access_token"]


class TestDependenciesIntegration:
    """Интеграционные тесты зависимостей с реальной аутентификацией."""

    @pytest.mark.asyncio
    async def test_dependency_returns_401(self, client):
        """Тест возврата 401 при отсутствии авторизации."""
        response = await client.get("/api/v1/users")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_admin_access_users(self, client, admin_token):
        """Админ имеет доступ к списку пользователей."""
        response = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    @pytest.mark.asyncio
    async def test_regular_user_forbidden(self, client, regular_token):
        """Обычный пользователь получает 403 к админским эндпоинтам."""
        response = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {regular_token}"},
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_admin_metrics_endpoint(self, client, admin_token):
        """Админ имеет доступ к метрикам."""
        response = await client.get(
            "/api/v1/system-metrics",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "active_users" in data
        assert "total_users" in data

    @pytest.mark.asyncio
    async def test_admin_metrics_forbidden(self, client, regular_token):
        """Обычный пользователь не имеет доступа к метрикам."""
        response = await client.get(
            "/api/v1/system-metrics",
            headers={"Authorization": f"Bearer {regular_token}"},
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_audit_logs_endpoint(self, client, admin_token):
        """Админ имеет доступ к аудит-логам."""
        response = await client.get(
            "/api/v1/audit-logs",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "total" in data
        assert "items" in data

    @pytest.mark.asyncio
    async def test_audit_logs_actions_endpoint(self, client, admin_token):
        """Админ имеет доступ к списку действий аудита."""
        response = await client.get(
            "/api/v1/audit-logs/actions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "actions" in data
        assert isinstance(data["actions"], list)