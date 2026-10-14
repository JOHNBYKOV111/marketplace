"""
Интеграционные тесты для административных эндпоинтов.

Тестирует:
- GET /admin/users/{user_id} - получение пользователя
- POST /admin/users/{user_id}/block - блокировка пользователя
- POST /admin/users/{user_id}/unblock - разблокировка пользователя
- GET /admin/users - список пользователей с пагинацией и фильтрацией
- GET /admin/audit-logs - получение логов безопасности
- GET /admin/audit-logs/actions - список действий
- GET /admin/audit-logs/user/{user_id} - логи пользователя
- GET /admin/metrics - метрики системы
- Проверку прав доступа (admin только)
- Обработку ошибок и граничные случаи
"""

from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import status
from sqlalchemy import select, text

from app.models.user import User


# ==================== ГЛОБАЛЬНЫЕ ФИКСТУРЫ (уровень модуля) ====================

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
async def blocked_user(create_test_user):
    """Заблокированный пользователь в тестовой БД."""
    return await create_test_user(
        email=f"blocked_{uuid4().hex[:8]}@example.com",
        password="Blocked123!",
        is_active=False,
        is_email_verified=True,
        is_superuser=False,
    )


# ==================== ТЕСТЫ ====================

class TestGetUser:
    """Тесты для GET /admin/users/{user_id}."""

    @pytest.mark.asyncio
    async def test_get_user_success(self, admin_client, db_session):
        """Тест успешного получения пользователя администратором."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        # Фиксированный ID админа из мока в conftest.py
        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        # ПРОД-ЛИД ФИКС: Удаляем старого админа СТРОГО по уникальному хэшу почты!
        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        # 1. Физически создаем админа в базе данных теста
        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        # 2. Создаем обычного пользователя, которого будем запрашивать через API
        target_id = uuid.uuid4()
        user_email = "api_test_fresh_user@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()

        local_user = User(
            id=target_id,
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        
        target_user_id = str(local_user.id)
        await db_session.flush()
        await db_session.refresh(local_user)

        # 3. Отправляем запрос - авторизация замокана в admin_client
        response = await admin_client.get(f"/api/v1/users/{target_user_id}")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == target_user_id

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, admin_client):
        """Тест получения несуществующего пользователя."""
        fake_id = uuid4()
        response = await admin_client.get(f"/api/v1/users/{fake_id}")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_get_user_unauthorized(self, client, regular_user):
        """Тест доступа без авторизации."""
        response = await client.get(f"/api/v1/users/{regular_user.id}")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_get_user_forbidden_regular_user(self, regular_client):
        """Тест: обычный пользователь получает 403 при попытке вызвать админку."""
        import uuid
        from app.core.dependencies import get_current_user
        from app.models.user import User

        # 1. Формируем объект обычного пользователя (is_superuser=False!)
        mock_user = User(
            id=uuid.uuid4(),
            email="user_forbidden_test@example.com",
            is_active=True,
            is_superuser=False,  # <--- Гарантирует срабатывание 403 Forbidden
            is_email_verified=True
        )

        # 2. Локальная функция-заглушка
        async def override_current_user():
            return mock_user

        # 3. Накатываем переопределение СТРОГО на объект app, который использует этот клиент!
        target_app = regular_client._transport.app
        target_app.dependency_overrides[get_current_user] = override_current_user

        try:
            # 4. Выполняем запрос по выровненному префиксному пути приложения
            target_id = str(uuid.uuid4())
            response = await regular_client.get(f"/api/v1/users/{target_id}")
            
            # 5. Теперь аутентификация (get_current_user) вернет mock_user, 
            # оригинальная функция get_current_admin примет его, увидит False и выкинет 403!
            assert response.status_code == status.HTTP_403_FORBIDDEN
            
        finally:
            # 6. Обязательно чистим за собой переопределения в приложении клиента
            if get_current_user in target_app.dependency_overrides:
                del target_app.dependency_overrides[get_current_user]


class TestBlockUser:
    """Тесты для POST /admin/users/{user_id}/block."""

    @pytest.mark.asyncio
    async def test_block_user_success(self, admin_client, db_session):
        """Тест успешной блокировки пользователя."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user_email = "block_test_user@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        target_user_id = str(local_user.id)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        assert local_user.is_active is True

        block_data = {"reason": "Violation of terms"}
        response = await admin_client.post(
            f"/api/v1/users/{target_user_id}/block",
            json=block_data,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["user_id"] == target_user_id

        await db_session.refresh(local_user)
        assert local_user.is_active is False

    @pytest.mark.asyncio
    async def test_block_user_already_blocked(self, admin_client, db_session):
        """Тест блокировки уже заблокированного пользователя."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user_email = "already_blocked_user@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=False,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        target_user_id = str(local_user.id)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        assert local_user.is_active is False

        block_data = {"reason": "Already blocked"}
        response = await admin_client.post(
            f"/api/v1/users/{target_user_id}/block",
            json=block_data,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "already blocked" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_block_user_not_found(self, admin_client):
        """Тест блокировки несуществующего пользователя."""
        fake_id = uuid4()
        block_data = {"reason": "Test"}
        response = await admin_client.post(
            f"/api/v1/users/{fake_id}/block",
            json=block_data,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_block_user_self(self, admin_client, db_session):
        """Тест попытки блокировки самого себя."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)
        await db_session.flush()
        await db_session.refresh(admin_user)
        
        target_user_id = str(admin_user.id)
        
        block_data = {"reason": "Test"}
        response = await admin_client.post(
            f"/api/v1/users/{target_user_id}/block",
            json=block_data,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = response.json()
        assert error_data["error"]["message"] == "Cannot block yourself"
        assert error_data["error"]["code"] == "BAD_REQUEST"

    @pytest.mark.asyncio
    async def test_block_user_invalid_reason(self, admin_client, db_session):
        """Тест блокировки с некорректной причиной."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user_email = "invalid_reason_user@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        target_user_id = str(local_user.id)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        # Пустая причина
        response = await admin_client.post(
            f"/api/v1/users/{target_user_id}/block",
            json={"reason": ""},
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Слишком длинная причина
        response = await admin_client.post(
            f"/api/v1/users/{target_user_id}/block",
            json={"reason": "a" * 501},
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestUnblockUser:
    """Тесты для POST /admin/users/{user_id}/unblock."""

    @pytest.mark.asyncio
    async def test_unblock_user_success(self, admin_client, db_session):
        """Тест успешной разблокировки пользователя."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user_email = "unblock_test_user@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=False,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        target_user_id = str(local_user.id)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        assert local_user.is_active is False

        unblock_data = {"reason": "Appeal approved"}
        response = await admin_client.post(
            f"/api/v1/users/{target_user_id}/unblock",
            json=unblock_data,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["user_id"] == target_user_id

        await db_session.refresh(local_user)
        assert local_user.is_active is True

    @pytest.mark.asyncio
    async def test_unblock_user_already_active(self, admin_client, db_session):
        """Тест разблокировки уже активного пользователя."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user_email = "already_active_user@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        target_user_id = str(local_user.id)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        assert local_user.is_active is True

        unblock_data = {"reason": "Already active"}
        response = await admin_client.post(
            f"/api/v1/users/{target_user_id}/unblock",
            json=unblock_data,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "already active" in data["message"].lower()


class TestListUsers:
    """Тесты для GET /admin/users."""

    @pytest.mark.asyncio
    async def test_list_users_success(self, admin_client, create_test_user, db_session):
        """Тест успешного получения списка пользователей."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        for i in range(3):
            user = await create_test_user(email=f"list_test_{i}@example.com")
            db_session.add(user)
        await db_session.flush()

        response = await admin_client.get("/api/v1/users")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # ПРОД-ЛИД ФИКС: читаем из поля items
        users_list = data.get("items", [])
        assert len(users_list) >= 3

    @pytest.mark.asyncio
    async def test_list_users_with_pagination(self, admin_client, create_test_user, db_session):
        """Тест списка пользователей с пагинацией."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        for i in range(10):
            user = await create_test_user(email=f"paginate_test_{i}@example.com")
            db_session.add(user)
        await db_session.flush()

        response = await admin_client.get("/api/v1/users?limit=5&offset=0")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # ПРОД-ЛИД ФИКС: читаем из поля items
        items = data.get("items", [])
        assert len(items) == 5
        # Проверяем общее количество
        assert data.get("total", 0) >= 10

    @pytest.mark.asyncio
    async def test_list_users_with_filters(self, admin_client, create_test_user, db_session):
        """Тест списка пользователей с фильтрацией."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user1 = await create_test_user(email="active_verified@example.com", is_active=True, is_email_verified=True)
        user2 = await create_test_user(email="active_not_verified@example.com", is_active=True, is_email_verified=False)
        db_session.add(user1)
        db_session.add(user2)
        await db_session.flush()

        response = await admin_client.get(
            "/api/v1/users?is_active=true&is_email_verified=true"
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # ПРОД-ЛИД ФИКС: читаем из поля items
        users_list = data.get("items", [])
        assert len(users_list) > 0
        for user in users_list:
            assert user["is_active"] is True
            assert user["is_email_verified"] is True

    @pytest.mark.asyncio
    async def test_list_users_unauthorized(self, client):
        """Тест доступа без авторизации."""
        response = await client.get("/api/v1/users")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestAuditLogs:
    """Тесты для GET /admin/audit-logs."""

    @pytest.mark.asyncio
    async def test_get_audit_logs_success(self, admin_client, create_test_audit_log, db_session):
        """Тест успешного получения логов аудита."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user_email = "audit_log_user@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        await create_test_audit_log(user_id=local_user.id, action="login", success=True)
        await db_session.flush()

        response = await admin_client.get("/api/v1/audit-logs")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1

    @pytest.mark.asyncio
    async def test_get_audit_logs_with_filters(self, admin_client, create_test_audit_log, db_session):
        """Тест получения логов с фильтрацией."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user_email = "audit_filter_user@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        await create_test_audit_log(user_id=local_user.id, action="login", success=True)
        await create_test_audit_log(user_id=local_user.id, action="logout", success=True)
        await db_session.flush()

        response = await admin_client.get(
            f"/api/v1/audit-logs?user_id={local_user.id}&action=login&success=true"
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        for item in data["items"]:
            assert item["action"] == "login"
            assert item["success"] is True

    @pytest.mark.asyncio
    async def test_get_audit_logs_invalid_limit(self, admin_client):
        """Тест с некорректным лимитом."""
        response = await admin_client.get("/api/v1/audit-logs?limit=1000")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestAuditActions:
    """Тесты для GET /admin/audit-logs/actions."""

    @pytest.mark.asyncio
    async def test_get_audit_actions_success(self, admin_client, create_test_audit_log, db_session):
        """Тест успешного получения списка действий."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user_email = "audit_actions_user@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        await create_test_audit_log(user_id=local_user.id, action="login", success=True)
        await db_session.flush()
        
        response = await admin_client.get("/api/v1/audit-logs/actions")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # ПРОД-ЛИД ФИКС: читаем из поля actions
        actions_list = data.get("actions", [])
        assert isinstance(actions_list, list)
        assert len(actions_list) > 0
        assert "login" in actions_list


class TestUserAuditLogs:
    """Тесты для GET /admin/audit-logs/user/{user_id}."""

    @pytest.mark.asyncio
    async def test_get_user_audit_logs_success(self, admin_client, create_test_audit_log, db_session):
        """Тест успешного получения логов пользователя."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user_email = "user_audit_logs@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        await create_test_audit_log(user_id=local_user.id, action="login", success=True)
        await db_session.flush()

        response = await admin_client.get(f"/api/v1/audit-logs/user/{local_user.id}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] >= 1

    @pytest.mark.asyncio
    async def test_get_user_audit_logs_with_pagination(self, admin_client, create_test_audit_log, db_session):
        """Тест получения логов пользователя с пагинацией."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user_email = "user_audit_pagination@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        for i in range(10):
            await create_test_audit_log(user_id=local_user.id, action=f"action_{i}", success=True)
        await db_session.flush()

        response = await admin_client.get(
            f"/api/v1/audit-logs/user/{local_user.id}?limit=5&offset=0"
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["items"]) == 5


class TestAdminMetrics:
    """Тесты для GET /admin/metrics."""

    @pytest.mark.asyncio
    async def test_get_admin_metrics_success(self, admin_client):
        """Тест успешного получения метрик."""
        # ПРОД-ЛИД ФИКС: обновлен путь на /system-metrics
        response = await admin_client.get("/api/v1/system-metrics")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "active_users" in data
        assert "total_users" in data
        assert isinstance(data["active_users"], int)
        assert isinstance(data["total_users"], int)

    @pytest.mark.asyncio
    async def test_get_admin_metrics_unauthorized(self, client):
        """Тест доступа к метрикам без авторизации."""
        # ПРОД-ЛИД ФИКС: обновлен путь на /system-metrics
        response = await client.get("/api/v1/system-metrics")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestEdgeCases:
    """Тесты для граничных случаев."""

    @pytest.mark.asyncio
    async def test_get_user_invalid_uuid_format(self, admin_client):
        """Тест с некорректным форматом UUID."""
        response = await admin_client.get("/api/v1/users/invalid-uuid")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_block_user_without_reason(self, admin_client, db_session):
        """Тест блокировки без указания причины."""
        import uuid
        import hashlib
        from sqlalchemy import text
        from app.core.security import hash_password_bcrypt

        admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
        admin_email = "admin@test.com"
        admin_email_hash = hashlib.sha256(admin_email.encode("utf-8")).hexdigest()

        await db_session.execute(text(f"DELETE FROM users WHERE email_hash = '{admin_email_hash}'"))
        await db_session.flush()

        admin_user = User(
            id=admin_id,
            email=admin_email,
            email_hash=admin_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=True,
            is_email_verified=True,
        )
        db_session.add(admin_user)

        user_email = "no_reason_user@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        target_user_id = str(local_user.id)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        response = await admin_client.post(
            f"/api/v1/users/{target_user_id}/block",
            json={},
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_block_user_without_auth(self, client, db_session):
        """Тест блокировки без авторизации."""
        import uuid
        import hashlib
        from app.core.security import hash_password_bcrypt

        user_email = "no_auth_user@example.com"
        user_email_hash = hashlib.sha256(user_email.encode("utf-8")).hexdigest()
        
        local_user = User(
            id=uuid.uuid4(),
            email=user_email,
            email_hash=user_email_hash,
            password_hash=hash_password_bcrypt("SecurePass123!"),
            is_active=True,
            is_superuser=False,
            is_email_verified=True,
        )
        
        if hasattr(local_user, "is_deleted"):
            local_user.is_deleted = False
        if hasattr(local_user, "deleted_at"):
            local_user.deleted_at = None

        db_session.add(local_user)
        await db_session.flush()
        await db_session.refresh(local_user)
        
        response = await client.post(
            f"/api/v1/users/{local_user.id}/block",
            json={"reason": "Test"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED