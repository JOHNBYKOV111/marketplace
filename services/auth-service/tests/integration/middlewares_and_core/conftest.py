"""
Локальный конфиг для тестов middleware и core-компонентов.

Содержит фикстуры для:
- Реальных клиентов для интеграционных тестов
- Тестовых пользователей и заголовков
- Работы с существующей тестовой БД
- Изоляции транзакций через SAVEPOINT
"""

import os
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from typing import AsyncGenerator, Dict, Any

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.main import app
from app.core.database import get_db, AsyncSessionLocal
from app.core.headers import GatewayHeaders
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.core.security import hash_password_bcrypt
from app.core.init_db import ensure_test_users, ensure_audit_logs, init_database_with_users


# ==================== КОНФИГУРАЦИЯ ТЕСТОВОЙ БД ====================

TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@postgres:5432/auth_db_test"
)


# ==================== ГЛОБАЛЬНАЯ ИНИЦИАЛИЗАЦИЯ (SESSION) ====================

@pytest.fixture(scope="session")
def event_loop():
    """Единый event loop на всю сессию для асинхронных фикстур."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def async_engine():
    """Единый engine на всю сессию тестов."""
    return create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        pool_pre_ping=True,
    )


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_session_database(async_engine):
    """
    Накатывает структуру и пользователей один раз за сессию.
    """
    print("\n=== [Инит] Накатываем пользователей на всю сессию ===")
    
    async with AsyncSession(async_engine) as session:
        await init_database_with_users()
        print("=== [Инит] Базовые данные зафиксированы ===")


# ==================== ИЗОЛЯЦИЯ ТЕСТОВ ЧЕРЕЗ SAVEPOINT ====================

@pytest_asyncio.fixture(scope="function")
async def db_session(async_engine):
    """
    Изолированная сессия для каждого теста через SAVEPOINT.
    Каждый тест получает свою транзакцию, которая откатывается после теста.
    """
    async with async_engine.connect() as connection:
        async with connection.begin() as transaction:
            async with AsyncSession(bind=connection, expire_on_commit=False) as session:
                await session.begin_nested()
                
                yield session
                
                await transaction.rollback()


# ==================== ФИКСТУРЫ ДЛЯ КЛИЕНТОВ ====================

@pytest_asyncio.fixture(scope="function")
async def admin_client(db_session, admin_headers):
    """
    Клиент для администратора с изолированной транзакцией.
    """
    app.dependency_overrides[get_db] = lambda: db_session
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver", headers=admin_headers) as client:
        yield client
    
    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def regular_client(db_session, user_headers):
    """
    Клиент для обычного пользователя с изолированной транзакцией.
    """
    app.dependency_overrides[get_db] = lambda: db_session
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver", headers=user_headers) as client:
        yield client
    
    app.dependency_overrides.clear()


# ==================== ФИКСТУРЫ ДЛЯ ПОЛЬЗОВАТЕЛЕЙ ====================

@pytest_asyncio.fixture(scope="function")
async def admin_user(db_session: AsyncSession) -> User:
    """
    Создание реального администратора в БД.
    Использует логику из init_db.py для единообразия.
    """
    admin, _ = await ensure_test_users(db_session, commit=False)
    return admin


@pytest_asyncio.fixture(scope="function")
async def regular_user(db_session: AsyncSession) -> User:
    """
    Создание реального обычного пользователя в БД.
    Использует логику из init_db.py для единообразия.
    """
    _, user = await ensure_test_users(db_session, commit=False)
    return user


@pytest_asyncio.fixture(scope="function")
async def audit_logs(db_session: AsyncSession, admin_user: User) -> None:
    """
    Создание тестовых аудит-логов для проверки эндпоинта /admin/audit-logs.
    """
    await ensure_audit_logs(db_session, admin_user.id)


# ==================== ФИКСТУРЫ ДЛЯ ЗАГОЛОВКОВ ====================

@pytest_asyncio.fixture(scope="function")
async def admin_headers(admin_user: User) -> Dict[str, str]:
    """Заголовки для администратора (имитация Gateway)."""
    return {
        GatewayHeaders.USER_ID: str(admin_user.id),
        GatewayHeaders.USER_ROLES: "admin",
    }


@pytest_asyncio.fixture(scope="function")
async def user_headers(regular_user: User) -> Dict[str, str]:
    """Заголовки для обычного пользователя (имитация Gateway)."""
    return {
        GatewayHeaders.USER_ID: str(regular_user.id),
        GatewayHeaders.USER_ROLES: "user",
    }


# ==================== ФИКСТУРЫ ДЛЯ МОКОВ ====================

@pytest_asyncio.fixture
def mock_user_repo():
    """Фикстура для мока репозитория пользователя."""
    repo = AsyncMock(spec=UserRepository)
    
    mock_user = User(
        id=uuid4(),
        email="test@example.com",
        email_hash=User.create_email_hash("test@example.com"),
        password_hash="hashed_password",
        is_active=True,
        is_email_verified=True,
        is_superuser=False,
    )
    repo.get_by_id = AsyncMock(return_value=mock_user)
    repo.get_by_email_hash = AsyncMock(return_value=mock_user)
    
    return repo


@pytest_asyncio.fixture
def mock_token_service():
    """Фикстура для мока токен сервиса."""
    service = AsyncMock(spec=TokenService)
    
    service.decode_token = AsyncMock(return_value={
        "sub": str(uuid4()),
        "exp": 1234567890,
        "iat": 1234567890,
        "type": "access",
    })
    service.create_token = AsyncMock(return_value="mock_token")
    
    return service


# ==================== ПЕРЕКЛЮЧАТЕЛЬ РЕЖИМОВ ====================

@pytest.fixture
def use_real_auth():
    """Фикстура для включения реальной авторизации."""
    with patch("app.core.dependencies.get_current_user_context") as mock:
        mock.return_value = None
        yield mock


@pytest.fixture
def use_mock_auth():
    """Фикстура для включения мок-авторизации."""
    with patch("app.core.dependencies.get_current_user_context") as mock:
        mock_user = User(
            id=uuid4(),
            email="test@example.com",
            email_hash=User.create_email_hash("test@example.com"),
            password_hash="hashed",
            is_active=True,
            is_email_verified=True,
            is_superuser=True,
        )
        mock.return_value = mock_user
        yield mock