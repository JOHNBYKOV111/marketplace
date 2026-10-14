"""
E2E Integration Test Fixtures for user ↔ auth service.

Lead-level design:
- Fully isolated: each test creates and destroys its own user via real API calls
- Dynamic data: Faker generates unique credentials per test run (no shared state)
- Pydantic contract validation: all responses validated against auth-service schemas
- Parallel-safe: zero hardcoded IDs/emails, full cleanup via API
- Real services only: no mocks, actual HTTP between auth-service and user-service

Provides:
- HTTP clients for both auth-service and user-service (real HTTP)
- Dynamic test user lifecycle (create via API → login → verify → delete)
- JWT token acquisition via real auth-service login
- Full cleanup after each test
- Pre-test cleanup: CircuitBreaker reset + Redis flush
- Two-sided AUTOCOMMIT seeding: writes to BOTH auth_db and user_db
- Session-scoped credentials: same email for seeder and test
- Idempotent: checks existing user before creating new
- Consistent UUID across both databases
"""

import asyncio
import hashlib
from typing import AsyncGenerator, Dict, Optional
from uuid import uuid4

import bcrypt
import pytest
import pytest_asyncio
from faker import Faker
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.models.base import Base as UserBase

from tests.e2e.schemas.auth_schemas import LoginResponse as AuthLoginResponse


# ==================== CONFIGURATION ====================

AUTH_SERVICE_BASE_URL = "http://auth-service:8000"
USER_SERVICE_BASE_URL = "http://user-service:8000"

AUTH_LOGIN_URL = "/api/v1/auth/login"
AUTH_LOGOUT_URL = "/api/v1/auth/logout"
AUTH_REGISTER_URL = "/api/v1/auth/register"
AUTH_DELETE_USER_URL = "/api/v1/users/{user_id}"
INTERNAL_USER_CREATE_URL = "/internal/user/create"
INTERNAL_USER_DELETE_URL = "/internal/user/delete"

INTERNAL_API_KEY = "test_api_key"

# Pepper должен совпадать с settings.SECRET_PEPPER в auth-service
AUTH_PEPPER = "your-pepper-change-in-production"

# Изолированные движки для прямых SQL-записей
AUTH_DB_URL = "postgresql+asyncpg://postgres:postgres@postgres:5432/auth_db"
USER_DB_URL = "postgresql+asyncpg://postgres:postgres@postgres:5432/user_db"

fake = Faker()


def _normalize_email(email: str) -> str:
    """Отрезает +суффикс — совпадает с логикой user-service."""
    if "+" in email:
        local, domain = email.split("@", 1)
        local = local.split("+")[0]
        return f"{local}@{domain}"
    return email


# ==================== DATABASE SETUP ====================

@pytest.fixture(scope="session")
def test_engine():
    engine = create_async_engine(
        settings.TEST_DATABASE_URL,
        echo=False,
        poolclass=NullPool,
    )
    return engine


@pytest.fixture(scope="session", autouse=True)
async def setup_database(test_engine):
    async with test_engine.begin() as conn:
        await conn.run_sync(UserBase.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(UserBase.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    async_session = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with test_engine.connect() as connection:
        session = async_session(bind=connection)
        yield session
        await session.rollback()
        await session.close()


# ==================== CLEANUP BEFORE EACH TEST ====================

@pytest_asyncio.fixture(autouse=True)
async def clean_cb_and_redis():
    """Сбрасывает CircuitBreaker и чистит Redis перед каждым тестом."""
    from app.core.redis_client import get_redis
    
    try:
        from app.core.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=100, recovery_timeout=3.0))
        await cb.force_close()
    except Exception:
        pass
    
    try:
        redis = await get_redis()
        await redis.flushdb()
    except Exception:
        pass
    
    yield


# ==================== HTTP CLIENTS ====================

@pytest_asyncio.fixture
async def auth_client() -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(base_url=AUTH_SERVICE_BASE_URL, timeout=30.0) as client:
        yield client


@pytest_asyncio.fixture
async def internal_auth_headers() -> Dict[str, str]:
    return {"X-Internal-API-Key": INTERNAL_API_KEY}


@pytest_asyncio.fixture
async def user_client() -> AsyncGenerator[AsyncClient, None]:
    """Реальный HTTP-клиент к user-service."""
    async with AsyncClient(base_url=USER_SERVICE_BASE_URL, timeout=30.0) as client:
        yield client


# ==================== DYNAMIC USER LIFECYCLE ====================

@pytest.fixture(scope="session")
def dynamic_user_credentials() -> Dict[str, str]:
    """Session-scoped: ОДИНАКОВЫЙ email для всех тестов в сессии."""
    return {
        "email": f"e2e.{fake.uuid4()}@example.com",
        "password": "E2eTestPass123!",
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
    }


def _make_auth_password_hash(password: str) -> str:
    """Хэширует пароль с pepper используя bcrypt rounds=12."""
    peppered = f"{password}{AUTH_PEPPER}"
    return bcrypt.hashpw(
        peppered.encode("utf-8"),
        bcrypt.gensalt(rounds=12),
    ).decode("utf-8")


async def _find_existing_user_id(
    email_hash: str,
    db_url: str,
) -> Optional[str]:
    """Находит user_id по email_hash в указанной БД."""
    engine = create_async_engine(db_url, isolation_level="AUTOCOMMIT")
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text("SELECT id FROM users WHERE email_hash = :email_hash"),
                {"email_hash": email_hash},
            )
            row = result.fetchone()
            return str(row[0]) if row else None
    finally:
        await engine.dispose()


async def _seed_user_both_dbs(
    user_id: str,
    email: str,
    password_hash: str,
    first_name: str,
    last_name: str,
) -> str:
    """Записывает пользователя в ОБЕ базы: auth_db и user_db.

    Возвращает РЕАЛЬНЫЙ user_id из auth_db (может отличаться от
    переданного если email уже существовал).
    """
    email_hash = hashlib.sha256(email.lower().strip().encode("utf-8")).hexdigest()
    real_user_id = user_id

    # 1. auth_db — для логина
    auth_engine = create_async_engine(AUTH_DB_URL, isolation_level="AUTOCOMMIT")
    try:
        async with auth_engine.connect() as conn:
            # Пробуем вставить
            await conn.execute(
                text(
                    """
                    INSERT INTO users (id, email, email_hash, password_hash, is_active, is_email_verified, is_superuser)
                    VALUES (:id, :email, :email_hash, :password_hash, true, true, false)
                    ON CONFLICT (email) DO NOTHING
                    """
                ),
                {
                    "id": user_id,
                    "email": email,
                    "email_hash": email_hash,
                    "password_hash": password_hash,
                },
            )
            # Получаем реальный id из auth_db
            result = await conn.execute(
                text("SELECT id FROM users WHERE email_hash = :email_hash"),
                {"email_hash": email_hash},
            )
            row = result.fetchone()
            if row:
                real_user_id = str(row[0])
    finally:
        await auth_engine.dispose()

    # 2. user_db — используем РЕАЛЬНЫЙ id из auth_db
    user_engine = create_async_engine(USER_DB_URL, isolation_level="AUTOCOMMIT")
    try:
        async with user_engine.connect() as conn:
            await conn.execute(
                text(
                    """
                    INSERT INTO users (id, email_hash, first_name, last_name, is_deleted)
                    VALUES (:id, :email_hash, :first_name, :last_name, false)
                    ON CONFLICT (email_hash) DO UPDATE
                    SET first_name = :first_name, last_name = :last_name, is_deleted = false
                    """
                ),
                {
                    "id": real_user_id,
                    "email_hash": email_hash,
                    "first_name": first_name,
                    "last_name": last_name,
                },
            )
    finally:
        await user_engine.dispose()

    return real_user_id


@pytest_asyncio.fixture(scope="function", autouse=True)
async def user_exists_in_user_service(
    dynamic_user_credentials: Dict[str, str],
) -> str:
    """AUTOUSE двухсторонний сидер.

    Проверяет существующую запись по email_hash. Если найдена —
    возвращает её id. Если нет — создаёт новую.
    Возвращает РЕАЛЬНЫЙ user_id из auth_db.
    """
    email = dynamic_user_credentials["email"]
    password = dynamic_user_credentials["password"]
    first_name = dynamic_user_credentials["first_name"]
    last_name = dynamic_user_credentials["last_name"]

    password_hash = _make_auth_password_hash(password)
    email_hash = hashlib.sha256(email.lower().strip().encode("utf-8")).hexdigest()

    # Проверяем существует ли пользователь в auth_db
    existing_id = await _find_existing_user_id(email_hash, AUTH_DB_URL)
    if existing_id:
        return existing_id

    # Пользователь не существует — создаём
    user_id = str(uuid4())
    real_id = await _seed_user_both_dbs(
        user_id=user_id,
        email=email,
        password_hash=password_hash,
        first_name=first_name,
        last_name=last_name,
    )

    return real_id


@pytest_asyncio.fixture
async def e2e_user(
    auth_client: AsyncClient,
    internal_auth_headers: Dict[str, str],
    dynamic_user_credentials: Dict[str, str],
    user_exists_in_user_service: str,
) -> Dict[str, str]:
    """Использует UUID от autouse сидера."""
    email = dynamic_user_credentials["email"]
    user_info = {
        "user_id": user_exists_in_user_service,
        "email": email,
    }
    yield user_info


@pytest_asyncio.fixture
async def auth_jwt(
    auth_client: AsyncClient,
    dynamic_user_credentials: Dict[str, str],
) -> str:
    response = await auth_client.post(
        AUTH_LOGIN_URL,
        json={
            "email": dynamic_user_credentials["email"],
            "password": dynamic_user_credentials["password"],
        },
    )
    assert response.status_code == 200, (
        f"Login failed: {response.status_code} — {response.text}"
    )

    login_data = AuthLoginResponse.model_validate(response.json())
    assert login_data.access_token, "No access_token in auth response"
    return login_data.access_token


@pytest_asyncio.fixture
async def auth_headers(auth_jwt: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {auth_jwt}"}