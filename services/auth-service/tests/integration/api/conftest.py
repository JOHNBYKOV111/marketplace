"""
Локальный конфиг для API тестов.

Содержит фикстуры для:
- Тестовых ролей (admin, regular, blocked)
- Заголовков авторизации
- Токенов доступа
- Клиентов с токенами
- Обхода Rate Limiter
- Auth тестов (login, refresh, logout, verify-email)
- JWKS тестов (реальные ключи, реальная БД, общая сессия)
- MFA тестов (реальная логика, синглтон MFAService)
- OAuth тестов (реальная БД, мок exchange_code)
"""

from uuid import uuid4
from typing import Dict, AsyncGenerator
from datetime import datetime, timedelta, timezone

import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.core.config import settings
from app.core.database import get_db
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.models.user_security_settings import UserSecuritySettings
from app.repositories.jwk_key_repository import JWKKeyRepository
from app.repositories.user_repository import UserRepository
from app.services.jwk_service import JWKService
from app.services.mfa_service import MFAService
from app.services.oauth_service import OAuthService
from app.routers.mfa import get_mfa_service
from app.routers.oauth import get_oauth_service, get_auth_service_for_oauth
from app.core.dependencies import get_current_user, get_current_admin


# ==================== СИНХРОНИЗАЦИЯ НАСТРОЕК ДЛЯ ТЕСТОВ ====================

if not hasattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES"):
    val_access = getattr(settings, "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", getattr(settings, "access_token_expire_minutes", 30))
    settings.__dict__["ACCESS_TOKEN_EXPIRE_MINUTES"] = val_access

if not hasattr(settings, "REFRESH_TOKEN_EXPIRE_MINUTES"):
    days = getattr(settings, "JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7)
    settings.__dict__["REFRESH_TOKEN_EXPIRE_MINUTES"] = days * 24 * 60

if not hasattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS"):
    val_refresh = getattr(settings, "JWT_REFRESH_TOKEN_EXPIRE_DAYS", getattr(settings, "refresh_token_expire_days", 7))
    settings.__dict__["REFRESH_TOKEN_EXPIRE_DAYS"] = val_refresh


# ==================== КОНСТАНТЫ ДЛЯ ОБХОДА RATE LIMITER ====================

TEST_BYPASS_HEADER = "X-Test-Bypass"
TEST_BYPASS_SECRET = "test-bypass-secret-key-2024"


# ==================== ФИКСТУРЫ ДЛЯ ЗАГОЛОВКОВ ====================

@pytest_asyncio.fixture
def admin_headers() -> Dict[str, str]:
    return {"Authorization": "Bearer admin_test_token", "X-User-Role": "admin", "X-User-Id": str(uuid4())}


@pytest_asyncio.fixture
def auth_headers() -> Dict[str, str]:
    return {"Authorization": "Bearer user_test_token", "X-User-Role": "user", "X-User-Id": str(uuid4())}


# ==================== ФИКСТУРЫ ДЛЯ ТЕСТОВЫХ РОЛЕЙ ====================

@pytest_asyncio.fixture
async def admin_user(create_test_user):
    return await create_test_user(email=f"admin_{uuid4().hex[:8]}@example.com", password="Admin123!", is_active=True, is_email_verified=True, is_superuser=True)


@pytest_asyncio.fixture
async def regular_user(create_test_user):
    return await create_test_user(email=f"user_{uuid4().hex[:8]}@example.com", password="User123!", is_active=True, is_email_verified=True, is_superuser=False)


@pytest_asyncio.fixture
async def blocked_user(create_test_user):
    return await create_test_user(email=f"blocked_{uuid4().hex[:8]}@example.com", password="Blocked123!", is_active=False, is_email_verified=True, is_superuser=False)


# ==================== ФИКСТУРЫ ДЛЯ AUTH ТЕСТОВ ====================

@pytest_asyncio.fixture
async def unverified_user(create_test_user):
    return await create_test_user(email=f"unverified_{uuid4().hex[:8]}@example.com", password="SecurePass123!", is_active=True, is_email_verified=False, is_superuser=False)


@pytest_asyncio.fixture
async def create_test_security_settings(db_session):
    async def _create(user_id, totp_enabled=False, totp_secret=None):
        s = UserSecuritySettings(user_id=user_id, totp_enabled=totp_enabled, totp_secret=totp_secret or f"totp_secret_{uuid4().hex[:16]}", totp_backup_codes=[])
        db_session.add(s)
        await db_session.flush()
        return s
    return _create


@pytest_asyncio.fixture
async def create_refresh_token(db_session):
    async def _create(user_id, token=None, expires_at=None, client_ip="127.0.0.1", user_agent="pytest"):
        from app.repositories.refresh_token_repository import RefreshTokenRepository
        repo = RefreshTokenRepository(db_session)
        token = token or f"test_refresh_{uuid4().hex[:16]}"
        expires_at = expires_at or (datetime.now(timezone.utc) + timedelta(days=30))
        await repo.create_token(user_id=user_id, token=token, expires_at=expires_at, client_ip=client_ip, user_agent=user_agent)
        await db_session.flush()
        return token
    return _create


# ==================== БАЗОВЫЕ КЛИЕНТЫ ====================

@pytest_asyncio.fixture
async def auth_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    app.dependency_overrides[get_db] = lambda: db_session
    await db_session.flush()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
    app.dependency_overrides.pop(get_db, None)


@pytest_asyncio.fixture
def get_url():
    routes = {"auth:login": "/api/v1/auth/login", "auth:refresh": "/api/v1/auth/refresh", "auth:logout": "/api/v1/auth/logout", "auth:logout_all": "/api/v1/auth/logout-all", "auth:verify_email": "/api/v1/auth/verify-email", "auth:verify_phone": "/api/v1/auth/verify-phone"}
    return lambda name: routes.get(name, f"/api/v1/{name}")


# ==================== ТОКЕНЫ ====================

@pytest_asyncio.fixture
async def admin_token(db_session) -> str:
    from app.core.init_db import init_database_with_users
    await init_database_with_users()
    await db_session.flush()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/api/v1/auth/login", json={"email": "admin@test.com", "password": "SecurePass123!"}, headers={TEST_BYPASS_HEADER: TEST_BYPASS_SECRET})
        assert r.status_code == 200, f"Admin login failed: {r.text}"
        return r.json()["access_token"]


@pytest_asyncio.fixture
async def regular_token(db_session) -> str:
    from app.core.init_db import init_database_with_users
    await init_database_with_users()
    await db_session.flush()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/api/v1/auth/login", json={"email": "user@test.com", "password": "SecurePass123!"}, headers={TEST_BYPASS_HEADER: TEST_BYPASS_SECRET})
        assert r.status_code == 200, f"User login failed: {r.text}"
        return r.json()["access_token"]


# ==================== АДМИН И ПОЛЬЗОВАТЕЛЬ КЛИЕНТЫ ====================

@pytest_asyncio.fixture
async def admin_client(db_session: AsyncSession, admin_token) -> AsyncGenerator[AsyncClient, None]:
    import hashlib, uuid
    admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
    admin_email = "admin@test.com"
    admin_user = User(id=admin_id, email=admin_email, email_hash=hashlib.sha256(admin_email.encode()).hexdigest(), is_active=True, is_superuser=True, is_email_verified=True)

    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_user] = lambda: admin_user
    app.dependency_overrides[get_current_admin] = lambda: admin_user
    await db_session.flush()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        client.headers["Authorization"] = f"Bearer {admin_token}"
        yield client

    for dep in [get_db, get_current_user, get_current_admin]:
        app.dependency_overrides.pop(dep, None)


@pytest_asyncio.fixture
async def regular_client(db_session: AsyncSession, regular_token) -> AsyncGenerator[AsyncClient, None]:
    app.dependency_overrides[get_db] = lambda: db_session
    await db_session.flush()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        client.headers["Authorization"] = f"Bearer {regular_token}"
        yield client
    app.dependency_overrides.pop(get_db, None)


# ==================== JWKS ФИКСТУРЫ (ОБЩАЯ СЕССИЯ) ====================

@pytest_asyncio.fixture
async def jwk_service(db_session: AsyncSession) -> JWKService:
    return JWKService(JWKKeyRepository(db_session))


@pytest_asyncio.fixture
async def jwks_public_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    app.dependency_overrides[get_db] = lambda: db_session
    await db_session.flush()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
    app.dependency_overrides.pop(get_db, None)


@pytest_asyncio.fixture
async def jwks_admin_client(db_session: AsyncSession, admin_token: str) -> AsyncGenerator[AsyncClient, None]:
    import hashlib, uuid
    admin_id = uuid.UUID("48f0b63c-e60b-4692-ba08-4d199a489b9b")
    admin_email = "admin@test.com"
    admin_user = User(id=admin_id, email=admin_email, email_hash=hashlib.sha256(admin_email.encode()).hexdigest(), is_active=True, is_superuser=True, is_email_verified=True)

    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_user] = lambda: admin_user
    app.dependency_overrides[get_current_admin] = lambda: admin_user
    await db_session.flush()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        client.headers["Authorization"] = f"Bearer {admin_token}"
        yield client

    for dep in [get_db, get_current_user, get_current_admin]:
        app.dependency_overrides.pop(dep, None)


# ==================== MFA ФИКСТУРЫ (СИНГЛТОН СЕРВИС) ====================

@pytest_asyncio.fixture
async def mfa_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    mfa_service = MFAService()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_mfa_service] = lambda: mfa_service
    await db_session.flush()
    headers = {"X-User-Id": str(uuid4()), "X-User-Roles": "user", "X-User-Email": "test@example.com"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        client.headers.update(headers)
        yield client
    for dep in [get_db, get_mfa_service]:
        app.dependency_overrides.pop(dep, None)


# ==================== OAUTH ФИКСТУРЫ (РЕАЛЬНАЯ БД, МОК EXCHANGE_CODE) ====================

@pytest_asyncio.fixture
async def oauth_service(db_session: AsyncSession) -> OAuthService:
    """OAuthService с реальной БД."""
    repo = UserRepository(db_session)
    return OAuthService(user_repository=repo)


@pytest_asyncio.fixture
async def oauth_client(db_session: AsyncSession, oauth_service: OAuthService) -> AsyncGenerator[AsyncClient, None]:
    """Клиент для OAuth тестов с реальной БД и Redis."""
    mock_auth = MagicMock()
    mock_auth.create_tokens = AsyncMock(return_value=("access_token", "refresh_token"))

    app.dependency_overrides[get_oauth_service] = lambda: oauth_service
    app.dependency_overrides[get_auth_service_for_oauth] = lambda: mock_auth
    await db_session.flush()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        yield client

    for dep in [get_oauth_service, get_auth_service_for_oauth]:
        app.dependency_overrides.pop(dep, None)