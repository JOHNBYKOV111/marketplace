"""
Локальный конфиг для тестов репозиториев.

Содержит фикстуры для:
- Репозиториев (audit_log_repository, user_repository, jwk_repository, oauth_state_repository, password_reset_repository, refresh_token_repository)
- Тестовых данных для JWK ключей
- Тестовых ID пользователей
- Тестовых OAuth состояний
- Тестового пользователя для password_reset тестов
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.jwk_key import JWKKey
from app.models.oauth_state import OAuthState
from app.models.user import User
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.user_repository import UserRepository
from app.repositories.jwk_key_repository import JWKKeyRepository
from app.repositories.oauth_state_repository import OAuthStateRepository
from app.repositories.password_reset_token_repository import PasswordResetTokenRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository


# ==================== ФИКСТУРЫ РЕПОЗИТОРИЕВ ====================

@pytest_asyncio.fixture(scope="function")
async def audit_log_repository(db_session: AsyncSession) -> AuditLogRepository:
    """Фикстура репозитория аудит-логов."""
    return AuditLogRepository(db_session)


@pytest_asyncio.fixture(scope="function")
async def user_repository(db_session: AsyncSession) -> UserRepository:
    """Фикстура репозитория пользователей."""
    return UserRepository(db_session)


@pytest_asyncio.fixture(scope="function")
async def jwk_repository(db_session: AsyncSession) -> JWKKeyRepository:
    """Фикстура репозитория JWK ключей."""
    return JWKKeyRepository(db_session)


@pytest_asyncio.fixture(scope="function")
async def oauth_state_repository(db_session: AsyncSession) -> OAuthStateRepository:
    """Фикстура репозитория OAuth состояний."""
    return OAuthStateRepository(db_session)


@pytest_asyncio.fixture(scope="function")
async def password_reset_repository(db_session: AsyncSession) -> PasswordResetTokenRepository:
    """Фикстура репозитория токенов сброса пароля."""
    return PasswordResetTokenRepository(db_session)


@pytest_asyncio.fixture(scope="function")
async def refresh_token_repository(db_session: AsyncSession) -> RefreshTokenRepository:
    """Фикстура репозитория refresh токенов."""
    return RefreshTokenRepository(db_session)


# ==================== ФИКСТУРЫ ДЛЯ OAuth ТЕСТОВ ====================

@pytest.fixture
def sample_user_id() -> uuid4:
    """ID пользователя для тестов OAuth."""
    return uuid4()


@pytest_asyncio.fixture
async def sample_oauth_state(
    oauth_state_repository: OAuthStateRepository,
    db_session: AsyncSession,
    sample_user_id: uuid4,
) -> OAuthState:
    """Создание тестового OAuth state."""
    oauth_state, state, code_verifier = OAuthState.create_login_state(
        provider="google",
        redirect_uri="https://example.com/callback",
        scope="email profile",
        ttl_seconds=600,
    )
    created = await oauth_state_repository.create(oauth_state)
    await db_session.flush()
    return created


# ==================== ФИКСТУРЫ ДЛЯ ПАРОЛЬ-РЕСЕТ ТЕСТОВ ====================

@pytest_asyncio.fixture(scope="function")
async def test_user(db_session: AsyncSession) -> UUID:
    """Создание реального пользователя в БД для тестов password_reset."""
    user = User(
        email=f"test_{uuid4()}@example.com",
        password_hash="hashed_password",
        is_active=True,
        is_email_verified=True,
        is_superuser=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user.id


# ==================== ФИКСТУРЫ ДЛЯ JWK ТЕСТОВ ====================

@pytest.fixture
def sample_active_key() -> JWKKey:
    """Активный JWK ключ с уникальным kid."""
    return JWKKey(
        kid=f"active_key_{uuid4().hex[:8]}",
        private_key_encrypted=f"encrypted_private_{uuid4().hex[:8]}",
        public_key="-----BEGIN PUBLIC KEY-----\nTEST1\n-----END PUBLIC KEY-----",
        algorithm="RS256",
        key_type="RSA",
        is_active=True,
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )


@pytest.fixture
def sample_inactive_key() -> JWKKey:
    """Неактивный JWK ключ с уникальным kid."""
    return JWKKey(
        kid=f"inactive_key_{uuid4().hex[:8]}",
        private_key_encrypted=f"encrypted_private_{uuid4().hex[:8]}",
        public_key="-----BEGIN PUBLIC KEY-----\nTEST2\n-----END PUBLIC KEY-----",
        algorithm="RS256",
        key_type="RSA",
        is_active=False,
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )


@pytest.fixture
def sample_expired_key() -> JWKKey:
    """Истекший JWK ключ с уникальным kid."""
    return JWKKey(
        kid=f"expired_key_{uuid4().hex[:8]}",
        private_key_encrypted=f"encrypted_private_{uuid4().hex[:8]}",
        public_key="-----BEGIN PUBLIC KEY-----\nTEST3\n-----END PUBLIC KEY-----",
        algorithm="RS256",
        key_type="RSA",
        is_active=False,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )