"""
Фикстуры для тестирования репозиториев.

Предоставляет:
- Моки репозиториев с предопределёнными ответами
- Фабрики для создания тестовых данных
- Хелперы для настройки моков под конкретные тестовые сценарии
- Наборы данных для каждого репозитория
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.jwk_key import JWKKey
from app.models.oauth_state import OAuthState
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_security_settings import UserSecuritySettings
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.jwk_key_repository import JWKKeyRepository
from app.repositories.oauth_state_repository import OAuthStateRepository
from app.repositories.password_reset_token_repository import PasswordResetTokenRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository
from app.repositories.user_security_settings_repository import UserSecuritySettingsRepository


# ==================== ФАБРИКИ ТЕСТОВЫХ ДАННЫХ ====================

class UserTestDataFactory:
    """Фабрика тестовых пользователей."""
    
    @staticmethod
    def create_user(
        user_id: UUID | None = None,
        email: str = "test@example.com",
        password_hash: str = "hashed_password",
        is_active: bool = True,
        is_email_verified: bool = False,
    ) -> User:
        """Создание тестового пользователя."""
        return User(
            id=user_id or uuid4(),
            email_hash=User.create_email_hash(email),
            password_hash=password_hash,
            is_active=is_active,
            is_email_verified=is_email_verified,
        )
    
    @staticmethod
    def create_active_user(user_id: UUID | None = None) -> User:
        """Создание активного пользователя."""
        return UserTestDataFactory.create_user(user_id=user_id, is_active=True)
    
    @staticmethod
    def create_blocked_user(user_id: UUID | None = None) -> User:
        """Создание заблокированного пользователя."""
        return UserTestDataFactory.create_user(user_id=user_id, is_active=False)
    
    @staticmethod
    def create_verified_user(user_id: UUID | None = None) -> User:
        """Создание верифицированного пользователя."""
        return UserTestDataFactory.create_user(
            user_id=user_id,
            is_email_verified=True,
        )


class RefreshTokenTestDataFactory:
    """Фабрика тестовых Refresh Token."""
    
    @staticmethod
    def create_refresh_token(
        token_id: str | None = None,
        user_id: UUID | None = None,
        expires_days: int = 30,
    ) -> RefreshToken:
        """Создание тестового Refresh Token."""
        return RefreshToken.create_token(
            user_id=user_id or uuid4(),
            expires_days=expires_days,
            device_id="test_device",
            device_name="Test Device",
            ip_address="127.0.0.1",
            user_agent="pytest",
        )
    
    @staticmethod
    def create_active_token(user_id: UUID | None = None) -> RefreshToken:
        """Создание активного Refresh Token."""
        return RefreshTokenTestDataFactory.create_refresh_token(user_id=user_id)
    
    @staticmethod
    def create_revoked_token(user_id: UUID | None = None) -> RefreshToken:
        """Создание отозванного Refresh Token."""
        token = RefreshTokenTestDataFactory.create_refresh_token(user_id=user_id)
        token.revoke()
        return token


class JWKKeyTestDataFactory:
    """Фабрика тестовых JWK ключей."""
    
    @staticmethod
    def create_active_rsa_key(kid: str = "test_rsa_1") -> JWKKey:
        """Создание активного RSA ключа."""
        return JWKKey(
            kid=kid,
            private_key_encrypted="encrypted_private",
            public_key="-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----",
            algorithm="RS256",
            key_type="RSA",
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
    
    @staticmethod
    def create_expired_key(kid: str = "expired_rsa_1") -> JWKKey:
        """Создание истекшего ключа."""
        return JWKKey(
            kid=kid,
            private_key_encrypted="encrypted_private",
            public_key="-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----",
            algorithm="RS256",
            key_type="RSA",
            is_active=False,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )


# ==================== МОКИ РЕПОЗИТОРИЕВ ====================

class UserRepositoryMock:
    """Мок UserRepository с предопределёнными ответами."""
    
    def __init__(self):
        self.users: dict[UUID, User] = {}
        self.should_fail_on_create = False
        self.should_fail_on_update = False
    
    def add_user(self, user: User) -> None:
        """Добавление пользователя в мок хранилище."""
        self.users[user.id] = user
    
    async def create(self, user: User) -> User:
        if self.should_fail_on_create:
            raise Exception("Database error")
        self.users[user.id] = user
        return user
    
    async def get_by_id(self, user_id: UUID) -> User | None:
        return self.users.get(user_id)
    
    async def get_by_email_hash(self, email_hash: str) -> User | None:
        for user in self.users.values():
            if user.email_hash == email_hash:
                return user
        return None
    
    async def update(self, user_id: UUID, **values) -> User | None:
        if self.should_fail_on_update:
            raise Exception("Database error")
        user = self.users.get(user_id)
        if user:
            for key, value in values.items():
                setattr(user, key, value)
        return user
    
    async def delete(self, user_id: UUID) -> bool:
        if user_id in self.users:
            del self.users[user_id]
            return True
        return False


class RefreshTokenRepositoryMock:
    """Мок RefreshTokenRepository с предопределёнными ответами."""
    
    def __init__(self):
        self.tokens: dict[str, RefreshToken] = {}
        self.revoked_tokens: set[str] = set()
    
    def add_token(self, token: RefreshToken) -> None:
        self.tokens[token.token_id] = token
    
    async def create(self, token_id: str, user_id: UUID, **kwargs) -> RefreshToken:
        token = RefreshTokenTestDataFactory.create_refresh_token(
            token_id=token_id,
            user_id=user_id,
        )
        self.tokens[token_id] = token
        return token
    
    async def get_active_by_token_id(self, token_id: str) -> RefreshToken | None:
        token = self.tokens.get(token_id)
        if token and token_id not in self.revoked_tokens:
            return token
        return None
    
    async def revoke(self, token_id: str) -> None:
        self.revoked_tokens.add(token_id)
    
    async def delete_expired(self) -> int:
        count = 0
        for token_id in list(self.tokens.keys()):
            if self.tokens[token_id].is_expired():
                del self.tokens[token_id]
                count += 1
        return count


class JWKKeyRepositoryMock:
    """Мок JWKKeyRepository с предопределёнными ответами."""
    
    def __init__(self):
        self.keys: dict[str, JWKKey] = {}
    
    def add_key(self, key: JWKKey) -> None:
        self.keys[key.kid] = key
    
    async def get_active_keys(self) -> list[JWKKey]:
        now = datetime.now(timezone.utc)
        return [
            key for key in self.keys.values()
            if key.is_active and key.expires_at and key.expires_at > now
        ]
    
    async def get_by_kid(self, kid: str) -> JWKKey | None:
        return self.keys.get(kid)
    
    async def create(self, key: JWKKey) -> JWKKey:
        self.keys[key.kid] = key
        return key


class AuditLogRepositoryMock:
    """Мок AuditLogRepository с предопределёнными ответами."""
    
    def __init__(self):
        self.logs: list[AuditLog] = []
        self.next_id = 1
    
    def add_log(self, log: AuditLog) -> None:
        log.id = self.next_id
        self.next_id += 1
        self.logs.append(log)
    
    async def create(self, log: AuditLog) -> AuditLog:
        log.id = self.next_id
        self.next_id += 1
        self.logs.append(log)
        return log
    
    async def get_with_filters(
        self,
        user_id: UUID | None = None,
        action: str | None = None,
        success: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditLog], int]:
        filtered = self.logs
        if user_id:
            filtered = [l for l in filtered if l.user_id == user_id]
        if action:
            filtered = [l for l in filtered if l.action == action]
        if success is not None:
            filtered = [l for l in filtered if l.success == success]
        
        total = len(filtered)
        paginated = filtered[offset:offset + limit]
        return paginated, total


# ==================== Pytest FIXTURES ====================

@pytest.fixture
def mock_db_session() -> AsyncMock:
    """Мок асинхронной сессии БД."""
    session = AsyncMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.close = AsyncMock()
    return session


@pytest.fixture
def user_repository(mock_db_session: AsyncMock) -> UserRepository:
    """Фикстура UserRepository с мок сессией."""
    return UserRepository(mock_db_session)


@pytest.fixture
def user_repository_mock() -> UserRepositoryMock:
    """Фикстура мока UserRepository."""
    return UserRepositoryMock()


@pytest.fixture
def user_security_settings_repository(mock_db_session: AsyncMock) -> UserSecuritySettingsRepository:
    """Фикстура UserSecuritySettingsRepository."""
    return UserSecuritySettingsRepository(mock_db_session)


@pytest.fixture
def audit_log_repository(mock_db_session: AsyncMock) -> AuditLogRepository:
    """Фикстура AuditLogRepository."""
    return AuditLogRepository(mock_db_session)


@pytest.fixture
def audit_log_repository_mock() -> AuditLogRepositoryMock:
    """Фикстура мока AuditLogRepository."""
    return AuditLogRepositoryMock()


@pytest.fixture
def jwk_key_repository(mock_db_session: AsyncMock) -> JWKKeyRepository:
    """Фикстура JWKKeyRepository."""
    return JWKKeyRepository(mock_db_session)


@pytest.fixture
def jwk_key_repository_mock() -> JWKKeyRepositoryMock:
    """Фикстура мока JWKKeyRepository."""
    return JWKKeyRepositoryMock()


@pytest.fixture
def password_reset_token_repository(mock_db_session: AsyncMock) -> PasswordResetTokenRepository:
    """Фикстура PasswordResetTokenRepository."""
    return PasswordResetTokenRepository(mock_db_session)


@pytest.fixture
def oauth_state_repository(mock_db_session: AsyncMock) -> OAuthStateRepository:
    """Фикстура OAuthStateRepository."""
    return OAuthStateRepository(mock_db_session)


@pytest.fixture
def refresh_token_repository(mock_db_session: AsyncMock) -> RefreshTokenRepository:
    """Фикстура RefreshTokenRepository."""
    return RefreshTokenRepository(mock_db_session)


@pytest.fixture
def refresh_token_repository_mock() -> RefreshTokenRepositoryMock:
    """Фикстура мока RefreshTokenRepository."""
    return RefreshTokenRepositoryMock()


# ==================== HELPER ФУНКЦИИ ДЛЯ ТЕСТОВ ====================

def setup_user_repository_with_users(
    repository: UserRepositoryMock,
    users: list[User],
) -> None:
    """Настройка мока UserRepository с пользователями."""
    for user in users:
        repository.add_user(user)


def setup_refresh_token_repository_with_tokens(
    repository: RefreshTokenRepositoryMock,
    tokens: list[RefreshToken],
) -> None:
    """Настройка мока RefreshTokenRepository с токенами."""
    for token in tokens:
        repository.add_token(token)


def setup_jwk_repository_with_keys(
    repository: JWKKeyRepositoryMock,
    keys: list[JWKKey],
) -> None:
    """Настройка мока JWKKeyRepository с ключами."""
    for key in keys:
        repository.add_key(key)


def setup_audit_log_repository_with_logs(
    repository: AuditLogRepositoryMock,
    logs: list[AuditLog],
) -> None:
    """Настройка мока AuditLogRepository с логами."""
    for log in logs:
        repository.add_log(log)


async def get_user_from_repository(
    repository: UserRepository,
    user_id: UUID,
) -> User | None:
    """Получение пользователя из репозитория."""
    return await repository.get_by_id(user_id)


async def cleanup_repository_mocks(
    repositories: list[Any],
) -> None:
    """Очистка всех мок репозиториев."""
    for repo in repositories:
        if hasattr(repo, 'users'):
            repo.users.clear()
        if hasattr(repo, 'tokens'):
            repo.tokens.clear()
        if hasattr(repo, 'keys'):
            repo.keys.clear()
        if hasattr(repo, 'logs'):
            repo.logs.clear()