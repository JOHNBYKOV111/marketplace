"""
Сервис аутентификации.

Реализует бизнес-логику:
- Аутентификация пользователя (с поддержкой MFA)
- Генерация и валидация JWT токенов
- Управление refresh токенами (с ротацией)
- Верификация email и телефона
- Управление сессиями и паролями
"""

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
    AuthenticationError,
    InvalidTokenError,
    MFARequiredError,
    UserBlockedException,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    verify_password,
)
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository
from app.repositories.user_security_settings_repository import UserSecuritySettingsRepository
from app.services.totp_service import TOTPService

logger = get_logger(__name__)


class AuthResult:
    """Результат аутентификации."""

    def __init__(
        self,
        user: User,
        access_token: str,
        refresh_token: str,
        access_expires_in: int,
        refresh_expires_in: int,
    ):
        self.user = user
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.access_expires_in = access_expires_in
        self.refresh_expires_in = refresh_expires_in


class RefreshResult:
    """Результат обновления токенов."""

    def __init__(
        self,
        access_token: str,
        refresh_token: str,
        user_id: UUID,
        access_expires_in: int,
        refresh_expires_in: int,
    ):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.user_id = user_id
        self.access_expires_in = access_expires_in
        self.refresh_expires_in = refresh_expires_in


class AuthService:
    """
    Сервис аутентификации и управления пользователями.
    
    Фасад над UserRepository, RefreshTokenRepository и UserSecuritySettingsRepository.
    """

    def __init__(
        self,
        session: AsyncSession,
        user_repo: Optional[UserRepository] = None,
        refresh_repo: Optional[RefreshTokenRepository] = None,
        settings_repo: Optional[UserSecuritySettingsRepository] = None,
        totp_service: Optional[TOTPService] = None,
    ):
        self.session = session
        self.user_repo = user_repo or UserRepository(session)
        self.refresh_repo = refresh_repo or RefreshTokenRepository(session)
        self.settings_repo = settings_repo or UserSecuritySettingsRepository(session)
        self.totp_service = totp_service or TOTPService()

    # ==================== ОСНОВНАЯ АУТЕНТИФИКАЦИЯ ====================

    async def authenticate(
        self,
        email: str,
        password: str,
        totp_code: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuthResult:
        """Аутентификация пользователя по email и паролю."""
        email_hash = User.create_email_hash(email)
        user = await self.user_repo.get_by_email_hash(email_hash)

        if not user:
            logger.warning(f"Login attempt with non-existent email: {email}")
            raise AuthenticationError("Invalid email or password")

        if not user.is_active:
            logger.warning(f"Login attempt from blocked user: {user.id}")
            raise UserBlockedException("User account is blocked")

        try:
            is_valid = verify_password(password, user.password_hash)
        except Exception as exc:
            logger.error(f"Crypto error during password verification for user {user.id}: {str(exc)}")
            is_valid = False

        if not is_valid:
            logger.warning(f"Authentication failed: invalid password for user_id: {user.id}")
            raise AuthenticationError("Invalid email or password")

        settings_obj = await self.settings_repo.get_by_user_id(user.id)
        if settings_obj and settings_obj.totp_enabled:
            if not totp_code:
                logger.info(f"MFA required for user: {user.id}")
                raise MFARequiredError("MFA verification required")
            if not self.totp_service.verify(settings_obj.totp_secret, totp_code):
                logger.warning(f"Invalid MFA code for user: {user.id}")
                raise AuthenticationError("Invalid MFA code")

        access_token, access_expires = self._create_access_token(user)
        refresh_token_str, refresh_expires = await self._create_refresh_token(
            user.id, client_ip=client_ip, user_agent=user_agent,
        )

        await self.user_repo.update_last_login(user.id)
        logger.info(f"User logged in: {user.id}")

        return AuthResult(
            user=user,
            access_token=access_token,
            refresh_token=refresh_token_str,
            access_expires_in=int(access_expires.total_seconds()),
            refresh_expires_in=int(refresh_expires.total_seconds()),
        )

    async def refresh_tokens(
        self, refresh_token: str, client_ip: Optional[str] = None,
    ) -> RefreshResult:
        """Обновление access токена через refresh token с ротацией."""
        try:
            payload = decode_token(refresh_token, verify_type="refresh")
        except InvalidTokenError:
            raise InvalidTokenError("Invalid refresh token")

        jti = payload["jti"]
        token_data = await self.refresh_repo.get_by_token_id(jti)

        if not token_data:
            raise InvalidTokenError("Invalid refresh token")
        if token_data.expires_at < datetime.now(timezone.utc):
            await self.refresh_repo.revoke(token_data.token_id)
            raise InvalidTokenError("Refresh token expired")
        if token_data.is_revoked:
            raise InvalidTokenError("Refresh token revoked")

        user = await self.user_repo.get_by_id(token_data.user_id)
        if not user or not user.is_active:
            raise InvalidTokenError("User account is not active")

        await self.refresh_repo.revoke(token_data.token_id)

        access_token, access_expires = self._create_access_token(user)
        new_refresh_token, refresh_expires = await self._create_refresh_token(
            user.id, client_ip=client_ip, user_agent=token_data.user_agent,
        )

        logger.info(f"Tokens refreshed for user: {user.id}")
        return RefreshResult(
            access_token=access_token,
            refresh_token=new_refresh_token,
            user_id=user.id,
            access_expires_in=int(access_expires.total_seconds()),
            refresh_expires_in=int(refresh_expires.total_seconds()),
        )

    # ==================== УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ ====================

    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        return await self.user_repo.get_by_id(user_id)

    async def get_user_by_email(self, email: str) -> Optional[User]:
        email_hash = User.create_email_hash(email)
        return await self.user_repo.get_by_email_hash(email_hash)

    async def update_password(self, user_id: UUID, new_password_hash: str) -> None:
        await self.user_repo.update_password(user_id, new_password_hash)

    # ==================== УПРАВЛЕНИЕ СЕССИЯМИ ====================

    async def get_user_sessions(self, user_id: UUID) -> List[RefreshToken]:
        """Получение всех активных сессий пользователя."""
        return await self.refresh_repo.get_active_by_user_id(user_id)

    async def revoke_all_sessions(self, user_id: UUID, except_session_id: Optional[str] = None) -> int:
        """Отзыв всех сессий пользователя, кроме указанной."""
        count = await self.refresh_repo.revoke_all_by_user_id(user_id, except_token_id=except_session_id)
        logger.info(f"Revoked {count} sessions for user: {user_id}")
        return count

    async def revoke_refresh_token(self, token: str) -> bool:
        """Отзыв конкретного refresh токена."""
        try:
            payload = decode_token(token, verify_type="refresh")
        except InvalidTokenError:
            return False
        jti = payload["jti"]
        token_data = await self.refresh_repo.get_by_token_id(jti)
        if not token_data:
            return False
        await self.refresh_repo.revoke(token_data.token_id)
        logger.info(f"Refresh token revoked: {token_data.token_id}")
        return True

    # ==================== СОБЫТИЯ И ЛОГИРОВАНИЕ ====================

    async def publish_password_changed(self, user_id: UUID) -> None:
        logger.info(f"Password changed event published for user: {user_id}")

    async def log_password_reset_request(self, user_id: UUID) -> None:
        logger.info(f"Password reset requested for user: {user_id}")

    # ==================== ТОКЕНЫ (ВНУТРЕННИЕ) ====================

    def _create_access_token(self, user: User) -> Tuple[str, timedelta]:
        expires_delta = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        token = create_access_token(
            data={"sub": str(user.id), "is_superuser": user.is_superuser},
            expires_delta=expires_delta,
        )
        return token, expires_delta

    async def _create_refresh_token(
        self, user_id: UUID, client_ip: Optional[str] = None, user_agent: Optional[str] = None,
    ) -> Tuple[str, timedelta]:
        expires_delta = timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        token = create_refresh_token(data={"sub": str(user_id)}, expires_delta=expires_delta)
        payload = decode_token(token, verify_type="refresh")
        jti = payload["jti"]
        await self.refresh_repo.create(
            token_id=jti, user_id=user_id,
            ip_address=client_ip, user_agent=user_agent,
            expires_at=datetime.now(timezone.utc) + expires_delta,
        )
        return token, expires_delta