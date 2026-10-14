"""
Сервис для работы с refresh токенами.

Обеспечивает:
- Создание и валидацию refresh токенов
- Ротацию токенов
- Управление сессиями пользователей
- Безопасный выход из системы
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple
from uuid import UUID, uuid4

from app.core.exceptions import (
    InvalidTokenError,
    TokenExpiredError,
    TokenRevokedError,
    UserNotFoundError,
)
from app.core.logging import get_logger
from app.models.refresh_token import RefreshToken
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository

logger = get_logger(__name__)


class RefreshTokenService:
    """
    Сервис для управления refresh токенами.

    Предоставляет бизнес-логику для работы с refresh токенами:
    - Создание токенов с привязкой к устройству
    - Валидация токенов (активность, срок действия, принадлежность)
    - Ротация токенов (обмен старого на новый)
    - Отзыв токенов (выход из системы)
    - Управление сессиями пользователя
    """

    def __init__(
        self,
        refresh_token_repository: RefreshTokenRepository,
        user_repository: UserRepository,
        default_expires_days: int = 30,
        max_sessions_per_user: int = 10,
    ):
        """
        Инициализация сервиса.

        Args:
            refresh_token_repository: Репозиторий refresh токенов
            user_repository: Репозиторий пользователей
            default_expires_days: Срок жизни токена по умолчанию (дни)
            max_sessions_per_user: Максимальное количество сессий на пользователя
        """
        self.refresh_token_repo = refresh_token_repository
        self.user_repository = user_repository
        self.default_expires_days = default_expires_days
        self.max_sessions_per_user = max_sessions_per_user

    async def create_refresh_token(
        self,
        user_id: UUID,
        device_id: Optional[str] = None,
        device_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        expires_days: Optional[int] = None,
    ) -> RefreshToken:
        """
        Создание нового refresh токена.

        Args:
            user_id: ID пользователя
            device_id: ID устройства
            device_name: Название устройства
            ip_address: IP адрес
            user_agent: User-Agent
            expires_days: Срок жизни в днях (если None, используется default)

        Returns:
            RefreshToken: Созданный токен

        Raises:
            UserNotFoundError: Если пользователь не найден
        """
        # Проверяем существование пользователя
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User not found: {user_id}")

        # Проверяем количество активных сессий
        active_sessions = await self.refresh_token_repo.get_active_by_user_id(user_id)
        if len(active_sessions) >= self.max_sessions_per_user:
            # Отзываем самый старый токен, чтобы освободить место
            oldest_session = sorted(active_sessions, key=lambda t: t.created_at)[0]
            await self.refresh_token_repo.revoke(oldest_session.token_id)
            logger.info(f"Revoked oldest session for user {user_id} due to limit")

        # Создаем токен через фабричный метод модели
        expires_days = expires_days or self.default_expires_days
        token = RefreshToken.create_token(
            user_id=user_id,
            expires_days=expires_days,
            device_id=device_id,
            device_name=device_name,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Сохраняем в БД
        created_token = await self.refresh_token_repo.create_from_object(token)
        await self.refresh_token_repo.session.commit()

        logger.info(
            f"Refresh token created for user {user_id}, "
            f"device: {device_name or 'unknown'}"
        )

        return created_token

    async def validate_refresh_token(
        self,
        token_id: str,
        user_id: Optional[UUID] = None,
    ) -> RefreshToken:
        """
        Валидация refresh токена.

        Args:
            token_id: ID токена
            user_id: ID пользователя (опционально, для проверки принадлежности)

        Returns:
            RefreshToken: Валидный токен

        Raises:
            InvalidTokenError: Если токен не найден
            TokenExpiredError: Если токен истек
            TokenRevokedError: Если токен отозван
            InvalidTokenError: Если токен не принадлежит пользователю
        """
        token = await self.refresh_token_repo.get_by_token_id(token_id)

        if not token:
            raise InvalidTokenError(f"Token not found: {token_id}")

        if token.is_expired:
            raise TokenExpiredError(f"Token expired: {token_id}")

        if token.is_revoked:
            raise TokenRevokedError(f"Token revoked: {token_id}")

        if user_id and token.user_id != user_id:
            raise InvalidTokenError(
                f"Token does not belong to user: {user_id}"
            )

        # Обновляем время последнего использования
        await self.refresh_token_repo.update_last_used(token_id)
        await self.refresh_token_repo.session.commit()

        return token

    async def rotate_refresh_token(
        self,
        old_token_id: str,
        user_id: UUID,
        device_id: Optional[str] = None,
        device_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[RefreshToken, RefreshToken]:
        """
        Ротация refresh токена (замена старого на новый).

        Args:
            old_token_id: ID старого токена
            user_id: ID пользователя
            device_id: ID устройства
            device_name: Название устройства
            ip_address: IP адрес
            user_agent: User-Agent

        Returns:
            Tuple[RefreshToken, RefreshToken]: (Новый токен, старый токен)

        Raises:
            InvalidTokenError: Если старый токен не найден
            TokenExpiredError: Если старый токен истек
            TokenRevokedError: Если старый токен отозван
        """
        # Валидируем старый токен
        old_token = await self.validate_refresh_token(old_token_id, user_id)

        # Отзываем старый токен
        await self.refresh_token_repo.revoke(old_token_id)

        # Создаем новый токен
        new_token = await self.create_refresh_token(
            user_id=user_id,
            device_id=device_id or old_token.device_id,
            device_name=device_name or old_token.device_name,
            ip_address=ip_address or old_token.ip_address,
            user_agent=user_agent or old_token.user_agent,
        )

        await self.refresh_token_repo.session.commit()

        logger.info(f"Refresh token rotated for user {user_id}")

        return new_token, old_token

    async def revoke_refresh_token(
        self,
        token_id: str,
        user_id: Optional[UUID] = None,
    ) -> None:
        """
        Отзыв refresh токена (выход из системы).

        Args:
            token_id: ID токена
            user_id: ID пользователя (опционально, для проверки принадлежности)

        Raises:
            InvalidTokenError: Если токен не найден
            TokenRevokedError: Если токен уже отозван
            InvalidTokenError: Если токен не принадлежит пользователю
        """
        token = await self.refresh_token_repo.get_by_token_id(token_id)

        if not token:
            raise InvalidTokenError(f"Token not found: {token_id}")

        if token.is_revoked:
            raise TokenRevokedError(f"Token already revoked: {token_id}")

        if user_id and token.user_id != user_id:
            raise InvalidTokenError(
                f"Token does not belong to user: {user_id}"
            )

        await self.refresh_token_repo.revoke(token_id)
        await self.refresh_token_repo.session.commit()

        logger.info(f"Refresh token revoked: {token_id}")

    async def revoke_all_user_tokens(
        self,
        user_id: UUID,
        except_token_id: Optional[str] = None,
    ) -> int:
        """
        Отзыв всех токенов пользователя (выход со всех устройств).

        Args:
            user_id: ID пользователя
            except_token_id: ID токена, который нужно исключить

        Returns:
            int: Количество отозванных токенов

        Raises:
            UserNotFoundError: Если пользователь не найден
        """
        # Проверяем существование пользователя
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User not found: {user_id}")

        revoked_count = await self.refresh_token_repo.revoke_all_by_user_id(
            user_id,
            except_token_id=except_token_id,
        )
        await self.refresh_token_repo.session.commit()

        logger.info(
            f"Revoked {revoked_count} tokens for user {user_id}, "
            f"except: {except_token_id}"
        )

        return revoked_count

    async def get_user_sessions(
        self,
        user_id: UUID,
        include_inactive: bool = False,
    ) -> List[RefreshToken]:
        """
        Получение всех сессий пользователя.

        Args:
            user_id: ID пользователя
            include_inactive: Включать ли неактивные сессии

        Returns:
            List[RefreshToken]: Список сессий
        """
        if include_inactive:
            tokens = await self.refresh_token_repo.get_all_by_user_id(user_id)
        else:
            tokens = await self.refresh_token_repo.get_active_by_user_id(user_id)

        return tokens

    async def cleanup_expired_tokens(self) -> int:
        """
        Очистка истекших токенов.

        Returns:
            int: Количество удаленных токенов
        """
        deleted_count = await self.refresh_token_repo.delete_expired()
        await self.refresh_token_repo.session.commit()

        if deleted_count > 0:
            logger.info(f"Deleted {deleted_count} expired tokens")

        return deleted_count

    async def is_token_active(self, token_id: str) -> bool:
        """
        Проверка активности токена.

        Args:
            token_id: ID токена

        Returns:
            bool: True если токен активен
        """
        return await self.refresh_token_repo.is_active(token_id)

    async def is_token_valid_for_user(
        self,
        token_id: str,
        user_id: UUID,
    ) -> bool:
        """
        Проверка принадлежности токена пользователю.

        Args:
            token_id: ID токена
            user_id: ID пользователя

        Returns:
            bool: True если токен принадлежит пользователю
        """
        token = await self.refresh_token_repo.get_by_token_id(token_id)
        if not token:
            return False
        return token.user_id == user_id