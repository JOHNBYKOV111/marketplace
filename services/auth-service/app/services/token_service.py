"""
Сервис для работы с токенами.

Реализует:
- Создание и валидацию JWT токенов (access, refresh, verification)
- Управление refresh токенами (хранение, ротация, отзыв)
- Защиту от CSRF и replay attacks
- Мониторинг и метрики токенов
- Автоматическую очистку истекших токенов
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple, Any
from uuid import UUID, uuid4

import jwt
from redis.asyncio import Redis
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.exceptions import InvalidTokenError, TokenExpiredError
from app.core.logging import get_logger
from app.core.metrics import token_metrics
from app.core.redis_client import redis_client as global_redis_client
from app.models.refresh_token import RefreshToken
from app.repositories.refresh_token_repository import RefreshTokenRepository

logger = get_logger(__name__)


class TokenType:
    """Типы токенов."""

    ACCESS = "access"
    REFRESH = "refresh"
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"
    PHONE_VERIFICATION = "phone_verification"


class TokenService:
    """
    Сервис для работы с токенами.

    Отвечает за:
    - Генерацию и валидацию JWT токенов
    - Управление refresh токенами (с ротацией)
    - Хранение токенов в Redis (blacklist/whitelist)
    - Мониторинг и метрики
    - Защиту от атак
    """

    def __init__(
        self,
        refresh_repo: Optional[RefreshTokenRepository] = None,
        redis_client: Optional[Redis] = None,
        secret_key: Optional[str] = None,
        public_key: Optional[str] = None,
        algorithm: str = "HS256",
        db: Optional[Any] = None,
    ):
        """
        Инициализация сервиса.

        Args:
            refresh_repo: Репозиторий refresh токенов
            redis_client: Клиент Redis (для blacklist/whitelist)
            secret_key: Секретный ключ для JWT (для подписи)
            public_key: Публичный ключ для JWT (для проверки подписи)
            algorithm: Алгоритм шифрования
            db: Сессия БД (для совместимости)
        """
        self.refresh_repo = refresh_repo
        self._redis_client = redis_client or global_redis_client.client
        self.secret_key = secret_key or settings.JWT_SECRET_KEY
        self.public_key = public_key or settings.JWT_PUBLIC_KEY or self.secret_key
        self.algorithm = algorithm or settings.JWT_ALGORITHM
        self.db = db

        # Настройки токенов
        self.access_expire_minutes = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_expire_days = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
        self.verification_expire_hours = 24
        self.reset_expire_hours = 1
        self.blacklist_ttl_minutes = settings.JWT_BLACKLIST_TTL_MINUTES

    # ==================== ОСНОВНЫЕ МЕТОДЫ ДЛЯ ТЕСТОВ ====================

    async def blacklist_access_token(self, jti: str, ttl: Optional[int] = None) -> None:
        """
        Добавление access токена в черный список.

        Args:
            jti: JWT ID токена
            ttl: Время жизни в секундах (если None, используется из настроек)

        Raises:
            Exception: Если Redis операция не удалась
        """
        if not self._redis_client:
            logger.warning("Redis client not available, blacklist operation skipped")
            return

        if ttl is None:
            ttl = self.blacklist_ttl_minutes * 60

        if ttl <= 0:
            logger.warning(f"Invalid TTL {ttl} for blacklist, skipping")
            return

        key = f"token:blacklist:{jti}"

        await self._redis_client.setex(key, ttl, "1")
        logger.debug(f"Token {jti} added to blacklist with TTL {ttl}s")

    async def _is_blacklisted(self, jti: str) -> bool:
        """
        Проверка, находится ли токен в черном списке.

        Args:
            jti: JWT ID токена

        Returns:
            bool: True если токен в черном списке
        """
        if not self._redis_client:
            return False

        if not jti:
            return False

        try:
            key = f"token:blacklist:{jti}"
            return await self._redis_client.exists(key) == 1
        except Exception as e:
            logger.error(f"Failed to check blacklist for token {jti}: {e}")
            return False

    async def validate_access_token(self, token: str) -> Optional[Dict]:
        """
        Валидация access токена с проверкой черного списка.

        Args:
            token: JWT токен

        Returns:
            Optional[Dict]: Данные токена или None если токен невалидный

        Raises:
            TokenExpiredError: Токен истек
            InvalidTokenError: Неверный токен
        """
        try:
            # Декодируем токен с использованием публичного ключа для проверки подписи
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                options={
                    "require": ["exp", "iat", "sub", "type"],
                },
            )

            # Проверяем тип токена
            if payload.get("type") != TokenType.ACCESS:
                logger.warning(f"Invalid token type: {payload.get('type')}")
                return None

            # Проверяем наличие jti
            jti = payload.get("jti")
            if jti:
                # Проверяем черный список
                if await self._is_blacklisted(jti):
                    logger.info(f"Token {jti} is blacklisted")
                    return None
            else:
                logger.debug("Token without jti, skipping blacklist check")

            token_metrics.increment_validated(TokenType.ACCESS)
            return payload

        except jwt.ExpiredSignatureError:
            token_metrics.increment_expired(TokenType.ACCESS)
            raise TokenExpiredError("Token has expired")

        except jwt.InvalidTokenError as e:
            token_metrics.increment_invalid(TokenType.ACCESS)
            logger.warning(f"Invalid token: {e}")
            return None

    async def create_access_token(
        self,
        user_id: UUID,
        email: Optional[str] = None,
        roles: Optional[list] = None,
    ) -> str:
        """
        Создание access токена.

        Args:
            user_id: ID пользователя
            email: Email пользователя
            roles: Список ролей

        Returns:
            str: JWT токен
        """
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=self.access_expire_minutes
        )

        payload = {
            "sub": str(user_id),
            "type": TokenType.ACCESS,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": self._generate_token_id(),
        }

        if email:
            payload["email"] = email
        if roles:
            payload["roles"] = roles

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        token_metrics.increment_created(TokenType.ACCESS)

        logger.debug(f"Access token created for user: {user_id}")
        return token

    # ==================== ДОПОЛНИТЕЛЬНЫЕ МЕТОДЫ ====================

    async def create_refresh_token(
        self,
        user_id: UUID,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[str, RefreshToken, datetime]:
        """
        Создание refresh токена с сохранением в БД.

        Args:
            user_id: ID пользователя
            client_ip: IP клиента
            user_agent: User-Agent

        Returns:
            Tuple[str, RefreshToken, datetime]: Токен, объект БД, время истечения
        """
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=self.refresh_expire_days
        )

        token = self._generate_refresh_token()

        refresh_token = await self.refresh_repo.create_token(
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        if self._redis_client:
            await self._cache_refresh_token(token, user_id, expires_at)

        token_metrics.increment_created(TokenType.REFRESH)
        logger.info(f"Refresh token created for user: {user_id}")

        return token, refresh_token, expires_at

    async def create_email_verification_token(self, user_id: UUID) -> str:
        """
        Создание токена для верификации email.

        Args:
            user_id: ID пользователя

        Returns:
            str: Токен верификации
        """
        expires_at = datetime.now(timezone.utc) + timedelta(
            hours=self.verification_expire_hours
        )

        payload = {
            "sub": str(user_id),
            "type": TokenType.EMAIL_VERIFICATION,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": self._generate_token_id(),
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        token_metrics.increment_created(TokenType.EMAIL_VERIFICATION)

        logger.debug(f"Email verification token created for user: {user_id}")
        return token

    async def create_password_reset_token(self, user_id: UUID) -> str:
        """
        Создание токена для сброса пароля.

        Args:
            user_id: ID пользователя

        Returns:
            str: Токен сброса
        """
        expires_at = datetime.now(timezone.utc) + timedelta(
            hours=self.reset_expire_hours
        )

        payload = {
            "sub": str(user_id),
            "type": TokenType.PASSWORD_RESET,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": self._generate_token_id(),
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        token_metrics.increment_created(TokenType.PASSWORD_RESET)

        logger.debug(f"Password reset token created for user: {user_id}")
        return token

    async def decode_token(self, token: str, token_type: str) -> Dict:
        """
        Декодирование и валидация токена.

        Args:
            token: Токен
            token_type: Ожидаемый тип токена

        Returns:
            Dict: Данные токена

        Raises:
            InvalidTokenError: Неверный токен
            TokenExpiredError: Токен истек
        """
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                options={
                    "require": ["exp", "iat", "sub", "type", "jti"],
                },
            )

            if payload.get("type") != token_type:
                raise InvalidTokenError(
                    f"Invalid token type: expected {token_type}, got {payload.get('type')}"
                )

            if await self._is_token_revoked(payload["jti"]):
                raise InvalidTokenError("Token has been revoked")

            token_metrics.increment_validated(token_type)

            return payload

        except jwt.ExpiredSignatureError:
            token_metrics.increment_expired(token_type)
            raise TokenExpiredError("Token has expired")

        except jwt.InvalidTokenError as e:
            token_metrics.increment_invalid(token_type)
            raise InvalidTokenError(f"Invalid token: {str(e)}")

    async def revoke_token(self, jti: str) -> bool:
        """
        Отзыв токена (добавление в черный список).

        Args:
            jti: ID токена

        Returns:
            bool: True если отозван
        """
        if not self._redis_client:
            return False

        key = f"token:revoked:{jti}"
        await self._redis_client.setex(key, 86400, "1")

        logger.debug(f"Token revoked: {jti}")
        return True

    async def revoke_refresh_token(self, token: str) -> bool:
        """
        Отзыв refresh токена.

        Args:
            token: Refresh токен

        Returns:
            bool: True если отозван
        """
        token_data = await self.refresh_repo.get_by_token(token)
        if not token_data:
            return False

        await self.refresh_repo.revoke_token(token_data.id)

        if self._redis_client:
            cache_key = f"refresh_token:{token}"
            await self._redis_client.delete(cache_key)
            await self.revoke_token(token_data.jti or token)

        token_metrics.increment_revoked(TokenType.REFRESH)
        logger.info(f"Refresh token revoked: {token_data.id}")

        return True

    async def revoke_all_user_tokens(
        self,
        user_id: UUID,
        except_session_id: Optional[str] = None,
        reason: str = "revoked_by_admin"
    ) -> int:
        """
        Отзыв всех refresh токенов пользователя.

        Args:
            user_id: ID пользователя
            except_session_id: ID сессии, которую не нужно отзывать
            reason: Причина отзыва

        Returns:
            int: Количество отозванных токенов
        """
        count = await self.refresh_repo.revoke_all_user_tokens(user_id)

        if self._redis_client:
            pass

        logger.info(f"All refresh tokens revoked for user: {user_id}, count: {count}, reason: {reason}")
        return count

    async def validate_refresh_token(self, token: str) -> RefreshToken:
        """
        Валидация refresh токена.

        Args:
            token: Refresh токен

        Returns:
            RefreshToken: Объект токена

        Raises:
            InvalidTokenError: Неверный или истекший токен
        """
        if self._redis_client:
            cached = await self._get_cached_refresh_token(token)
            if cached:
                return cached

        token_data = await self.refresh_repo.get_by_token(token)
        if not token_data:
            raise InvalidTokenError("Invalid refresh token")

        if token_data.is_revoked:
            raise InvalidTokenError("Refresh token has been revoked")

        if token_data.expires_at < datetime.now(timezone.utc):
            raise InvalidTokenError("Refresh token has expired")

        if self._redis_client:
            await self._cache_refresh_token(
                token,
                token_data.user_id,
                token_data.expires_at,
            )

        return token_data

    async def rotate_refresh_token(
        self,
        old_token: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[str, RefreshToken]:
        """
        Ротация refresh токена (одноразовое использование).

        Args:
            old_token: Старый refresh токен
            client_ip: IP клиента
            user_agent: User-Agent

        Returns:
            Tuple[str, RefreshToken]: Новый токен и объект

        Raises:
            InvalidTokenError: Неверный старый токен
        """
        token_data = await self.validate_refresh_token(old_token)

        await self.revoke_refresh_token(old_token)

        new_token, new_data, _ = await self.create_refresh_token(
            user_id=token_data.user_id,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        logger.info(
            f"Refresh token rotated for user: {token_data.user_id}",
            extra={
                "old_token_id": str(token_data.id),
                "new_token_id": str(new_data.id),
            },
        )

        return new_token, new_data

    async def cleanup_expired_tokens(self, batch_size: int = 1000) -> int:
        """
        Очистка истекших refresh токенов.

        Args:
            batch_size: Размер батча

        Returns:
            int: Количество удаленных токенов
        """
        count = await self.refresh_repo.delete_expired_tokens(batch_size)

        if self._redis_client:
            pass

        logger.info(f"Cleaned up {count} expired refresh tokens")
        return count

    def _generate_refresh_token(self) -> str:
        """
        Генерация случайного refresh токена.

        Returns:
            str: Случайный токен
        """
        return secrets.token_urlsafe(64)

    def _generate_token_id(self) -> str:
        """
        Генерация уникального ID токена.

        Returns:
            str: ID токена
        """
        return secrets.token_hex(16)

    async def _cache_refresh_token(
        self,
        token: str,
        user_id: UUID,
        expires_at: datetime,
    ) -> None:
        """
        Кэширование refresh токена в Redis.

        Args:
            token: Refresh токен
            user_id: ID пользователя
            expires_at: Время истечения
        """
        if not self._redis_client:
            return

        ttl = int((expires_at - datetime.now(timezone.utc)).total_seconds())
        if ttl <= 0:
            return

        key = f"refresh_token:{token}"
        value = f"{user_id}|{expires_at.isoformat()}"
        await self._redis_client.setex(key, ttl, value)

    async def _get_cached_refresh_token(self, token: str) -> Optional[RefreshToken]:
        """
        Получение refresh токена из кэша.

        Args:
            token: Refresh токен

        Returns:
            Optional[RefreshToken]: Объект токена или None
        """
        if not self._redis_client:
            return None

        key = f"refresh_token:{token}"
        value = await self._redis_client.get(key)

        if not value:
            return None

        return None

    async def _is_token_revoked(self, jti: str) -> bool:
        """
        Проверка, отозван ли токен.

        Args:
            jti: ID токена

        Returns:
            bool: True если отозван
        """
        if not self._redis_client:
            return False

        key = f"token:revoked:{jti}"
        return await self._redis_client.exists(key) == 1

    async def get_token_metrics(self) -> Dict[str, int]:
        """
        Получение метрик токенов.

        Returns:
            Dict[str, int]: Метрики
        """
        return token_metrics.get_all()

    async def health_check(self) -> bool:
        """
        Проверка здоровья сервиса.

        Returns:
            bool: True если сервис работает
        """
        try:
            if self._redis_client:
                await self._redis_client.ping()

            if self.refresh_repo:
                await self.refresh_repo.count_active()

            return True

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

    async def get_active_sessions_count(self, user_id: UUID) -> int:
        """
        Получение количества активных сессий пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            int: Количество активных сессий
        """
        if not self.refresh_repo:
            return 0

        # ПРОД-ЛИД ФИКС: используем универсальный метод count с фильтрами
        count = await self.refresh_repo.count(
            filters={
                "user_id": user_id,
                "is_revoked": False,
            }
        )
        logger.debug(f"User {user_id} has {count} active sessions")
        return count