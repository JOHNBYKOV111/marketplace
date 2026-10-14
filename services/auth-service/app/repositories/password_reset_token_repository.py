"""
Репозиторий для работы с токенами сброса пароля.

Обеспечивает:
- CRUD операции для токенов сброса пароля
- Поиск по хэшу токена
- Поиск по user_id
- Удаление просроченных токенов
- Удаление всех токенов пользователя
- Атомарные операции с транзакциями
- Полную совместимость с SQLAlchemy 2.0 и asyncpg

Связанные модули:
- app.models.password_reset_token - модель PasswordResetToken
- app.services.password_reset_service - бизнес-логика сброса пароля
- app.routers.auth - эндпоинты сброса пароля
"""

from datetime import datetime, timezone
from typing import Optional, List
from uuid import UUID

from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.password_reset_token import PasswordResetToken
from app.repositories.base import BaseRepository


class PasswordResetTokenRepository(BaseRepository[PasswordResetToken]):
    """
    Репозиторий для управления токенами сброса пароля в БД.

    Наследует базовые CRUD операции от BaseRepository.
    Добавляет специфические методы для работы с токенами сброса пароля.

    Attributes:
        model: Класс модели PasswordResetToken
    """

    def __init__(self, session: AsyncSession) -> None:
        """
        Инициализация репозитория.

        Args:
            session: Асинхронная сессия SQLAlchemy
        """
        super().__init__(PasswordResetToken, session)
        self._session = session

    # ==================== ОСНОВНЫЕ МЕТОДЫ ====================

    async def create(self, token: PasswordResetToken) -> PasswordResetToken:
        """
        Создание нового токена сброса пароля.

        Args:
            token: Объект PasswordResetToken для сохранения

        Returns:
            PasswordResetToken: Созданный токен с заполненным id

        Raises:
            IntegrityError: Если token_hash уже существует
        """
        self._session.add(token)
        await self._session.flush()
        await self._session.refresh(token)
        return token

    async def get_by_token_hash(self, token_hash: str) -> Optional[PasswordResetToken]:
        """
        Получение токена по хэшу.

        Args:
            token_hash: Хэш токена

        Returns:
            Optional[PasswordResetToken]: Найденный токен или None
        """
        stmt = select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_user_id(self, user_id: UUID) -> Optional[PasswordResetToken]:
        """
        Получение первого попавшегося токена пользователя.

        Используется для проверки наличия активного токена у пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            Optional[PasswordResetToken]: Найденный токен или None
        """
        stmt = (
            select(PasswordResetToken)
            .where(
                and_(
                    PasswordResetToken.user_id == user_id,
                    PasswordResetToken.expires_at > datetime.now(timezone.utc),
                    PasswordResetToken.used_at.is_(None),
                )
            )
            .order_by(PasswordResetToken.created_at.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_all_by_user_id(self, user_id: UUID) -> List[PasswordResetToken]:
        """
        Получение всех токенов пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            List[PasswordResetToken]: Список всех токенов пользователя
        """
        stmt = (
            select(PasswordResetToken)
            .where(PasswordResetToken.user_id == user_id)
            .order_by(PasswordResetToken.created_at.desc())
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def get_active_by_user_id(self, user_id: UUID) -> List[PasswordResetToken]:
        """
        Получение всех активных токенов пользователя.

        Активным считается токен, у которого:
        - expires_at > now
        - used_at is None

        Args:
            user_id: ID пользователя

        Returns:
            List[PasswordResetToken]: Список активных токенов
        """
        now = datetime.now(timezone.utc)
        stmt = (
            select(PasswordResetToken)
            .where(
                and_(
                    PasswordResetToken.user_id == user_id,
                    PasswordResetToken.expires_at > now,
                    PasswordResetToken.used_at.is_(None),
                )
            )
            .order_by(PasswordResetToken.created_at.desc())
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()

    # ==================== ПРОВЕРКИ ====================

    async def exists(self, token_hash: str) -> bool:
        """
        Проверка существования токена по хэшу.

        Args:
            token_hash: Хэш токена

        Returns:
            bool: True если токен существует
        """
        stmt = select(PasswordResetToken.id).where(PasswordResetToken.token_hash == token_hash).limit(1)
        result = await self._session.execute(stmt)
        return result.scalar() is not None

    async def is_valid(self, token_hash: str) -> bool:
        """
        Проверка, действителен ли токен.

        Args:
            token_hash: Хэш токена

        Returns:
            bool: True если токен существует, не истек и не использован
        """
        token = await self.get_by_token_hash(token_hash)
        if token is None:
            return False
        return token.is_valid()

    # ==================== УДАЛЕНИЕ ====================

    async def delete_by_token_hash(self, token_hash: str) -> int:
        """
        Удаление токена по хэшу.

        Args:
            token_hash: Хэш токена

        Returns:
            int: Количество удаленных записей (0 или 1)
        """
        stmt = delete(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def delete_expired(self) -> int:
        """
        Удаление всех истекших токенов.

        Returns:
            int: Количество удаленных записей
        """
        now = datetime.now(timezone.utc)
        stmt = delete(PasswordResetToken).where(PasswordResetToken.expires_at < now)
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def delete_by_user_id(self, user_id: UUID) -> int:
        """
        Удаление всех токенов пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            int: Количество удаленных записей
        """
        stmt = delete(PasswordResetToken).where(PasswordResetToken.user_id == user_id)
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def delete_expired_by_user(self, user_id: UUID) -> int:
        """
        Удаление истекших токенов конкретного пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            int: Количество удаленных записей
        """
        now = datetime.now(timezone.utc)
        stmt = delete(PasswordResetToken).where(
            and_(
                PasswordResetToken.user_id == user_id,
                PasswordResetToken.expires_at < now,
            )
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def delete_used(self) -> int:
        """
        Удаление всех использованных токенов.

        Returns:
            int: Количество удаленных записей
        """
        stmt = delete(PasswordResetToken).where(PasswordResetToken.used_at.is_not(None))
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def delete_used_by_user(self, user_id: UUID) -> int:
        """
        Удаление использованных токенов конкретного пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            int: Количество удаленных записей
        """
        stmt = delete(PasswordResetToken).where(
            and_(
                PasswordResetToken.user_id == user_id,
                PasswordResetToken.used_at.is_not(None),
            )
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    # ==================== ОБНОВЛЕНИЕ ====================

    async def mark_as_used(self, token_hash: str) -> Optional[PasswordResetToken]:
        """
        Отметить токен как использованный.

        Args:
            token_hash: Хэш токена

        Returns:
            Optional[PasswordResetToken]: Обновленный токен или None
        """
        now = datetime.now(timezone.utc)
        stmt = (
            update(PasswordResetToken)
            .where(PasswordResetToken.token_hash == token_hash)
            .values(
                used_at=now,
                updated_at=now,
            )
            .returning(PasswordResetToken)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.scalar_one_or_none()

    async def extend_expiry(
        self,
        token_hash: str,
        additional_seconds: int = 3600,
    ) -> Optional[PasswordResetToken]:
        """
        Продление срока действия токена.

        Args:
            token_hash: Хэш токена
            additional_seconds: Количество секунд для продления (по умолчанию 3600)

        Returns:
            Optional[PasswordResetToken]: Обновленный токен или None
        """
        now = datetime.now(timezone.utc)
        stmt = (
            update(PasswordResetToken)
            .where(
                and_(
                    PasswordResetToken.token_hash == token_hash,
                    PasswordResetToken.used_at.is_(None),
                )
            )
            .values(
                expires_at=now + timedelta(seconds=additional_seconds),
                updated_at=now,
            )
            .returning(PasswordResetToken)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.scalar_one_or_none()

    # ==================== МЕТРИКИ ====================

    async def count_active(self) -> int:
        """
        Подсчет активных токенов.

        Returns:
            int: Количество активных токенов
        """
        now = datetime.now(timezone.utc)
        stmt = (
            select(func.count())
            .select_from(PasswordResetToken)
            .where(
                and_(
                    PasswordResetToken.expires_at > now,
                    PasswordResetToken.used_at.is_(None),
                )
            )
        )
        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def count_expired(self) -> int:
        """
        Подсчет истекших токенов.

        Returns:
            int: Количество истекших токенов
        """
        now = datetime.now(timezone.utc)
        stmt = (
            select(func.count())
            .select_from(PasswordResetToken)
            .where(PasswordResetToken.expires_at < now)
        )
        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def count_used(self) -> int:
        """
        Подсчет использованных токенов.

        Returns:
            int: Количество использованных токенов
        """
        stmt = (
            select(func.count())
            .select_from(PasswordResetToken)
            .where(PasswordResetToken.used_at.is_not(None))
        )
        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def count_by_user(self, user_id: UUID) -> int:
        """
        Подсчет всех токенов пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            int: Количество токенов пользователя
        """
        stmt = (
            select(func.count())
            .select_from(PasswordResetToken)
            .where(PasswordResetToken.user_id == user_id)
        )
        result = await self._session.execute(stmt)
        return result.scalar() or 0

    # ==================== ПАРТИРОВАННОЕ УДАЛЕНИЕ ====================

    async def delete_expired_batch(self, batch_size: int = 1000) -> int:
        """
        Пакетное удаление истекших токенов.

        Args:
            batch_size: Размер пакета

        Returns:
            int: Количество удаленных записей
        """
        now = datetime.now(timezone.utc)
        total_deleted = 0

        while True:
            stmt = (
                delete(PasswordResetToken)
                .where(PasswordResetToken.expires_at < now)
                .limit(batch_size)
            )
            result = await self._session.execute(stmt)
            await self._session.flush()
            deleted = result.rowcount
            total_deleted += deleted

            if deleted < batch_size:
                break

        return total_deleted

    # ==================== ОЧИСТКА ====================

    async def cleanup_old_used_tokens(self, days: int = 7) -> int:
        """
        Очистка старых использованных токенов старше N дней.

        Args:
            days: Количество дней

        Returns:
            int: Количество удаленных записей
        """
        threshold = datetime.now(timezone.utc) - timedelta(days=days)
        stmt = delete(PasswordResetToken).where(
            and_(
                PasswordResetToken.used_at.is_not(None),
                PasswordResetToken.used_at < threshold,
            )
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount