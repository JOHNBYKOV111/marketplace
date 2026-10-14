"""
Репозиторий для работы с OAuth 2.0 состояниями (state).

Обеспечивает:
- CRUD операции для OAuth состояний
- Поиск по state, user_id
- Удаление по state, user_id
- Очистку истекших состояний
- Атомарные операции с транзакциями
- Полную совместимость с SQLAlchemy 2.0 и asyncpg

Связанные модули:
- app.models.oauth_state - модель OAuthState
- app.services.oauth_service - бизнес-логика OAuth
- app.routers.oauth - эндпоинты OAuth
"""

from datetime import datetime, timezone
from typing import Optional, List, Tuple
from uuid import UUID

from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_state import OAuthState
from app.repositories.base import BaseRepository


class OAuthStateRepository(BaseRepository[OAuthState]):
    """
    Репозиторий для управления OAuth состояниями в БД.

    Наследует базовые CRUD операции от BaseRepository.
    Добавляет специфические методы для работы с OAuth 2.0 состояниями.

    Attributes:
        model: Класс модели OAuthState
    """

    def __init__(self, session: AsyncSession) -> None:
        """
        Инициализация репозитория.

        Args:
            session: Асинхронная сессия SQLAlchemy
        """
        super().__init__(OAuthState, session)
        self._session = session

    # ==================== ОСНОВНЫЕ МЕТОДЫ ====================

    async def create(self, oauth_state: OAuthState) -> OAuthState:
        """
        Создание нового OAuth состояния.

        Args:
            oauth_state: Объект OAuthState для сохранения

        Returns:
            OAuthState: Созданное состояние с заполненным id

        Raises:
            IntegrityError: Если state уже существует
        """
        self._session.add(oauth_state)
        await self._session.flush()
        await self._session.refresh(oauth_state)
        return oauth_state

    async def get_by_state(self, state: str) -> Optional[OAuthState]:
        """
        Получение OAuth состояния по state.

        Args:
            state: Уникальный идентификатор OAuth сессии

        Returns:
            Optional[OAuthState]: Найденное состояние или None
        """
        stmt = select(OAuthState).where(OAuthState.state == state)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_user_id(self, user_id: UUID) -> Optional[OAuthState]:
        """
        Получение OAuth состояния по user_id (для привязки аккаунтов).

        Args:
            user_id: ID пользователя

        Returns:
            Optional[OAuthState]: Найденное состояние или None
        """
        stmt = (
            select(OAuthState)
            .where(
                and_(
                    OAuthState.user_id == user_id,
                    OAuthState.is_linked == True,
                )
            )
            .order_by(OAuthState.created_at.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active_by_user_id(self, user_id: UUID) -> List[OAuthState]:
        """
        Получение всех активных состояний пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            List[OAuthState]: Список активных состояний
        """
        now = datetime.now(timezone.utc)
        stmt = (
            select(OAuthState)
            .where(
                and_(
                    OAuthState.user_id == user_id,
                    OAuthState.expires_at > now,
                )
            )
            .order_by(OAuthState.created_at.desc())
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def get_by_user_id_and_provider(
        self,
        user_id: UUID,
        provider: str,
    ) -> Optional[OAuthState]:
        """
        Получение OAuth состояния по user_id и провайдеру.

        Args:
            user_id: ID пользователя
            provider: Имя провайдера

        Returns:
            Optional[OAuthState]: Найденное состояние или None
        """
        stmt = (
            select(OAuthState)
            .where(
                and_(
                    OAuthState.user_id == user_id,
                    OAuthState.provider == provider,
                    OAuthState.is_linked == True,
                )
            )
            .order_by(OAuthState.created_at.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active_states(self) -> List[OAuthState]:
        """
        Получение всех активных состояний (не истекших).

        Returns:
            List[OAuthState]: Список активных состояний
        """
        now = datetime.now(timezone.utc)
        stmt = select(OAuthState).where(OAuthState.expires_at > now)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    # ==================== ПРОВЕРКИ ====================

    async def exists(self, state: str) -> bool:
        """
        Проверка существования OAuth состояния по state.

        Args:
            state: Уникальный идентификатор OAuth сессии

        Returns:
            bool: True если состояние существует
        """
        stmt = select(OAuthState.id).where(OAuthState.state == state).limit(1)
        result = await self._session.execute(stmt)
        return result.scalar() is not None

    async def is_valid(self, state: str) -> bool:
        """
        Проверка, действительно ли OAuth состояние (не истекло).

        Args:
            state: Уникальный идентификатор OAuth сессии

        Returns:
            bool: True если состояние существует и не истекло
        """
        oauth_state = await self.get_by_state(state)
        if oauth_state is None:
            return False
        return not oauth_state.is_expired()

    async def is_linked(self, state: str) -> bool:
        """
        Проверка, является ли состояние привязкой аккаунта.

        Args:
            state: Уникальный идентификатор OAuth сессии

        Returns:
            bool: True если состояние для привязки аккаунта
        """
        oauth_state = await self.get_by_state(state)
        if oauth_state is None:
            return False
        return oauth_state.is_linked

    # ==================== УДАЛЕНИЕ ====================

    async def delete_by_state(self, state: str) -> int:
        """
        Удаление OAuth состояния по state.

        Args:
            state: Уникальный идентификатор OAuth сессии

        Returns:
            int: Количество удаленных записей (0 или 1)
        """
        stmt = delete(OAuthState).where(OAuthState.state == state)
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def delete_by_user_id(self, user_id: UUID) -> int:
        """
        Удаление всех OAuth состояний пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            int: Количество удаленных записей
        """
        stmt = delete(OAuthState).where(OAuthState.user_id == user_id)
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def delete_expired(self) -> int:
        """
        Удаление всех истекших OAuth состояний.

        Returns:
            int: Количество удаленных записей
        """
        now = datetime.now(timezone.utc)
        stmt = delete(OAuthState).where(OAuthState.expires_at < now)
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def delete_expired_by_user(self, user_id: UUID) -> int:
        """
        Удаление истекших состояний конкретного пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            int: Количество удаленных записей
        """
        now = datetime.now(timezone.utc)
        stmt = delete(OAuthState).where(
            and_(
                OAuthState.user_id == user_id,
                OAuthState.expires_at < now,
            )
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def delete_by_provider(self, provider: str) -> int:
        """
        Удаление всех состояний для конкретного провайдера.

        Args:
            provider: Имя провайдера

        Returns:
            int: Количество удаленных записей
        """
        stmt = delete(OAuthState).where(OAuthState.provider == provider)
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    # ==================== ОБНОВЛЕНИЕ ====================

    async def extend_ttl(self, state: str, seconds: int = 600) -> Optional[OAuthState]:
        """
        Продление TTL для OAuth состояния.

        Args:
            state: Уникальный идентификатор OAuth сессии
            seconds: Количество секунд для продления (по умолчанию 600)

        Returns:
            Optional[OAuthState]: Обновленное состояние или None
        """
        now = datetime.now(timezone.utc)
        new_expires_at = now + timedelta(seconds=seconds)

        stmt = (
            update(OAuthState)
            .where(OAuthState.state == state)
            .values(
                expires_at=new_expires_at,
                updated_at=now,
            )
            .returning(OAuthState)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.scalar_one_or_none()

    async def mark_as_linked(self, state: str, user_id: UUID) -> Optional[OAuthState]:
        """
        Отметить состояние как привязанное к пользователю.

        Args:
            state: Уникальный идентификатор OAuth сессии
            user_id: ID пользователя

        Returns:
            Optional[OAuthState]: Обновленное состояние или None
        """
        now = datetime.now(timezone.utc)
        stmt = (
            update(OAuthState)
            .where(OAuthState.state == state)
            .values(
                user_id=user_id,
                is_linked=True,
                updated_at=now,
            )
            .returning(OAuthState)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.scalar_one_or_none()

    # ==================== МЕТРИКИ ====================

    async def count_active_states(self) -> int:
        """
        Подсчет активных состояний.

        Returns:
            int: Количество активных состояний
        """
        now = datetime.now(timezone.utc)
        stmt = (
            select(func.count())
            .select_from(OAuthState)
            .where(OAuthState.expires_at > now)
        )
        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def count_expired_states(self) -> int:
        """
        Подсчет истекших состояний.

        Returns:
            int: Количество истекших состояний
        """
        now = datetime.now(timezone.utc)
        stmt = (
            select(func.count())
            .select_from(OAuthState)
            .where(OAuthState.expires_at < now)
        )
        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def count_by_provider(self) -> dict:
        """
        Подсчет состояний по провайдерам.

        Returns:
            dict: Словарь {provider: count}
        """
        stmt = (
            select(OAuthState.provider, func.count())
            .group_by(OAuthState.provider)
        )
        result = await self._session.execute(stmt)
        return dict(result.all())

    # ==================== ПАРТИРОВАННОЕ УДАЛЕНИЕ ====================

    async def delete_expired_batch(self, batch_size: int = 1000) -> int:
        """
        Пакетное удаление истекших состояний.

        Args:
            batch_size: Размер пакета

        Returns:
            int: Количество удаленных записей
        """
        now = datetime.now(timezone.utc)
        total_deleted = 0

        while True:
            stmt = (
                delete(OAuthState)
                .where(OAuthState.expires_at < now)
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

    async def cleanup_old_states(self, days: int = 7) -> int:
        """
        Очистка старых состояний старше N дней.

        Args:
            days: Количество дней

        Returns:
            int: Количество удаленных записей
        """
        threshold = datetime.now(timezone.utc) - timedelta(days=days)
        stmt = delete(OAuthState).where(OAuthState.created_at < threshold)
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def cleanup_orphaned_states(self) -> int:
        """
        Очистка состояний без пользователя (orphaned).

        Returns:
            int: Количество удаленных записей
        """
        # Состояния с is_linked=True, но без user_id
        stmt = delete(OAuthState).where(
            and_(
                OAuthState.is_linked == True,
                OAuthState.user_id.is_(None),
            )
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount