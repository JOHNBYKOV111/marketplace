"""
Репозиторий для работы с JWK ключами в базе данных.

Обеспечивает:
- CRUD операции с JWK ключами
- Поиск по kid
- Получение активных/истекших ключей
- Активацию/деактивацию ключей
- Удаление истекших ключей
- Подсчёт метрик (active, expired, total)

Связанные модули:
- app.models.jwk_key - модель JWKKey
- app.services.jwk_service - бизнес-логика JWK
"""

from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from sqlalchemy import select, update, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.jwk_key import JWKKey
from app.core.logging import get_logger

logger = get_logger(__name__)


class JWKKeyRepository:
    """
    Репозиторий для работы с JWK ключами.

    Предоставляет методы для управления криптографическими ключами
    в базе данных: создание, поиск, активация/деактивация, удаление.
    """

    def __init__(self, session: AsyncSession):
        """
        Инициализация репозитория.

        Args:
            session: Асинхронная сессия SQLAlchemy
        """
        self.session = session

    # ==================== CREATE ====================

    async def create(self, key: JWKKey) -> JWKKey:
        """
        Создание нового JWK ключа.

        Args:
            key: Объект JWKKey для создания

        Returns:
            JWKKey: Созданный ключ с присвоенным ID
        """
        self.session.add(key)
        await self.session.flush()
        logger.debug(f"Created JWK key: {key.kid}")
        return key

    # ==================== READ ====================

    async def get_by_kid(self, kid: str) -> Optional[JWKKey]:
        """
        Получение ключа по Key ID.

        Args:
            kid: Key ID (уникальный идентификатор ключа)

        Returns:
            Optional[JWKKey]: Найденный ключ или None
        """
        stmt = select(JWKKey).where(JWKKey.kid == kid)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_id(self, key_id: UUID) -> Optional[JWKKey]:
        """
        Получение ключа по ID.

        Args:
            key_id: UUID ключа

        Returns:
            Optional[JWKKey]: Найденный ключ или None
        """
        stmt = select(JWKKey).where(JWKKey.id == key_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active_keys(self) -> List[JWKKey]:
        """
        Получение списка активных ключей.

        Активный ключ: is_active=True И expires_at > now ИЛИ expires_at IS NULL.

        Returns:
            List[JWKKey]: Список активных ключей, отсортированный по убыванию created_at
        """
        now = datetime.now(timezone.utc)
        stmt = (
            select(JWKKey)
            .where(
                JWKKey.is_active == True,
                (JWKKey.expires_at > now) | (JWKKey.expires_at.is_(None)),
            )
            .order_by(JWKKey.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_keys_for_verification(self) -> List[JWKKey]:
        """
        Получение ключей для верификации JWT.

        Возвращает все активные ключи, которые могут использоваться
        для проверки подписи JWT токенов.

        Returns:
            List[JWKKey]: Список ключей для верификации
        """
        return await self.get_active_keys()

    async def get_all_keys(self) -> List[JWKKey]:
        """
        Получение всех ключей (включая неактивные и истекшие).

        Returns:
            List[JWKKey]: Список всех ключей, отсортированный по убыванию created_at
        """
        stmt = select(JWKKey).order_by(JWKKey.created_at.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    # ==================== UPDATE ====================

    async def update(self, key_id: UUID, **kwargs) -> None:
        """
        Обновление полей ключа.

        Args:
            key_id: UUID ключа
            **kwargs: Поля для обновления (algorithm, key_type, is_active, и т.д.)
        """
        stmt = update(JWKKey).where(JWKKey.id == key_id).values(**kwargs)
        await self.session.execute(stmt)
        await self.session.flush()
        logger.debug(f"Updated JWK key {key_id}: {list(kwargs.keys())}")

    async def activate_key(self, kid: str) -> bool:
        """
        Активация ключа по kid.

        Устанавливает is_active=True и обновляет activated_at.
        Не трогает expires_at — срок действия ключа определяется этим полем.
        is_expired является вычисляемым свойством модели, а не колонкой БД.

        Args:
            kid: Key ID ключа для активации

        Returns:
            bool: True если ключ найден и активирован, False если не найден
        """
        key = await self.get_by_kid(kid)
        if not key:
            return False

        now = datetime.now(timezone.utc)
        values = {
            "is_active": True,
            "activated_at": now,
            "updated_at": now,
        }

        stmt = update(JWKKey).where(JWKKey.kid == kid).values(**values)
        await self.session.execute(stmt)
        await self.session.flush()

        logger.info(f"Activated JWK key: {kid}")
        return True

    async def deactivate_key(self, kid: str) -> bool:
        """
        Деактивация ключа по kid.

        Устанавливает is_active=False.
        Не трогает expires_at — ключ может быть деактивирован досрочно,
        но срок его действия определяется полем expires_at.
        is_expired является вычисляемым свойством модели, а не колонкой БД.

        Args:
            kid: Key ID ключа для деактивации

        Returns:
            bool: True если ключ найден и деактивирован, False если не найден
        """
        key = await self.get_by_kid(kid)
        if not key:
            return False

        now = datetime.now(timezone.utc)
        values = {
            "is_active": False,
            "updated_at": now,
        }

        stmt = update(JWKKey).where(JWKKey.kid == kid).values(**values)
        await self.session.execute(stmt)
        await self.session.flush()

        logger.info(f"Deactivated JWK key: {kid}")
        return True

    # ==================== DELETE ====================

    async def delete(self, key_id: UUID) -> bool:
        """
        Удаление ключа по ID.

        Args:
            key_id: UUID ключа

        Returns:
            bool: True если ключ удалён, False если не найден
        """
        stmt = delete(JWKKey).where(JWKKey.id == key_id)
        result = await self.session.execute(stmt)
        await self.session.flush()

        deleted = result.rowcount > 0
        if deleted:
            logger.info(f"Deleted JWK key: {key_id}")
        return deleted

    async def delete_expired_keys(self) -> int:
        """
        Удаление всех истекших ключей.

        Истекший ключ: expires_at < now И is_active = False.

        Returns:
            int: Количество удалённых ключей
        """
        now = datetime.now(timezone.utc)
        stmt = delete(JWKKey).where(
            JWKKey.expires_at < now,
            JWKKey.is_active == False,
        )
        result = await self.session.execute(stmt)
        await self.session.flush()

        deleted_count = result.rowcount
        logger.info(f"Deleted {deleted_count} expired JWK keys")
        return deleted_count

    # ==================== COUNT ====================

    async def count_active_keys(self) -> int:
        """
        Подсчёт активных ключей.

        Returns:
            int: Количество активных ключей
        """
        now = datetime.now(timezone.utc)
        stmt = select(func.count()).where(
            JWKKey.is_active == True,
            (JWKKey.expires_at > now) | (JWKKey.expires_at.is_(None)),
        )
        result = await self.session.execute(stmt)
        return result.scalar() or 0

    async def count_expired_keys(self) -> int:
        """
        Подсчёт истекших ключей.

        Returns:
            int: Количество истекших ключей
        """
        now = datetime.now(timezone.utc)
        stmt = select(func.count()).where(
            JWKKey.expires_at < now,
            JWKKey.is_active == False,
        )
        result = await self.session.execute(stmt)
        return result.scalar() or 0

    async def count_total_keys(self) -> int:
        """
        Подсчёт всех ключей.

        Returns:
            int: Общее количество ключей
        """
        stmt = select(func.count()).select_from(JWKKey)
        result = await self.session.execute(stmt)
        return result.scalar() or 0