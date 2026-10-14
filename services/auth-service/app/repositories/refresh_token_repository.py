"""
Репозиторий для работы с refresh токенами.

Обеспечивает CRUD операции с refresh токенами.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional
from uuid import UUID, uuid4

from sqlalchemy import and_, delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.refresh_token import RefreshToken
from app.repositories.base import BaseRepository


class RefreshTokenRepository(BaseRepository[RefreshToken]):
    """
    Репозиторий для работы с refresh токенами.

    Предоставляет полный набор CRUD операций для управления refresh токенами.
    """

    def __init__(self, session: AsyncSession):
        """
        Инициализация репозитория.

        Args:
            session: Асинхронная сессия БД
        """
        super().__init__(RefreshToken, session)

    async def create(
        self,
        token_id: str,
        user_id: UUID,
        device_id: Optional[str] = None,
        device_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> RefreshToken:
        """
        Создание нового refresh токена.

        Args:
            token_id: ID токена (строка)
            user_id: ID пользователя
            device_id: ID устройства
            device_name: Название устройства
            ip_address: IP адрес
            user_agent: User-Agent
            expires_at: Время истечения (если None, то +30 дней)

        Returns:
            RefreshToken: Созданный токен
        """
        if expires_at is None:
            expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        refresh_token = RefreshToken(
            id=uuid4(),
            user_id=user_id,
            token_id=token_id,
            device_id=device_id,
            device_name=device_name,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            is_revoked=False,
            is_rotated=False,
        )

        self.session.add(refresh_token)
        await self.session.flush()
        return refresh_token

    async def create_from_object(self, token: RefreshToken) -> RefreshToken:
        """
        Создание токена из готового объекта.

        Args:
            token: Объект RefreshToken

        Returns:
            RefreshToken: Созданный токен
        """
        self.session.add(token)
        await self.session.flush()
        return token

    async def get_by_token_id(self, token_id: str) -> Optional[RefreshToken]:
        """
        Получение токена по token_id.

        Args:
            token_id: ID токена

        Returns:
            Optional[RefreshToken]: Найденный токен или None
        """
        stmt = select(RefreshToken).where(RefreshToken.token_id == token_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active_by_token_id(self, token_id: str) -> Optional[RefreshToken]:
        """
        Получение активного токена по token_id.

        Args:
            token_id: ID токена

        Returns:
            Optional[RefreshToken]: Активный токен или None
        """
        now = datetime.now(timezone.utc)
        stmt = select(RefreshToken).where(
            RefreshToken.token_id == token_id,
            RefreshToken.is_revoked == False,
            RefreshToken.expires_at > now,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active_by_user_id(self, user_id: UUID) -> List[RefreshToken]:
        """
        Получение всех активных токенов пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            List[RefreshToken]: Список активных токенов
        """
        now = datetime.now(timezone.utc)
        stmt = select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked == False,
            RefreshToken.expires_at > now,
        ).order_by(RefreshToken.created_at.desc())
        
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_all_by_user_id(self, user_id: UUID) -> List[RefreshToken]:
        """
        Получение всех токенов пользователя (включая неактивные).

        Args:
            user_id: ID пользователя

        Returns:
            List[RefreshToken]: Список всех токенов
        """
        stmt = select(RefreshToken).where(
            RefreshToken.user_id == user_id
        ).order_by(RefreshToken.created_at.desc())
        
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def revoke(self, token_id: str) -> None:
        """
        Отзыв токена.

        Args:
            token_id: ID токена
        """
        stmt = update(RefreshToken).where(
            RefreshToken.token_id == token_id,
            RefreshToken.is_revoked == False,
        ).values(
            is_revoked=True,
            revoked_at=datetime.now(timezone.utc),
        )
        await self.session.execute(stmt)

    async def revoke_all_by_user_id(
        self,
        user_id: UUID,
        except_token_id: Optional[str] = None,
    ) -> int:
        """
        Отзыв всех токенов пользователя.

        Args:
            user_id: ID пользователя
            except_token_id: ID токена, который нужно исключить

        Returns:
            int: Количество отозванных токенов
        """
        conditions = [
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked == False,
        ]
        if except_token_id:
            conditions.append(RefreshToken.token_id != except_token_id)

        stmt = update(RefreshToken).where(
            and_(*conditions)
        ).values(
            is_revoked=True,
            revoked_at=datetime.now(timezone.utc),
        )
        result = await self.session.execute(stmt)
        return result.rowcount

    async def update_last_used(
        self,
        token_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """
        Обновление метаданных токена.

        Args:
            token_id: ID токена
            ip_address: Новый IP адрес
            user_agent: Новый User-Agent
        """
        values = {"last_used_at": datetime.now(timezone.utc)}
        if ip_address is not None:
            values["ip_address"] = ip_address
        if user_agent is not None:
            values["user_agent"] = user_agent

        stmt = update(RefreshToken).where(
            RefreshToken.token_id == token_id
        ).values(**values)
        await self.session.execute(stmt)

    async def delete_expired(self) -> int:
        """
        Удаление просроченных токенов.

        Returns:
            int: Количество удаленных токенов
        """
        now = datetime.now(timezone.utc)
        stmt = delete(RefreshToken).where(RefreshToken.expires_at < now)
        result = await self.session.execute(stmt)
        return result.rowcount

    async def delete_by_token_id(self, token_id: str) -> int:
        """
        Полное удаление токена.

        Args:
            token_id: ID токена

        Returns:
            int: Количество удаленных записей (0 или 1)
        """
        stmt = delete(RefreshToken).where(RefreshToken.token_id == token_id)
        result = await self.session.execute(stmt)
        return result.rowcount

    async def is_active(self, token_id: str) -> bool:
        """
        Проверка активности токена.

        Args:
            token_id: ID токена

        Returns:
            bool: True если токен активен
        """
        token = await self.get_active_by_token_id(token_id)
        return token is not None

    async def exists(self, token_id: str) -> bool:
        """
        Проверка существования токена.

        Args:
            token_id: ID токена

        Returns:
            bool: True если токен существует
        """
        token = await self.get_by_token_id(token_id)
        return token is not None

    async def revoke_all_user_tokens(self, user_id: UUID) -> int:
        """
        Отзыв всех токенов пользователя (без исключений).

        Args:
            user_id: ID пользователя

        Returns:
            int: Количество отозванных токенов
        """
        return await self.revoke_all_by_user_id(user_id, except_token_id=None)

    async def count_by_user_id(self, user_id: UUID) -> int:
        """
        Подсчет количества токенов пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            int: Количество токенов
        """
        stmt = select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked == False,
        )
        result = await self.session.execute(stmt)
        return len(result.scalars().all())