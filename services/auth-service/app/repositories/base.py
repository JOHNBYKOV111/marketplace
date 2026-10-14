"""
Базовый репозиторий с CRUD операциями.
"""

from typing import Generic, TypeVar, Type, Optional, List, Dict, Any, Sequence, Union
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.models.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """Базовый репозиторий с CRUD операциями."""

    def __init__(self, model: Type[ModelType], session: AsyncSession):
        """
        Инициализация репозитория.

        Args:
            model: Класс модели SQLAlchemy
            session: Асинхронная сессия
        """
        self.model = model
        self.session = session

    async def create(self, instance: ModelType) -> ModelType:
        """
        Сохраняет переданный экземпляр модели в БД.

        Args:
            instance: Экземпляр модели для сохранения

        Returns:
            ModelType: Сохраненная модель
        """
        self.session.add(instance)
        await self.session.commit()
        await self.session.refresh(instance)
        return instance

    async def create_from_dict(self, **kwargs) -> ModelType:
        """
        Создает новую запись из словаря.

        Args:
            **kwargs: Поля модели

        Returns:
            ModelType: Созданная модель
        """
        instance = self.model(**kwargs)
        self.session.add(instance)
        await self.session.commit()
        await self.session.refresh(instance)
        return instance

    async def get(self, id: UUID) -> Optional[ModelType]:
        """
        Получает запись по ID.

        Args:
            id: UUID записи

        Returns:
            Optional[ModelType]: Найденная модель или None
        """
        stmt = select(self.model).where(self.model.id == id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_id(self, id: Union[UUID, int]) -> Optional[ModelType]:
        """
        Получает запись по ID (универсальный метод).

        Args:
            id: ID записи (UUID или int)

        Returns:
            Optional[ModelType]: Найденная модель или None
        """
        stmt = select(self.model).where(self.model.id == id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_all(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[str] = None,
        descending: bool = False,
    ) -> List[ModelType]:
        """
        Получает список записей с пагинацией и фильтрацией.

        Args:
            limit: Количество записей
            offset: Смещение
            filters: Фильтры
            order_by: Поле для сортировки
            descending: По убыванию

        Returns:
            List[ModelType]: Список моделей
        """
        stmt = self._build_query(filters, order_by, descending)
        stmt = stmt.limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        Подсчитывает количество записей.

        Args:
            filters: Фильтры

        Returns:
            int: Количество записей
        """
        stmt = self._build_query(filters)
        count_stmt = select(func.count()).select_from(stmt.subquery())
        result = await self.session.execute(count_stmt)
        return result.scalar_one()

    async def update(self, id: UUID, **kwargs) -> Optional[ModelType]:
        """
        Обновляет запись.

        Args:
            id: UUID записи
            **kwargs: Поля для обновления

        Returns:
            Optional[ModelType]: Обновленная модель или None
        """
        instance = await self.get(id)
        if not instance:
            return None

        for key, value in kwargs.items():
            if hasattr(instance, key):
                setattr(instance, key, value)

        await self.session.commit()
        await self.session.refresh(instance)
        return instance

    async def delete(self, id: UUID) -> bool:
        """
        Удаляет запись.

        Args:
            id: UUID записи

        Returns:
            bool: True если удалено, иначе False
        """
        instance = await self.get(id)
        if not instance:
            return False

        await self.session.delete(instance)
        await self.session.commit()
        return True

    async def exists(self, **kwargs) -> bool:
        """
        Проверяет существование записи.

        Args:
            **kwargs: Поля для проверки

        Returns:
            bool: True если существует
        """
        stmt = select(self.model).filter_by(**kwargs)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none() is not None

    def _build_query(
        self,
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[str] = None,
        descending: bool = False,
    ) -> Select:
        """
        Строит запрос с фильтрацией и сортировкой.

        Args:
            filters: Фильтры
            order_by: Поле для сортировки
            descending: По убыванию

        Returns:
            Select: Запрос SQLAlchemy
        """
        stmt = select(self.model)

        if filters:
            for key, value in filters.items():
                if value is not None:
                    if hasattr(self.model, key):
                        stmt = stmt.where(getattr(self.model, key) == value)

        if order_by and hasattr(self.model, order_by):
            column = getattr(self.model, order_by)
            stmt = stmt.order_by(column.desc() if descending else column)

        return stmt