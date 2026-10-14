"""
Репозиторий для работы с аудит-логами.
"""

from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID
from datetime import datetime

from sqlalchemy import select, func, and_, or_, desc, text, cast, Integer
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.repositories.base import BaseRepository


class AuditLogRepository(BaseRepository[AuditLog]):
    """Репозиторий для работы с аудит-логами."""

    def __init__(self, session: AsyncSession):
        """Инициализация репозитория аудит-логов."""
        super().__init__(AuditLog, session)

    async def get_by_user_id(
        self,
        user_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """
        Получает аудит-логи по ID пользователя.

        Args:
            user_id: UUID пользователя
            limit: Количество записей
            offset: Смещение

        Returns:
            List[AuditLog]: Список аудит-логов
        """
        stmt = (
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_user_id(self, user_id: UUID) -> int:
        """
        Подсчитывает количество аудит-логов пользователя.

        Args:
            user_id: UUID пользователя

        Returns:
            int: Количество аудит-логов
        """
        stmt = select(func.count()).select_from(AuditLog).where(AuditLog.user_id == user_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def get_by_action(
        self,
        action: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """
        Получает аудит-логи по действию.

        Args:
            action: Название действия
            limit: Количество записей
            offset: Смещение

        Returns:
            List[AuditLog]: Список аудит-логов
        """
        stmt = (
            select(AuditLog)
            .where(AuditLog.action == action)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_all_with_filters(
        self,
        user_id: Optional[UUID] = None,
        action: Optional[str] = None,
        success: Optional[bool] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[AuditLog], int]:
        """
        Получает аудит-логи с фильтрацией и возвращает общее количество.

        Args:
            user_id: ID пользователя
            action: Действие
            success: Статус выполнения
            start_date: Начальная дата
            end_date: Конечная дата
            limit: Количество записей
            offset: Смещение

        Returns:
            Tuple[List[AuditLog], int]: Список аудит-логов и общее количество
        """
        conditions = []
        if user_id:
            conditions.append(AuditLog.user_id == user_id)
        if action:
            conditions.append(AuditLog.action == action)
        if success is not None:
            conditions.append(AuditLog.success == success)
        if start_date:
            conditions.append(AuditLog.created_at >= start_date)
        if end_date:
            conditions.append(AuditLog.created_at <= end_date)

        stmt = select(AuditLog)
        if conditions:
            stmt = stmt.where(and_(*conditions))

        # Подсчёт общего количества
        count_stmt = select(func.count()).select_from(AuditLog)
        if conditions:
            count_stmt = count_stmt.where(and_(*conditions))
        count_result = await self.session.execute(count_stmt)
        total = count_result.scalar_one()

        # Получение записей с пагинацией
        stmt = stmt.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        logs = list(result.scalars().all())

        return logs, total

    async def count_with_filters(
        self,
        user_id: Optional[UUID] = None,
        action: Optional[str] = None,
        success: Optional[bool] = None,
    ) -> int:
        """
        Подсчитывает количество аудит-логов с фильтрацией.

        Args:
            user_id: ID пользователя
            action: Действие
            success: Статус выполнения

        Returns:
            int: Количество аудит-логов
        """
        conditions = []
        if user_id:
            conditions.append(AuditLog.user_id == user_id)
        if action:
            conditions.append(AuditLog.action == action)
        if success is not None:
            conditions.append(AuditLog.success == success)

        stmt = select(func.count()).select_from(AuditLog)
        if conditions:
            stmt = stmt.where(and_(*conditions))

        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def get_distinct_actions(self) -> List[str]:
        """
        Получает список уникальных действий.

        Returns:
            List[str]: Список уникальных действий
        """
        stmt = select(AuditLog.action).distinct()
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_actions_list(self) -> List[str]:
        """
        Получает список уникальных действий (алиас для get_distinct_actions).

        Returns:
            List[str]: Список уникальных действий
        """
        return await self.get_distinct_actions()

    async def get_failed_actions(
        self,
        user_id: Optional[UUID] = None,
        limit: int = 100,
    ) -> List[AuditLog]:
        """
        Получает неудачные действия.

        Args:
            user_id: ID пользователя (опционально)
            limit: Количество записей

        Returns:
            List[AuditLog]: Список неудачных действий
        """
        conditions = [AuditLog.success == False]
        if user_id:
            conditions.append(AuditLog.user_id == user_id)

        stmt = select(AuditLog).where(and_(*conditions)).order_by(AuditLog.created_at.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_statistics(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Dict[str, int]]:
        """
        Получает статистику по действиям.

        Args:
            start_date: Начальная дата
            end_date: Конечная дата

        Returns:
            Dict[str, Dict[str, int]]: Статистика по действиям
        """
        conditions = []
        if start_date:
            conditions.append(AuditLog.created_at >= start_date)
        if end_date:
            conditions.append(AuditLog.created_at <= end_date)

        # Используем cast для правильного преобразования boolean к integer
        stmt = select(
            AuditLog.action,
            func.count().label('total'),
            func.sum(cast(AuditLog.success, Integer)).label('success_count')
        )
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.group_by(AuditLog.action)

        result = await self.session.execute(stmt)
        rows = result.all()

        stats = {}
        for row in rows:
            action = row[0]
            total = row[1]
            success_count = row[2] or 0
            stats[action] = {
                'total': total,
                'success': success_count,
                'failed': total - success_count,
            }

        return stats

    async def cleanup_old_logs(self, days: int = 90) -> int:
        """
        Удаляет старые логи.

        Args:
            days: Количество дней, после которых логи считаются старыми

        Returns:
            int: Количество удалённых записей
        """
        from datetime import datetime, timedelta, timezone

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        stmt = select(AuditLog).where(AuditLog.created_at < cutoff)
        result = await self.session.execute(stmt)
        logs_to_delete = list(result.scalars().all())

        for log in logs_to_delete:
            await self.session.delete(log)

        await self.session.commit()
        return len(logs_to_delete)

    async def create_log(
        self,
        user_id: UUID,
        action: str,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        error_message: Optional[str] = None,
        old_value: Optional[Dict[str, Any]] = None,
        new_value: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """
        Создает аудит-лог.

        Args:
            user_id: ID пользователя
            action: Действие
            success: Статус выполнения
            details: Дополнительные детали
            ip_address: IP-адрес
            user_agent: User-Agent
            trace_id: Trace ID
            request_id: Request ID
            session_id: Session ID
            error_message: Сообщение об ошибке
            old_value: Старое значение
            new_value: Новое значение

        Returns:
            AuditLog: Созданный аудит-лог
        """
        return await self.create_from_dict(
            user_id=user_id,
            action=action,
            success=success,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            trace_id=trace_id,
            request_id=request_id,
            session_id=session_id,
            error_message=error_message,
            old_value=old_value,
            new_value=new_value,
        )