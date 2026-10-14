"""
Audit log repository for database operations.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy import case, delete, select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


class AuditLogRepository:
    """Repository for AuditLog database operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, log: AuditLog) -> AuditLog:
        """Create an audit log entry."""
        self.db.add(log)
        await self.db.flush()
        return log

    async def get_by_id(self, log_id: UUID) -> Optional[AuditLog]:
        """Get audit log by ID."""
        result = await self.db.execute(
            select(AuditLog).where(AuditLog.id == log_id)
        )
        return result.scalar_one_or_none()

    async def get_by_user_id(
        self,
        user_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[AuditLog], int]:
        """Get audit logs for a specific user with pagination."""
        where_clause = AuditLog.user_id == user_id

        count_query = select(func.count()).select_from(AuditLog).where(where_clause)
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()

        query = (
            select(AuditLog)
            .where(where_clause)
            .order_by(AuditLog.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self.db.execute(query)
        logs = result.scalars().all()

        return logs, total

    async def get_by_action(self, action: str) -> List[AuditLog]:
        """Get audit logs by action type."""
        result = await self.db.execute(
            select(AuditLog).where(AuditLog.action == action)
        )
        return result.scalars().all()

    async def get_with_filters(
        self,
        user_id: UUID = None,
        action: str = None,
        success: bool = None,
        start_date: datetime = None,
        end_date: datetime = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[AuditLog], int]:
        """Get audit logs with combined filters."""
        conditions = []

        if user_id is not None:
            conditions.append(AuditLog.user_id == user_id)
        if action is not None:
            conditions.append(AuditLog.action == action)
        if success is not None:
            conditions.append(AuditLog.success == success)
        if start_date is not None:
            conditions.append(AuditLog.created_at >= start_date)
        if end_date is not None:
            conditions.append(AuditLog.created_at <= end_date)

        where_clause = and_(*conditions) if conditions else None

        count_query = select(func.count()).select_from(AuditLog)
        if where_clause is not None:
            count_query = count_query.where(where_clause)
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()

        query = (
            select(AuditLog)
            .order_by(AuditLog.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        if where_clause is not None:
            query = query.where(where_clause)
        result = await self.db.execute(query)
        logs = result.scalars().all()

        return logs, total

    async def get_failed_actions(
        self,
        user_id: UUID = None,
        limit: int = 20,
    ) -> List[AuditLog]:
        """Get failed action logs."""
        conditions = [AuditLog.success == False]
        if user_id is not None:
            conditions.append(AuditLog.user_id == user_id)

        query = (
            select(AuditLog)
            .where(and_(*conditions))
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
        )
        result = await self.db.execute(query)
        return result.scalars().all()

    async def get_statistics(
        self,
        start_date: datetime = None,
        end_date: datetime = None,
    ) -> dict:
        """Get audit log statistics in a single query."""
        conditions = []
        if start_date is not None:
            conditions.append(AuditLog.created_at >= start_date)
        if end_date is not None:
            conditions.append(AuditLog.created_at <= end_date)

        where_clause = and_(*conditions) if conditions else None

        query = select(
            func.count().label("total"),
            func.sum(case((AuditLog.success == True, 1), else_=0)).label("successful"),
            func.sum(case((AuditLog.success == False, 1), else_=0)).label("failed"),
        ).select_from(AuditLog)

        if where_clause is not None:
            query = query.where(where_clause)

        result = await self.db.execute(query)
        row = result.one()

        return {
            "total": row.total or 0,
            "successful": row.successful or 0,
            "failed": row.failed or 0,
        }

    async def get_actions_list(self) -> List[str]:
        """Get list of distinct action types."""
        result = await self.db.execute(
            select(AuditLog.action).distinct()
        )
        rows = result.fetchall()
        return [row[0] for row in rows]

    async def cleanup_old_logs(self, days: int = 90) -> int:
        """Delete logs older than specified days using bulk delete."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        stmt = delete(AuditLog).where(AuditLog.created_at < cutoff)
        result = await self.db.execute(stmt)
        await self.db.flush()
        return result.rowcount