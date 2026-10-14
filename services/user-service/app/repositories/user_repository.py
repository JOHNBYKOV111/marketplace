"""
User repository for database operations.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List
from uuid import UUID

from sqlalchemy import delete, select, func, and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


class UserRepository:
    """Repository for User database operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, user: User) -> User:
        """Create a new user."""
        try:
            self.db.add(user)
            await self.db.flush()
            return user
        except IntegrityError:
            await self.db.rollback()
            raise

    async def get_by_id(self, user_id: UUID) -> Optional[User]:
        """Get user by ID."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_email_hash(self, email_hash: str) -> Optional[User]:
        """Get user by email hash."""
        if not email_hash:
            return None
        result = await self.db.execute(
            select(User).where(User.email_hash == email_hash)
        )
        return result.scalar_one_or_none()

    async def get_by_phone_hash(self, phone_hash: str) -> Optional[User]:
        """Get user by phone hash."""
        if not phone_hash:
            return None
        result = await self.db.execute(
            select(User).where(User.phone_hash == phone_hash)
        )
        return result.scalar_one_or_none()

    async def update(self, user: User) -> Optional[User]:
        """Update user fields. Returns updated user or None if not found."""
        existing = await self.db.get(User, user.id)
        if not existing:
            return None

        for key, value in user.__dict__.items():
            if key != "_sa_instance_state" and value is not None:
                setattr(existing, key, value)

        await self.db.flush()
        return existing

    async def soft_delete(self, user_id: UUID) -> bool:
        """Soft delete a user."""
        user = await self.get_by_id(user_id)
        if not user:
            return False
        user.is_deleted = True
        user.deleted_at = datetime.now(timezone.utc)
        await self.db.flush()
        return True

    async def delete_expired_soft_deleted(self, days: int = 30) -> int:
        """Hard delete users soft-deleted more than N days ago using bulk delete."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        stmt = delete(User).where(
            User.is_deleted == True,
            User.deleted_at < cutoff,
        )
        result = await self.db.execute(stmt)
        await self.db.flush()
        return result.rowcount

    async def block(self, user_id: UUID) -> bool:
        """Block a user (delegates to auth-service, stub in user-service)."""
        user = await self.get_by_id(user_id)
        if not user:
            return False
        return True

    async def unblock(self, user_id: UUID) -> bool:
        """Unblock a user (delegates to auth-service, stub in user-service)."""
        user = await self.get_by_id(user_id)
        if not user:
            return False
        return True

    async def list_users(
        self,
        limit: int = 20,
        offset: int = 0,
        search: str = None,
    ) -> Tuple[List[User], int]:
        """List non-deleted users with pagination and optional search."""
        conditions = [User.is_deleted == False]

        where_clause = and_(*conditions)

        count_query = select(func.count()).select_from(User).where(where_clause)
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()

        query = (
            select(User)
            .where(where_clause)
            .order_by(User.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self.db.execute(query)
        users = list(result.scalars().all())

        return users, total

    async def count_users(self) -> int:
        """Count non-deleted users."""
        query = select(func.count()).select_from(User).where(User.is_deleted == False)
        result = await self.db.execute(query)
        return result.scalar()