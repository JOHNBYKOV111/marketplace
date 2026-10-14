from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, or_, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    """Репозиторий для работы с пользователями."""

    def __init__(self, session: AsyncSession):
        super().__init__(User, session)

    async def get_by_email(self, email: str) -> Optional[User]:
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_email_hash(self, email_hash: str) -> Optional[User]:
        stmt = select(User).where(User.email_hash == email_hash)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_phone_hash(self, phone_hash: str) -> Optional[User]:
        stmt = select(User).where(User.phone_hash == phone_hash)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_verification_token(self, token: str) -> Optional[User]:
        stmt = select(User).where(
            User.email_verification_token == token,
            User.email_verification_token_expires > datetime.now(timezone.utc),
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_reset_token(self, token: str) -> Optional[User]:
        stmt = select(User).where(
            User.reset_password_token == token,
            User.reset_password_token_expires > datetime.now(timezone.utc),
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        stmt = select(User).where(User.is_active == True).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_blocked_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        stmt = select(User).where(User.is_active == False).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_email_or_id(
        self, email: Optional[str] = None, user_id: Optional[UUID] = None
    ) -> Optional[User]:
        conditions = []
        if email:
            conditions.append(User.email == email)
        if user_id:
            conditions.append(User.id == user_id)
        if not conditions:
            return None
        stmt = select(User).where(or_(*conditions))
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_password(self, user_id: UUID, new_password_hash: str) -> Optional[User]:
        return await self.update(user_id, password_hash=new_password_hash)

    async def update_verification_token(
        self, user_id: UUID, token: str, expires_at: datetime
    ) -> Optional[User]:
        return await self.update(
            user_id,
            email_verification_token=token,
            email_verification_token_expires=expires_at,
        )

    async def verify_email(self, user_id: UUID) -> Optional[User]:
        return await self.update(
            user_id,
            is_email_verified=True,
            email_verification_token=None,
            email_verification_token_expires=None,
        )

    async def update_reset_token(
        self, user_id: UUID, token: str, expires_at: datetime
    ) -> Optional[User]:
        return await self.update(
            user_id,
            reset_password_token=token,
            reset_password_token_expires=expires_at,
        )

    async def clear_reset_token(self, user_id: UUID) -> Optional[User]:
        return await self.update(
            user_id,
            reset_password_token=None,
            reset_password_token_expires=None,
        )

    async def block_user(self, user_id: UUID) -> Optional[User]:
        return await self.update(user_id, is_active=False)

    async def unblock_user(self, user_id: UUID) -> Optional[User]:
        return await self.update(user_id, is_active=True)

    async def delete_user(self, user_id: UUID) -> bool:
        user = await self.get(user_id)
        if not user:
            return False
        await self.session.delete(user)
        await self.session.commit()
        return True

    async def list_users(
        self,
        limit: int = 20,
        offset: int = 0,
        is_active: Optional[bool] = None,
        is_email_verified: Optional[bool] = None,
    ) -> List[User]:
        conditions = []
        if is_active is not None:
            conditions.append(User.is_active == is_active)
        if is_email_verified is not None:
            conditions.append(User.is_email_verified == is_email_verified)
        stmt = select(User)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(User.created_at.desc()).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_users(
        self,
        is_active: Optional[bool] = None,
        is_email_verified: Optional[bool] = None,
    ) -> int:
        conditions = []
        if is_active is not None:
            conditions.append(User.is_active == is_active)
        if is_email_verified is not None:
            conditions.append(User.is_email_verified == is_email_verified)
        stmt = select(func.count()).select_from(User)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def update_last_login(self, user_id: UUID) -> Optional[User]:
        return await self.update(user_id, updated_at=datetime.now(timezone.utc))

    async def get_metrics(self) -> Dict[str, int]:
        total_stmt = select(func.count()).select_from(User)
        total_result = await self.session.execute(total_stmt)
        total = total_result.scalar_one()
        active_stmt = select(func.count()).select_from(User).where(User.is_active == True)
        active_result = await self.session.execute(active_stmt)
        active = active_result.scalar_one()
        blocked_stmt = select(func.count()).select_from(User).where(User.is_active == False)
        blocked_result = await self.session.execute(blocked_stmt)
        blocked = blocked_result.scalar_one()
        verified_stmt = select(func.count()).select_from(User).where(User.is_email_verified == True)
        verified_result = await self.session.execute(verified_stmt)
        verified = verified_result.scalar_one()
        superuser_stmt = select(func.count()).select_from(User).where(User.is_superuser == True)
        superuser_result = await self.session.execute(superuser_stmt)
        superusers = superuser_result.scalar_one()
        return {
            "total_users": total,
            "active_users": active,
            "blocked_users": blocked,
            "verified_users": verified,
            "superusers": superusers,
        }

    async def create_user(
        self,
        user_id: UUID,
        email: str,
        email_hash: str,
        password_hash: str,
        phone_hash: Optional[str] = None,
        is_active: bool = True,
        is_email_verified: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> User:
        user = User(
            id=user_id,
            email=email,
            email_hash=email_hash,
            phone_hash=phone_hash,
            password_hash=password_hash,
            is_active=is_active,
            is_email_verified=is_email_verified,
            metadata=metadata,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def get_by_id(self, user_id: UUID) -> Optional[User]:
        return await self.get(user_id)

    async def update_user(self, user_id: UUID, **kwargs) -> Optional[User]:
        user = await self.get(user_id)
        if not user:
            return None
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
        user.updated_at = datetime.now(timezone.utc)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def create(self, **kwargs) -> User:
        return await self.create_user(**kwargs)

    async def update(self, user_id: UUID, **kwargs) -> Optional[User]:
        return await self.update_user(user_id, **kwargs)

    async def delete(self, user_id: UUID) -> bool:
        return await self.delete_user(user_id)