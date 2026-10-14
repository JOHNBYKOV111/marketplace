"""
Role repository for database operations.
"""

from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.models.role import Role, Permission, RolePermission, UserRole


class RoleRepository:
    """Repository for Role and Permission database operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, role: Role) -> Role:
        """Create a new role."""
        self.db.add(role)
        await self.db.flush()
        return role

    async def get_by_id(self, role_id: UUID) -> Optional[Role]:
        """Get role by ID."""
        result = await self.db.execute(select(Role).where(Role.id == role_id))
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> Optional[Role]:
        """Get role by name."""
        result = await self.db.execute(select(Role).where(Role.name == name))
        return result.scalar_one_or_none()

    async def list_all(self) -> List[Role]:
        """List all roles."""
        result = await self.db.execute(select(Role).order_by(Role.name))
        return result.scalars().all()

    async def update(self, role: Role) -> Role:
        """Update a role."""
        merged = await self.db.merge(role)
        await self.db.flush()
        return merged

    async def delete(self, role_id: UUID) -> bool:
        """Delete a role by ID."""
        role = await self.get_by_id(role_id)
        if not role:
            return False
        await self.db.delete(role)
        await self.db.flush()
        return True

    async def assign_permission(self, role_id: UUID, permission_id: UUID) -> RolePermission:
        """Assign a permission to a role."""
        rp = RolePermission(role_id=role_id, permission_id=permission_id)
        self.db.add(rp)
        await self.db.flush()
        return rp

    async def remove_permission(self, role_id: UUID, permission_id: UUID) -> bool:
        """Remove a permission from a role."""
        result = await self.db.execute(
            select(RolePermission).where(
                and_(
                    RolePermission.role_id == role_id,
                    RolePermission.permission_id == permission_id,
                )
            )
        )
        rp = result.scalar_one_or_none()
        if not rp:
            return False
        await self.db.delete(rp)
        await self.db.flush()
        return True

    async def get_role_permissions(self, role_id: UUID) -> List[Permission]:
        """Get all permissions assigned to a role."""
        result = await self.db.execute(
            select(Permission)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.role_id == role_id)
        )
        return result.scalars().all()

    async def assign_role_to_user(
        self,
        user_id: UUID,
        role_id: UUID,
        assigned_by: UUID = None,
        expires_at: datetime = None,
    ) -> UserRole:
        """Assign a role to a user."""
        ur = UserRole(
            user_id=user_id,
            role_id=role_id,
            assigned_by=assigned_by,
            expires_at=expires_at,
        )
        self.db.add(ur)
        await self.db.flush()
        return ur

    async def remove_role_from_user(self, user_id: UUID, role_id: UUID) -> bool:
        """Remove a role from a user."""
        result = await self.db.execute(
            select(UserRole).where(
                and_(
                    UserRole.user_id == user_id,
                    UserRole.role_id == role_id,
                )
            )
        )
        ur = result.scalar_one_or_none()
        if not ur:
            return False
        await self.db.delete(ur)
        await self.db.flush()
        return True

    async def get_roles_by_user_id(self, user_id: UUID) -> List[Role]:
        """Get all active roles assigned to a user. Expired roles are excluded."""
        now = datetime.now(timezone.utc)
        result = await self.db.execute(
            select(Role)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(
                and_(
                    UserRole.user_id == user_id,
                    or_(UserRole.expires_at == None, UserRole.expires_at > now),
                )
            )
        )
        return result.scalars().all()

    async def get_child_roles(self, role_id: UUID) -> List[Role]:
        """Get child roles of a given role."""
        result = await self.db.execute(
            select(Role).where(Role.parent_role_id == role_id)
        )
        return result.scalars().all()

    async def get_parent_role(self, role_id: UUID) -> Optional[Role]:
        """Get parent role in a single query using aliased join."""
        ParentRole = aliased(Role)
        result = await self.db.execute(
            select(ParentRole)
            .select_from(Role)
            .join(ParentRole, Role.parent_role_id == ParentRole.id)
            .where(Role.id == role_id)
        )
        return result.scalar_one_or_none()