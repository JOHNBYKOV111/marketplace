"""
Role and Permission models for RBAC/ABAC system.

Models:
- Role: user roles with hierarchical inheritance
- Permission: granular access permissions (resource + action)
- RolePermission: many-to-many association with grant timestamp
- UserRole: many-to-many association with metadata (assigned_by, expires_at)
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.models.base import Base


class Role(Base):
    """
    User role model with hierarchical inheritance support.

    Attributes:
        name: Unique role name (admin, manager, user, etc.)
        description: Optional human-readable description
        is_system: System roles cannot be deleted
        inherits_permissions: Whether to inherit permissions from parent role
        parent_role_id: Self-referential foreign key for role hierarchy
    """

    __tablename__ = "roles"

    __table_args__ = (
        Index("ix_roles_is_system", "is_system"),
        Index("ix_roles_parent_role_id", "parent_role_id"),
    )

    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    is_system: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    inherits_permissions: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    parent_role_id: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("roles.id", ondelete="SET NULL"),
        nullable=True,
    )

    parent_role: Mapped[Optional["Role"]] = relationship(
        "Role",
        remote_side="Role.id",
        back_populates="children",
    )

    children: Mapped[list["Role"]] = relationship(
        "Role",
        back_populates="parent_role",
    )

    permissions: Mapped[list["Permission"]] = relationship(
        "Permission",
        secondary="role_permissions",
        back_populates="roles",
    )

    @validates("name")
    def validate_name(self, key, name):
        if not name or not name.strip():
            raise ValueError("Role name cannot be empty")
        return name.strip()

    def __repr__(self) -> str:
        return f"<Role(id={self.id}, name='{self.name}', is_system={self.is_system})>"


@event.listens_for(Role, "before_delete")
def prevent_system_role_delete(mapper, connection, target):
    if target.is_system:
        raise ValueError(f"System role '{target.name}' cannot be deleted")


class Permission(Base):
    """
    Granular permission model.

    Each permission grants access to a specific action on a specific resource.
    Example: resource='users', action='read' -> can view user profiles.

    Attributes:
        name: Unique permission identifier (users.read, posts.write)
        resource: Target resource (users, posts, comments)
        action: Allowed action (read, write, delete, manage)
        description: Optional human-readable description
    """

    __tablename__ = "permissions"

    __table_args__ = (
        UniqueConstraint("resource", "action", name="uq_permission_resource_action"),
        Index("ix_permissions_resource", "resource"),
        Index("ix_permissions_action", "action"),
    )

    name: Mapped[str] = mapped_column(
        String(150),
        unique=True,
        nullable=False,
    )

    resource: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    action: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    roles: Mapped[list["Role"]] = relationship(
        "Role",
        secondary="role_permissions",
        back_populates="permissions",
    )

    @validates("name")
    def validate_name(self, key, name):
        if not name or not name.strip():
            raise ValueError("Permission name cannot be empty")
        return name.strip()

    @validates("resource")
    def validate_resource(self, key, resource):
        if not resource or not resource.strip():
            raise ValueError("Resource cannot be empty")
        return resource.strip().lower()

    @validates("action")
    def validate_action(self, key, action):
        if not action or not action.strip():
            raise ValueError("Action cannot be empty")
        return action.strip().lower()

    def __repr__(self) -> str:
        return f"<Permission(id={self.id}, resource='{self.resource}', action='{self.action}')>"


class RolePermission(Base):
    """
    Association table for Role-Permission many-to-many relationship.
    """

    __tablename__ = "role_permissions"

    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
        Index("ix_role_permissions_role_id", "role_id"),
        Index("ix_role_permissions_permission_id", "permission_id"),
    )

    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
    )

    permission_id: Mapped[UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"),
        nullable=False,
    )

    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class UserRole(Base):
    """
    Association table for User-Role many-to-many relationship.
    """

    __tablename__ = "user_roles"

    __table_args__ = (
        Index("ix_user_roles_user_id", "user_id"),
        Index("ix_user_roles_role_id", "role_id"),
        Index("ix_user_roles_expires_at", "expires_at"),
    )

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
    )

    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    assigned_by: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )