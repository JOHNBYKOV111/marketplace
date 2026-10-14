"""
User model for user-service.

Stores user profile data only.
Email, status flags, and auth data are owned by auth-service.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class User(Base):
    """
    Core user model.

    Stores profile and compliance data.
    All auth-related fields (email, is_active, is_email_verified,
    is_superuser, password_hash) are owned by auth-service.
    """

    __tablename__ = "users"

    email_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        unique=True,
    )

    phone_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    first_name: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    last_name: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    avatar_url: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    deletion_requested_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    security_settings: Mapped[Optional["UserSecuritySettings"]] = relationship(
        "UserSecuritySettings",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @staticmethod
    def create_email_hash(email: str) -> str:
        return hashlib.sha256(email.lower().encode()).hexdigest()

    @staticmethod
    def create_phone_hash(phone: str) -> str:
        normalized = "".join(filter(str.isdigit, phone))
        return hashlib.sha256(normalized.encode()).hexdigest()

    def __repr__(self) -> str:
        return f"<User(id={self.id})>"