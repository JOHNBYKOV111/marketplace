import hashlib
import hmac
from typing import Optional, Dict, Any
from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, String, Index, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class User(Base):
    """Модель пользователя."""
    
    __tablename__ = "users"
    
    __table_args__ = (
        Index("ix_users_email", "email", unique=True),
        Index("ix_users_is_active", "is_active"),
        Index("ix_users_is_superuser", "is_superuser"),
        Index("ix_users_email_hash", "email_hash", unique=True),
        Index("ix_users_phone_hash", "phone_hash"),
        Index("ix_users_email_verification_token", "email_verification_token"),
        Index("ix_users_reset_password_token", "reset_password_token"),
    )
    
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    
    email_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        unique=True,
    )
    
    phone: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
    )
    
    phone_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    
    is_email_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    
    is_superuser: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    
    email_verification_token: Mapped[Optional[str]] = mapped_column(
        String(1024),
        nullable=True,
        index=True,
    )
    
    email_verification_token_expires: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    reset_password_token: Mapped[Optional[str]] = mapped_column(
        String(1024),
        nullable=True,
        index=True,
    )
    
    reset_password_token_expires: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    security_settings: Mapped[Optional["UserSecuritySettings"]] = relationship(
        "UserSecuritySettings",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    
    @staticmethod
    def create_email_hash(email: str) -> str:
        return hashlib.sha256(email.lower().encode()).hexdigest()
    
    @staticmethod
    def create_phone_hash(phone: str) -> str:
        normalized = ''.join(filter(str.isdigit, phone))
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, is_active={self.is_active})>"