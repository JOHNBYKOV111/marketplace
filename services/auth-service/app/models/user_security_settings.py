"""
Модель настроек безопасности пользователя.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Boolean, DateTime, Index, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class UserSecuritySettings(Base):
    """Модель настроек безопасности пользователя."""
    
    __tablename__ = "user_security_settings"
    
    __table_args__ = (
        Index("ix_user_security_settings_user_id", "user_id"),
        Index("ix_user_security_settings_totp_enabled", "totp_enabled"),
    )
    
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    
    totp_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    
    totp_secret: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    
    totp_backup_codes: Mapped[Optional[list[str]]] = mapped_column(
        JSON,
        nullable=True,
        default=list,
    )
    
    last_password_change: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    user: Mapped["User"] = relationship(
        "User",
        back_populates="security_settings",
        lazy="selectin",
        uselist=False,
    )
    
    def enable_totp(self, secret: str) -> None:
        """
        Включает TOTP для пользователя.
        
        Args:
            secret: Секретный ключ TOTP
        """
        self.totp_enabled = True
        self.totp_secret = secret
    
    def disable_totp(self) -> None:
        """Отключает TOTP для пользователя."""
        self.totp_enabled = False
        self.totp_secret = None
        self.totp_backup_codes = []
    
    def check_totp_enabled(self) -> bool:
        """
        Проверяет, включён ли TOTP.
        
        Returns:
            bool: True если TOTP включён
        """
        return self.totp_enabled and self.totp_secret is not None
    
    def __repr__(self) -> str:
        return f"<UserSecuritySettings(user_id={self.user_id}, totp_enabled={self.totp_enabled})>"