"""
User security settings model for MFA/2FA management.
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class UserSecuritySettings(Base):
    """User security settings for MFA/2FA."""

    __tablename__ = "user_security_settings"

    user_id: Mapped[UUID] = mapped_column(
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
        MutableList.as_mutable(JSONB),
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
        """Enable TOTP with encrypted secret."""
        self.totp_enabled = True
        self.totp_secret = secret

    def disable_totp(self) -> None:
        """Disable TOTP and clear related data."""
        self.totp_enabled = False
        self.totp_secret = None
        self.totp_backup_codes = []

    def check_totp_enabled(self) -> bool:
        """Check if TOTP is fully enabled."""
        return self.totp_enabled and self.totp_secret is not None

    def __repr__(self) -> str:
        return f"<UserSecuritySettings(user_id={self.user_id}, totp_enabled={self.totp_enabled})>"