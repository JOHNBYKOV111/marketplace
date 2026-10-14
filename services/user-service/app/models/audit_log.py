"""
Audit log model for append-only audit trail.
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLog(Base):
    """
    Append-only audit log for compliance and security tracking.

    Records are immutable by design — any attempt to update an existing
    record will be rejected at the ORM level.
    """

    __tablename__ = "audit_logs"

    __table_args__ = (
        Index("ix_audit_logs_user_id", "user_id"),
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_success", "success"),
        Index("ix_audit_logs_user_action", "user_id", "action"),
    )

    __mapper_args__ = {"confirm_deleted_rows": False}

    user_id: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
    )

    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )

    details: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    user_agent: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    trace_id: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    request_id: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    session_id: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    error_message: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    old_value: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
    )

    new_value: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
    )

    def __setattr__(self, name, value):
        """Prevent modification of existing records to ensure immutability."""
        if name != "_sa_instance_state" and name != "id" and self.id is not None:
            raise AttributeError(f"AuditLog records are immutable. Cannot modify '{name}'.")
        super().__setattr__(name, value)

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action='{self.action}', success={self.success})>"