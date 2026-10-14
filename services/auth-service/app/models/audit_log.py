"""
Модель аудит-лога для отслеживания действий пользователей.
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy import String, Boolean, JSON, DateTime, Index, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class AuditLog(Base):
    """Модель аудит-лога."""
    
    __tablename__ = "audit_logs"
    
    __table_args__ = (
        Index("ix_audit_logs_user_id", "user_id"),
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_success", "success"),
        Index("ix_audit_logs_trace_id", "trace_id"),
    )
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    
    success: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default={},
    )
    
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    
    trace_id: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        index=True,
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
    
    old_value: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )
    
    new_value: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=func.now(),
        nullable=False,
        index=True,
    )
    
    # Отношения
    user: Mapped[Optional["User"]] = relationship(
        "User",
        backref="audit_logs",
        lazy="selectin",
    )
    
    @classmethod
    def create_login_record(
        cls,
        user_id: Optional[uuid.UUID],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
    ) -> "AuditLog":
        """
        Создаёт запись аудит-лога для действия login.
        
        Args:
            user_id: ID пользователя (может быть None для неудачных попыток)
            ip_address: IP-адрес
            user_agent: User-Agent
            trace_id: Trace ID
            request_id: Request ID
            session_id: Session ID
            success: Успешно ли выполнено
            error_message: Сообщение об ошибке
            
        Returns:
            AuditLog: Созданный аудит-лог
        """
        return cls(
            user_id=user_id,
            action="login",
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            trace_id=trace_id,
            request_id=request_id,
            session_id=session_id,
            error_message=error_message,
        )
    
    @classmethod
    def create_logout_record(
        cls,
        user_id: uuid.UUID,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        success: bool = True,
    ) -> "AuditLog":
        """
        Создаёт запись аудит-лога для действия logout.
        """
        return cls(
            user_id=user_id,
            action="logout",
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            trace_id=trace_id,
            request_id=request_id,
            session_id=session_id,
        )
    
    @classmethod
    def create_password_change_record(
        cls,
        user_id: uuid.UUID,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
    ) -> "AuditLog":
        """
        Создаёт запись аудит-лога для смены пароля.
        """
        return cls(
            user_id=user_id,
            action="password_change",
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            trace_id=trace_id,
            request_id=request_id,
            session_id=session_id,
            error_message=error_message,
        )
    
    @classmethod
    def create_mfa_record(
        cls,
        user_id: uuid.UUID,
        action: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
    ) -> "AuditLog":
        """
        Создаёт запись аудит-лога для MFA действий.
        
        Args:
            user_id: ID пользователя
            action: Действие (mfa_enable, mfa_disable, mfa_verify)
            ip_address: IP-адрес
            user_agent: User-Agent
            trace_id: Trace ID
            request_id: Request ID
            session_id: Session ID
            success: Успешно ли выполнено
            details: Дополнительные детали
        """
        return cls(
            user_id=user_id,
            action=action,
            success=success,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            trace_id=trace_id,
            request_id=request_id,
            session_id=session_id,
        )
    
    @classmethod
    def create_admin_action_record(
        cls,
        user_id: uuid.UUID,
        action: str,
        details: Dict[str, Any],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
    ) -> "AuditLog":
        """
        Создаёт запись аудит-лога для действий администратора.
        """
        return cls(
            user_id=user_id,
            action=f"admin_{action}",
            success=success,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            trace_id=trace_id,
            request_id=request_id,
            session_id=session_id,
            error_message=error_message,
        )
    
    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, user_id={self.user_id}, action={self.action})>"