"""
Модель refresh токена для управления сессиями.

Обеспечивает:
- Безопасное хранение refresh токенов
- Отслеживание активных сессий
- Ротацию токенов
- Автоматическую очистку истекших токенов
- Индексы для высоконагруженных запросов
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    String,
    func,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class RefreshToken(Base, TimestampMixin):
    """
    Модель refresh токена.

    Хранит информацию о refresh токенах для управления сессиями.
    Поддерживает ротацию токенов и отслеживание активности.

    Атрибуты:
        id: Уникальный идентификатор токена (UUID)
        user_id: ID пользователя
        token_id: ID токена (уникальная строка)
        device_id: ID устройства
        device_name: Название устройства
        expires_at: Время истечения токена
        is_revoked: Флаг отзыва токена
        revoked_at: Время отзыва токена
        ip_address: IP клиента (для безопасности)
        user_agent: User-Agent клиента
        last_used_at: Время последнего использования
        is_rotated: Флаг ротации токена
    """

    __tablename__ = "refresh_tokens"

    __table_args__ = (
        Index("ix_refresh_tokens_user_id", "user_id"),
        Index("ix_refresh_tokens_token_id", "token_id"),
        Index("ix_refresh_tokens_expires_at", "expires_at"),
        Index("ix_refresh_tokens_is_revoked", "is_revoked"),
        Index("ix_refresh_tokens_user_revoked", "user_id", "is_revoked"),
        Index("ix_refresh_tokens_user_expires", "user_id", "expires_at"),
        UniqueConstraint("token_id", name="uq_refresh_tokens_token_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        doc="Уникальный идентификатор записи",
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        doc="ID пользователя",
    )

    token_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        doc="ID refresh токена (строка)",
    )

    device_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="ID устройства",
    )

    device_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Название устройства",
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        doc="Время истечения токена",
    )

    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        doc="Флаг отзыва токена",
    )

    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Время отзыва токена",
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
        doc="IP адрес клиента (IPv4 - 15, IPv6 - 45)",
    )

    user_agent: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
        doc="User-Agent клиента",
    )

    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Время последнего использования",
    )

    is_rotated: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        doc="Флаг ротации токена",
    )

    @property
    def is_expired(self) -> bool:
        """
        Проверка истечения токена.

        Returns:
            bool: True если токен истек
        """
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_active(self) -> bool:
        """
        Проверка активности токена.

        Токен активен если:
        - Не истек
        - Не отозван

        Returns:
            bool: True если токен активен
        """
        return not self.is_expired and not self.is_revoked

    @property
    def lifetime_seconds(self) -> int:
        """
        Время жизни токена в секундах.

        Returns:
            int: Количество секунд от создания до истечения
        """
        return int((self.expires_at - self.created_at).total_seconds())

    @property
    def remaining_seconds(self) -> int:
        """
        Оставшееся время жизни в секундах.

        Returns:
            int: Количество секунд до истечения
        """
        if self.is_expired:
            return 0
        return int((self.expires_at - datetime.now(timezone.utc)).total_seconds())

    @classmethod
    def create_token(
        cls,
        user_id: uuid.UUID,
        expires_days: int = 30,
        device_id: Optional[str] = None,
        device_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> "RefreshToken":
        """
        Фабричный метод для создания refresh токена.

        Args:
            user_id: ID пользователя
            expires_days: Количество дней до истечения
            device_id: ID устройства
            device_name: Название устройства
            ip_address: IP адрес
            user_agent: User-Agent

        Returns:
            RefreshToken: Созданный объект токена
        """
        token_id = f"rt_{uuid.uuid4().hex}"
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

        return cls(
            user_id=user_id,
            token_id=token_id,
            device_id=device_id,
            device_name=device_name,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            is_revoked=False,
            is_rotated=False,
        )

    def revoke(self) -> None:
        """
        Отзыв токена.

        Устанавливает флаг is_revoked и время отзыва.
        """
        if not self.is_revoked:
            self.is_revoked = True
            self.revoked_at = datetime.now(timezone.utc)

    def touch(self) -> None:
        """
        Обновление времени последнего использования.
        """
        self.last_used_at = datetime.now(timezone.utc)

    def is_valid_for_user(self, user_id: uuid.UUID) -> bool:
        """
        Проверка принадлежности токена пользователю.

        Args:
            user_id: ID пользователя

        Returns:
            bool: True если токен принадлежит пользователю
        """
        return self.user_id == user_id

    def __repr__(self) -> str:
        return (
            f"<RefreshToken("
            f"id={self.id}, "
            f"user_id={self.user_id}, "
            f"token_id={self.token_id}, "
            f"is_active={self.is_active}, "
            f"expires_at={self.expires_at}"
            f")>"
        )

    def to_dict(self) -> dict:
        """
        Преобразование модели в словарь.

        Returns:
            dict: Словарь с данными токена
        """
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "token_id": self.token_id,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "is_active": self.is_active,
            "is_revoked": self.is_revoked,
            "is_rotated": self.is_rotated,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "remaining_seconds": self.remaining_seconds,
        }