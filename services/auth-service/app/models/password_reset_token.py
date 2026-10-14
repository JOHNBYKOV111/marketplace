# app/models/password_reset_token.py

"""
Модель для хранения токенов сброса пароля.

Используется для:
- Хранения одноразовых токенов сброса пароля
- Защиты от атак перебора (brute force) через хэширование токенов
- Автоматического истечения TTL (по умолчанию 1 час)
- Отметки использованных токенов
- Очистки просроченных токенов

Связанные модули:
- app.repositories.password_reset_token_repository - CRUD операции
- app.services.password_reset_service - бизнес-логика сброса пароля
- app.routers.auth - эндпоинты сброса пароля
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from uuid import UUID

from sqlalchemy import DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class PasswordResetToken(Base):
    """
    Модель токена сброса пароля.

    Поддерживает:
    - Одноразовое использование (отметка used_at)
    - Автоматическое истечение TTL (по умолчанию 1 час)
    - Хэширование токенов для безопасного хранения
    - Защиту от атак перебора
    - Очистку просроченных токенов

    Attributes:
        id: Уникальный идентификатор записи (UUID)
        user_id: ID пользователя (внешний ключ)
        token_hash: Хэш токена (SHA256)
        expires_at: Время истечения срока действия
        used_at: Время использования (null если не использован)
        created_at: Время создания записи
        updated_at: Время последнего обновления

    Индексы:
        - idx_password_reset_token_user_id: Поиск токенов пользователя
        - idx_password_reset_token_token_hash: Быстрый поиск по хэшу (уникальный)
        - idx_password_reset_token_expires_at: Очистка просроченных токенов
        - idx_password_reset_token_user_expires: Составной индекс для удаления
    """

    __tablename__ = "password_reset_tokens"

    # ==================== ПЕРВИЧНЫЙ КЛЮЧ ====================

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),  # ✅ Исправлено
        doc="Уникальный идентификатор записи",
    )

    # ==================== СВЯЗЬ С ПОЛЬЗОВАТЕЛЕМ ====================

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        index=True,
        doc="ID пользователя",
    )

    # ==================== ХЭШ ТОКЕНА ====================

    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        doc="Хэш токена сброса пароля (SHA256)",
    )

    # ==================== ВРЕМЕННЫЕ ПОЛЯ ====================

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        doc="Время истечения срока действия токена",
    )

    used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Время использования токена (null если не использован)",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),  # ✅ Исправлено
        doc="Время создания записи",
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),  # ✅ Исправлено
        onupdate=func.now(),  # ✅ Исправлено
        doc="Время последнего обновления",
    )

    # ==================== ИНДЕКСЫ ====================

    __table_args__ = (
        # Составной индекс для метода delete_by_user_id()
        Index(
            "idx_password_reset_token_user_id",
            "user_id",
        ),
        # Составной индекс для метода delete_expired()
        Index(
            "idx_password_reset_token_expires_at",
            "expires_at",
        ),
        # Составной индекс для проверки активных токенов
        Index(
            "idx_password_reset_token_user_expires",
            "user_id",
            "expires_at",
        ),
    )

    # ==================== МЕТОДЫ ====================

    def __repr__(self) -> str:
        """Строковое представление модели."""
        return (
            f"<PasswordResetToken(id={self.id}, user_id={self.user_id}, "
            f"token_hash={self.token_hash[:8]}..., expires_at={self.expires_at})>"
        )

    def is_expired(self) -> bool:
        """
        Проверка, истек ли срок действия токена.

        Returns:
            bool: True если токен истек
        """
        return self.expires_at < datetime.now(timezone.utc)

    def is_used(self) -> bool:
        """
        Проверка, был ли токен использован.

        Returns:
            bool: True если токен использован
        """
        return self.used_at is not None

    def is_valid(self) -> bool:
        """
        Проверка, действителен ли токен для использования.

        Токен считается действительным если:
        - Не истек
        - Не использован

        Returns:
            bool: True если токен действителен
        """
        return not self.is_expired() and not self.is_used()

    def mark_as_used(self) -> None:
        """
        Отметить токен как использованный.
        Устанавливает used_at на текущее время.
        """
        self.used_at = datetime.now(timezone.utc)

    @classmethod
    def create_token_hash(cls, raw_token: str) -> str:
        """
        Создание хэша токена для безопасного хранения.

        Args:
            raw_token: Сырой токен

        Returns:
            str: SHA256 хэш токена
        """
        import hashlib
        return hashlib.sha256(raw_token.encode()).hexdigest()

    @classmethod
    def generate_raw_token(cls) -> str:
        """
        Генерация сырого токена сброса пароля.

        Returns:
            str: Случайный токен длиной 64 символа
        """
        return secrets.token_urlsafe(64)

    @classmethod
    def create_for_user(
        cls,
        user_id: UUID,
        ttl_hours: int = 1,
    ) -> Tuple["PasswordResetToken", str]:
        """
        Фабричный метод для создания токена сброса пароля для пользователя.

        Args:
            user_id: ID пользователя
            ttl_hours: Время жизни в часах (по умолчанию 1 час)

        Returns:
            Tuple[PasswordResetToken, str]: (Созданный объект, сырой токен)
        """
        ttl_seconds = ttl_hours * 3600
        return cls.create_for_user_with_custom_ttl(
            user_id=user_id,
            ttl_seconds=ttl_seconds,
        )

    @classmethod
    def create_for_user_with_custom_ttl(
        cls,
        user_id: UUID,
        ttl_seconds: int,
    ) -> Tuple["PasswordResetToken", str]:
        """
        Фабричный метод для создания токена с кастомным TTL.

        Args:
            user_id: ID пользователя
            ttl_seconds: Время жизни в секундах

        Returns:
            Tuple[PasswordResetToken, str]: (Созданный объект, сырой токен)
        """
        raw_token = cls.generate_raw_token()
        token_hash = cls.create_token_hash(raw_token)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        token = cls(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            used_at=None,
        )

        return token, raw_token