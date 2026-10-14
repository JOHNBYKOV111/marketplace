"""
Модель для хранения OAuth 2.0 состояний (state).

Используется для:
- Хранения параметров OAuth 2.0 авторизации (state, code_verifier)
- Поддержки логина через внешних провайдеров (Google, VK, etc.)
- Привязки внешних аккаунтов к пользователям
- Защиты от CSRF атак (state)
- Автоматического истечения TTL

Связанные модули:
- app.repositories.oauth_state_repository - CRUD операции
- app.services.oauth_service - бизнес-логика OAuth
- app.routers.oauth - эндпоинты OAuth
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class OAuthState(Base):
    """
    Модель OAuth 2.0 состояния для авторизации через внешних провайдеров.

    Поддерживает:
    - Логин через OAuth провайдеров (Google, VK, GitHub, etc.)
    - Привязку внешних аккаунтов к существующим пользователям
    - Защиту от CSRF через проверку state
    - Автоматическое истечение TTL (по умолчанию 10 минут)
    - Хранение code_verifier для PKCE (Proof Key for Code Exchange)

    Attributes:
        id: Уникальный идентификатор записи (UUID)
        state: Уникальный идентификатор OAuth сессии (RFC 6749)
        code_verifier: Строка для PKCE (RFC 7636)
        provider: Имя провайдера (google, vk, github, etc.)
        redirect_uri: URI для редиректа после авторизации
        scope: Запрашиваемые разрешения (email, profile, etc.)
        user_id: ID пользователя (для привязки аккаунтов)
        is_linked: Флаг привязки аккаунта
        expires_at: Время истечения TTL
        created_at: Время создания записи
        updated_at: Время последнего обновления

    Индексы:
        - idx_oauth_state_state: Быстрый поиск по state (уникальный)
        - idx_oauth_state_user_id: Поиск состояний пользователя
        - idx_oauth_state_expires_at: Очистка истекших состояний
        - idx_oauth_state_user_id_expires_at: Составной индекс для удаления
    """

    __tablename__ = "oauth_states"

    # ==================== ПЕРВИЧНЫЙ КЛЮЧ ====================

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
        doc="Уникальный идентификатор записи (генерируется БД)",
    )

    # ==================== OAuth 2.0 ПОЛЯ ====================

    state: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        doc="Уникальный идентификатор OAuth сессии (RFC 6749)",
    )

    code_verifier: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Строка для PKCE (RFC 7636)",
    )

    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        doc="Имя провайдера: google, vk, github, etc.",
    )

    redirect_uri: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        doc="URI для редиректа после авторизации",
    )

    scope: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Запрашиваемые разрешения (email, profile, etc.)",
    )

    # ==================== СВЯЗЬ С ПОЛЬЗОВАТЕЛЕМ ====================

    user_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
        index=True,
        doc="ID пользователя (для привязки аккаунтов)",
    )

    is_linked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        doc="Флаг: true - привязка аккаунта, false - логин",
    )

    # ==================== ВРЕМЕННЫЕ ПОЛЯ ====================
    # created_at и updated_at наследуются из Base

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        doc="Время истечения TTL",
    )

    # ==================== ИНДЕКСЫ ====================

    __table_args__ = (
        # Составной индекс для метода delete_expired()
        Index(
            "idx_oauth_state_expires_at",
            "expires_at",
        ),
        # Составной индекс для метода delete_by_user_id()
        Index(
            "idx_oauth_state_user_id",
            "user_id",
        ),
        # Составной индекс для проверки активных состояний
        Index(
            "idx_oauth_state_user_id_expires_at",
            "user_id",
            "expires_at",
        ),
    )

    # ==================== МЕТОДЫ ====================

    def __repr__(self) -> str:
        """Строковое представление модели."""
        return (
            f"<OAuthState(id={self.id}, state={self.state[:8]}..., "
            f"provider={self.provider}, is_linked={self.is_linked})>"
        )

    def is_expired(self) -> bool:
        """
        Проверка, истек ли срок действия состояния.

        Returns:
            bool: True если состояние истекло
        """
        return self.expires_at < datetime.now(timezone.utc)

    @classmethod
    def generate_state(cls) -> str:
        """
        Генерация уникального state для OAuth 2.0.

        Returns:
            str: Случайный state длиной 32 символа
        """
        return secrets.token_urlsafe(32)

    @classmethod
    def generate_code_verifier(cls) -> str:
        """
        Генерация code_verifier для PKCE (RFC 7636).

        Returns:
            str: Случайный code_verifier длиной 64 символа
        """
        return secrets.token_urlsafe(64)

    @classmethod
    def create_login_state(
        cls,
        provider: str,
        redirect_uri: str,
        scope: Optional[str] = None,
        ttl_seconds: int = 600,
    ) -> Tuple["OAuthState", str, str]:
        """
        Фабричный метод для создания OAuth состояния логина.

        Args:
            provider: Имя провайдера
            redirect_uri: URI для редиректа
            scope: Запрашиваемые разрешения
            ttl_seconds: Время жизни в секундах (по умолчанию 600 = 10 минут)

        Returns:
            Tuple[OAuthState, str, str]: (Созданный объект, state, code_verifier)
        """
        state = cls.generate_state()
        code_verifier = cls.generate_code_verifier()
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        oauth_state = cls(
            state=state,
            code_verifier=code_verifier,
            provider=provider,
            redirect_uri=redirect_uri,
            scope=scope,
            is_linked=False,
            expires_at=expires_at,
        )

        return oauth_state, state, code_verifier

    @classmethod
    def create_link_state(
        cls,
        provider: str,
        redirect_uri: str,
        user_id: UUID,
        scope: Optional[str] = None,
        ttl_seconds: int = 600,
    ) -> Tuple["OAuthState", str, str]:
        """
        Фабричный метод для создания OAuth состояния привязки аккаунта.

        Args:
            provider: Имя провайдера
            redirect_uri: URI для редиректа
            user_id: ID пользователя для привязки
            scope: Запрашиваемые разрешения
            ttl_seconds: Время жизни в секундах (по умолчанию 600 = 10 минут)

        Returns:
            Tuple[OAuthState, str, str]: (Созданный объект, state, code_verifier)
        """
        state = cls.generate_state()
        code_verifier = cls.generate_code_verifier()
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        oauth_state = cls(
            state=state,
            code_verifier=code_verifier,
            provider=provider,
            redirect_uri=redirect_uri,
            scope=scope,
            user_id=user_id,
            is_linked=True,
            expires_at=expires_at,
        )

        return oauth_state, state, code_verifier