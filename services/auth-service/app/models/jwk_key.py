"""
Модель для хранения JWK (JSON Web Key) ключей.

Используется для:
- Хранения асимметричных ключей (RSA, EC) для подписи JWT
- Ротации ключей (активные, истекшие)
- Поддержки нескольких активных ключей одновременно
- Безопасного хранения приватных ключей в зашифрованном виде

Связанные модули:
- app.repositories.jwk_key_repository - CRUD операции
- app.services.jwk_service - бизнес-логика работы с ключами
- app.core.security - подпись и верификация JWT
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Index, String, Text, Integer, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class JWKKey(Base):
    """
    Модель JWK ключа для подписи и верификации JWT токенов.

    Поддерживает:
    - Несколько активных ключей для плавной ротации
    - Автоматическое истечение срока действия
    - Шифрование приватных ключей (Vault или локальное)
    - Индексы для быстрого поиска активных ключей

    Attributes:
        id: Уникальный идентификатор ключа (UUID)
        kid: Key ID - уникальный идентификатор для JWK (RFC 7517)
        private_key_encrypted: Зашифрованный приватный ключ (PEM)
        public_key: Публичный ключ в формате PEM
        algorithm: Алгоритм подписи (RS256, RS384, RS512, ES256, ES384, ES512)
        key_type: Тип ключа (RSA, EC)
        is_active: Активен ли ключ для подписи новых токенов
        is_verification_enabled: Доступен ли ключ для верификации старых токенов
        expires_at: Время истечения срока действия ключа
        created_at: Время создания записи
        updated_at: Время последнего обновления
        activated_at: Время активации ключа
        rotated_at: Время ротации ключа
        created_by: Кто создал ключ
        activated_by: Кто активировал ключ
        rotated_by: Кто выполнил ротацию
        key_size: Размер ключа в битах
        key_metadata: Дополнительные метаданные

    Индексы:
        - idx_jwk_key_kid: Быстрый поиск по kid (уникальный)
        - idx_jwk_key_is_active: Фильтрация активных ключей
        - idx_jwk_key_expires_at: Очистка истекших ключей
        - idx_jwk_key_is_active_expires_at: Составной индекс для get_active_keys()
    """

    __tablename__ = "jwk_keys"

    # ==================== ПЕРВИЧНЫЙ КЛЮЧ ====================

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
        doc="Уникальный идентификатор ключа (генерируется БД)",
    )

    # ==================== ОСНОВНЫЕ ПОЛЯ ====================

    kid: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        doc="Key ID - уникальный идентификатор для JWK (RFC 7517)",
    )

    private_key_encrypted: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Зашифрованный приватный ключ в формате PEM",
    )

    public_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Публичный ключ в формате PEM",
    )

    algorithm: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        doc="Алгоритм подписи: RS256, RS384, RS512, ES256, ES384, ES512",
    )

    key_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        doc="Тип ключа: RSA, EC",
    )

    # ==================== СТАТУСЫ ====================

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        doc="Активен ли ключ для подписи новых токенов",
    )

    is_verification_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        doc="Доступен ли ключ для верификации старых токенов",
    )

    # ==================== ВРЕМЯ ЖИЗНИ ====================

    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        doc="Время истечения срока действия ключа",
    )

    activated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Время активации ключа",
    )

    rotated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Время ротации ключа",
    )

    # ==================== КТО ВЫПОЛНИЛ ОПЕРАЦИЮ ====================

    created_by: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Кто создал ключ (user_id или system)",
    )

    activated_by: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Кто активировал ключ",
    )

    rotated_by: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Кто выполнил ротацию",
    )

    # ==================== ДОПОЛНИТЕЛЬНЫЕ ДАННЫЕ ====================

    key_size: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        doc="Размер ключа в битах (для RSA: 2048/4096)",
    )

    key_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        Text,
        nullable=True,
        doc="Дополнительные метаданные в формате JSON",
    )

    # ==================== СЛУЖЕБНЫЕ ПОЛЯ ====================
    # created_at и updated_at наследуются из Base

    # ==================== ИНДЕКСЫ ====================

    __table_args__ = (
        # Составной индекс для метода get_active_keys()
        # is_active=True AND expires_at > now()
        Index(
            "idx_jwk_key_is_active_expires_at",
            "is_active",
            "expires_at",
            postgresql_where=(
                (is_active == True) & (expires_at > datetime.now(timezone.utc))
            ),
        ),
        # Частичный индекс для активных ключей
        Index(
            "idx_jwk_key_active_only",
            "is_active",
            postgresql_where=(is_active == True),
        ),
        # Частичный индекс для истекших ключей (для быстрой очистки)
        Index(
            "idx_jwk_key_expired_only",
            "expires_at",
            postgresql_where=(expires_at < datetime.now(timezone.utc)),
        ),
    )

    # ==================== МЕТОДЫ ====================

    def __repr__(self) -> str:
        """Строковое представление модели."""
        return (
            f"<JWKKey(id={self.id}, kid={self.kid}, "
            f"algorithm={self.algorithm}, is_active={self.is_active})>"
        )

    @property
    def is_expired(self) -> bool:
        """
        Проверка, истек ли срок действия ключа.

        Returns:
            bool: True если ключ истек или expires_at в прошлом
        """
        if self.expires_at is None:
            return False
        return self.expires_at < datetime.now(timezone.utc)

    @property
    def is_valid(self) -> bool:
        """
        Проверка, действителен ли ключ для использования.

        Ключ считается действительным если:
        - is_active == True
        - expires_at is None или expires_at > now

        Returns:
            bool: True если ключ активен и не истек
        """
        return self.is_active and not self.is_expired

    def activate(self, activated_by: Optional[str] = None) -> None:
        """
        Активация ключа.

        Args:
            activated_by: Кто активировал
        """
        self.is_active = True
        self.activated_at = datetime.now(timezone.utc)
        if activated_by:
            self.activated_by = activated_by

    def deactivate(self) -> None:
        """Деактивация ключа."""
        self.is_active = False

    def expire(self) -> None:
        """Помечаем ключ как истекший."""
        self.is_active = False

    def rotate(self, new_private_key: str, new_public_key: str, rotated_by: Optional[str] = None) -> None:
        """
        Ротация ключа (обновление криптографических материалов).

        Args:
            new_private_key: Новый зашифрованный приватный ключ
            new_public_key: Новый публичный ключ
            rotated_by: Кто выполнил ротацию
        """
        self.private_key_encrypted = new_private_key
        self.public_key = new_public_key
        self.is_active = False
        self.rotated_at = datetime.now(timezone.utc)
        if rotated_by:
            self.rotated_by = rotated_by

    def should_rotate(self, rotation_interval_days: int = 90) -> bool:
        """
        Проверка необходимости ротации ключа.

        Args:
            rotation_interval_days: Интервал ротации в днях

        Returns:
            bool: True если ключ нужно ротировать
        """
        if self.rotated_at:
            age = datetime.now(timezone.utc) - self.rotated_at
        else:
            age = datetime.now(timezone.utc) - self.created_at

        return age.days >= rotation_interval_days

    def get_jwks_public_data(self) -> Dict[str, Any]:
        """
        Получение публичных данных ключа в формате JWKS.

        Returns:
            Dict[str, Any]: Данные ключа в формате JWK
        """
        import json

        # Если public_key уже в формате JWK
        if self.public_key.startswith("{"):
            try:
                jwk_data = json.loads(self.public_key)
                jwk_data["kid"] = self.kid
                jwk_data["alg"] = self.algorithm
                jwk_data["use"] = "sig"
                return jwk_data
            except json.JSONDecodeError:
                pass

        # Если public_key в формате PEM — конвертируем
        # Для RSA возвращаем базовую структуру
        return {
            "kid": self.kid,
            "kty": self.key_type,
            "alg": self.algorithm,
            "use": "sig",
            "n": "TODO: extract_from_pem",  # Для RSA
            "e": "AQAB",  # Для RSA
        }

    def to_dict(self, include_private: bool = False) -> Dict[str, Any]:
        """
        Преобразование модели в словарь.

        Args:
            include_private: Включать приватный ключ

        Returns:
            Dict[str, Any]: Словарь с данными модели
        """
        data = {
            "id": str(self.id),
            "kid": self.kid,
            "key_type": self.key_type,
            "algorithm": self.algorithm,
            "is_active": self.is_active,
            "is_verification_enabled": self.is_verification_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotated_at": self.rotated_at.isoformat() if self.rotated_at else None,
            "key_size": self.key_size,
            "key_metadata": self.key_metadata,
        }

        if include_private:
            data["public_key"] = self.public_key
            data["private_key_encrypted"] = self.private_key_encrypted
            data["created_by"] = self.created_by
            data["activated_by"] = self.activated_by
            data["rotated_by"] = self.rotated_by

        return data

    @classmethod
    def create_rsa_key(
        cls,
        kid: str,
        private_key_encrypted: str,
        public_key: str,
        algorithm: str = "RS256",
        expires_days: int = 365,
        key_size: int = 2048,
        created_by: Optional[str] = None,
    ) -> "JWKKey":
        """
        Фабричный метод для создания RSA ключа.

        Args:
            kid: Key ID
            private_key_encrypted: Зашифрованный приватный ключ
            public_key: Публичный ключ
            algorithm: Алгоритм (RS256, RS384, RS512)
            expires_days: Срок действия в днях
            key_size: Размер ключа
            created_by: Кто создал

        Returns:
            JWKKey: Созданный ключ
        """
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

        return cls(
            kid=kid,
            private_key_encrypted=private_key_encrypted,
            public_key=public_key,
            algorithm=algorithm,
            key_type="RSA",
            expires_at=expires_at,
            is_active=False,
            is_verification_enabled=True,
            key_size=key_size,
            created_by=created_by,
            activated_at=None,
            activated_by=None,
            rotated_at=None,
            rotated_by=None,
        )

    @classmethod
    def create_ec_key(
        cls,
        kid: str,
        private_key_encrypted: str,
        public_key: str,
        algorithm: str = "ES256",
        expires_days: int = 365,
        key_size: int = 256,
        created_by: Optional[str] = None,
    ) -> "JWKKey":
        """
        Фабричный метод для создания EC ключа.

        Args:
            kid: Key ID
            private_key_encrypted: Зашифрованный приватный ключ
            public_key: Публичный ключ
            algorithm: Алгоритм (ES256, ES384, ES512)
            expires_days: Срок действия в днях
            key_size: Размер ключа
            created_by: Кто создал

        Returns:
            JWKKey: Созданный ключ
        """
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

        return cls(
            kid=kid,
            private_key_encrypted=private_key_encrypted,
            public_key=public_key,
            algorithm=algorithm,
            key_type="EC",
            expires_at=expires_at,
            is_active=False,
            is_verification_enabled=True,
            key_size=key_size,
            created_by=created_by,
            activated_at=None,
            activated_by=None,
            rotated_at=None,
            rotated_by=None,
        )