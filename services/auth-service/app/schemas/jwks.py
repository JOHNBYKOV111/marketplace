"""
Pydantic схемы для JWKS (JSON Web Key Set) эндпоинтов.

Используются для:
- Валидации запросов на ротацию ключей
- Форматирования ответов с JWK ключами
- Сериализации метрик и статистики
- Документирования API

Связанные модули:
- app.models.jwk_key - модель JWKKey
- app.services.jwk_service - бизнес-логика
- app.routers.jwks - эндпоинты
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ==================== БАЗОВЫЕ СХЕМЫ ====================

class BaseJWKSchema(BaseModel):
    """Базовая схема для JWKS с общими настройками."""
    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore",
        json_encoders={
            datetime: lambda v: v.isoformat() if v else None,
        },
    )


# ==================== ПУБЛИЧНЫЕ JWKS ====================

class JWKPublicData(BaseJWKSchema):
    """
    Публичные данные ключа в формате JWK (RFC 7517).

    Используется для ответа на /.well-known/jwks.json
    """
    kid: str = Field(..., description="Key ID - уникальный идентификатор ключа")
    kty: str = Field(..., description="Key Type: RSA, EC")
    alg: str = Field(..., description="Algorithm: RS256, ES256, etc.")
    use: str = Field(default="sig", description="Key usage: sig")
    n: Optional[str] = Field(None, description="RSA modulus (base64url)")
    e: Optional[str] = Field(None, description="RSA public exponent (base64url)")
    crv: Optional[str] = Field(None, description="Elliptic curve name")
    x: Optional[str] = Field(None, description="EC x coordinate (base64url)")
    y: Optional[str] = Field(None, description="EC y coordinate (base64url)")

    @field_validator("use")
    @classmethod
    def validate_use(cls, v: str) -> str:
        """Валидация использования ключа."""
        if v not in ["sig", "enc"]:
            raise ValueError("use must be 'sig' or 'enc'")
        return v


class JWKSResponse(BaseJWKSchema):
    """
    Ответ JWKS (JSON Web Key Set).

    Возвращается по адресу /.well-known/jwks.json
    """
    keys: List[JWKPublicData] = Field(
        default_factory=list,
        description="Список публичных ключей",
    )


# ==================== АДМИНСКИЕ СХЕМЫ ====================

class JWKKeyResponse(BaseJWKSchema):
    """
    Полная информация о JWK ключе (для админа).

    Используется в GET /admin/jwks/keys и /admin/jwks/keys/active
    """
    id: UUID = Field(..., description="Уникальный идентификатор ключа")
    kid: str = Field(..., description="Key ID")
    key_type: str = Field(..., description="Тип ключа: RSA, EC")
    algorithm: str = Field(..., description="Алгоритм подписи")
    is_active: bool = Field(..., description="Активен ли ключ")
    is_verification_enabled: bool = Field(
        default=True,
        description="Доступен для верификации",
    )
    is_expired: bool = Field(default=False, description="Истек ли ключ")
    created_at: datetime = Field(..., description="Время создания")
    activated_at: Optional[datetime] = Field(None, description="Время активации")
    expires_at: Optional[datetime] = Field(None, description="Время истечения")
    rotated_at: Optional[datetime] = Field(None, description="Время ротации")
    key_size: Optional[int] = Field(None, description="Размер ключа в битах")
    created_by: Optional[str] = Field(None, description="Кто создал")
    activated_by: Optional[str] = Field(None, description="Кто активировал")
    rotated_by: Optional[str] = Field(None, description="Кто выполнил ротацию")
    key_metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Дополнительные метаданные",
    )

    @field_validator("key_type")
    @classmethod
    def validate_key_type(cls, v: str) -> str:
        """Валидация типа ключа."""
        if v not in ["RSA", "EC"]:
            raise ValueError("key_type must be 'RSA' or 'EC'")
        return v

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        """Валидация алгоритма."""
        allowed = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
        if v not in allowed:
            raise ValueError(f"algorithm must be one of {allowed}")
        return v


class JWKKeyListResponse(BaseJWKSchema):
    """
    Список JWK ключей.

    Используется в GET /admin/jwks/keys и /admin/jwks/keys/active
    """
    items: List[JWKKeyResponse] = Field(..., description="Список ключей")
    total: int = Field(..., description="Общее количество")


# ==================== РОТАЦИЯ КЛЮЧЕЙ ====================

class RotateKeysRequest(BaseJWKSchema):
    """
    Запрос на ротацию ключей.

    Используется в POST /admin/jwks/rotate
    """
    algorithm: str = Field(
        default="RS256",
        description="Алгоритм для нового ключа: RS256, RS384, RS512, ES256, ES384, ES512",
        pattern="^(RS256|RS384|RS512|ES256|ES384|ES512)$",
    )
    key_size: int = Field(
        default=2048,
        ge=2048,
        le=4096,
        description="Размер ключа в битах (для RSA: 2048-4096)",
    )
    grace_period_hours: int = Field(
        default=24,
        ge=1,
        le=168,
        description="Grace period для старого ключа (часы)",
    )
    rotated_by: Optional[str] = Field(
        None,
        description="Кто выполняет ротацию (user_id или system)",
    )

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        """Валидация алгоритма."""
        allowed = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
        if v not in allowed:
            raise ValueError(f"algorithm must be one of {allowed}")
        return v

    @field_validator("key_size")
    @classmethod
    def validate_key_size(cls, v: int) -> int:
        """Валидация размера ключа."""
        if v < 2048 or v > 4096:
            raise ValueError("key_size must be between 2048 and 4096")
        if v % 2 != 0:
            raise ValueError("key_size must be even")
        return v


class RotateKeysResponse(BaseJWKSchema):
    """
    Ответ на ротацию ключей.

    Используется в POST /admin/jwks/rotate
    """
    success: bool = Field(default=True, description="Успешность операции")
    new_kid: str = Field(..., description="Key ID нового ключа")
    expires_at: datetime = Field(..., description="Время истечения нового ключа")
    message: str = Field(
        default="Keys rotated successfully",
        description="Сообщение о результате",
    )


# ==================== АКТИВАЦИЯ / ДЕАКТИВАЦИЯ ====================

class ActivateKeyResponse(BaseJWKSchema):
    """
    Ответ на активацию ключа.

    Используется в POST /admin/jwks/keys/{kid}/activate
    """
    success: bool = Field(default=True, description="Успешность операции")
    kid: str = Field(..., description="Key ID активированного ключа")
    message: str = Field(
        default="Key activated successfully",
        description="Сообщение о результате",
    )


class DeactivateKeyResponse(BaseJWKSchema):
    """
    Ответ на деактивацию ключа.

    Используется в POST /admin/jwks/keys/{kid}/deactivate
    """
    success: bool = Field(default=True, description="Успешность операции")
    kid: str = Field(..., description="Key ID деактивированного ключа")
    message: str = Field(
        default="Key deactivated successfully",
        description="Сообщение о результате",
    )


# ==================== ОЧИСТКА ====================

class CleanupExpiredResponse(BaseJWKSchema):
    """
    Ответ на очистку истекших ключей.

    Используется в DELETE /admin/jwks/keys/expired
    """
    success: bool = Field(default=True, description="Успешность операции")
    deleted_count: int = Field(..., description="Количество удаленных ключей")
    message: str = Field(
        default="Expired keys cleaned up successfully",
        description="Сообщение о результате",
    )


# ==================== МЕТРИКИ ====================

class JWKSMetricsResponse(BaseJWKSchema):
    """
    Метрики JWKS.

    Используется в GET /admin/jwks/metrics
    """
    active_keys: int = Field(..., description="Количество активных ключей")
    expired_keys: int = Field(..., description="Количество истекших ключей")
    total_keys: int = Field(..., description="Общее количество ключей")
    keys_by_algorithm: Dict[str, int] = Field(
        default_factory=dict,
        description="Распределение ключей по алгоритмам",
    )
    grace_period_hours: int = Field(
        default=24,
        description="Grace period для старых ключей",
    )
    algorithm: str = Field(
        default="RS256",
        description="Текущий алгоритм по умолчанию",
    )
    cache_hit: bool = Field(
        default=False,
        description="Был ли использован кэш",
    )


# ==================== ОШИБКИ ====================

class JWKSErrorResponse(BaseJWKSchema):
    """
    Структура ответа с ошибкой.
    """
    error: str = Field(..., description="Код ошибки")
    message: str = Field(..., description="Сообщение об ошибке")
    details: Optional[Dict[str, Any]] = Field(None, description="Детали ошибки")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(),
        description="Время ошибки",
    )


# ==================== DEPRECATED / АЛИАСЫ ====================

# Для обратной совместимости с тестами
JWKKeyData = JWKKeyResponse
JWKKeyList = JWKKeyListResponse
RotateKeysRequestData = RotateKeysRequest
RotateKeysResponseData = RotateKeysResponse
ActivateKeyResponseData = ActivateKeyResponse
DeactivateKeyResponseData = DeactivateKeyResponse
CleanupExpiredResponseData = CleanupExpiredResponse
JWKSMetricsResponseData = JWKSMetricsResponse