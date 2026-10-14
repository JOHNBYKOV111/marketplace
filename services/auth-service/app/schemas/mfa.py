"""
MFA (Multi-Factor Authentication) схемы.

Содержит Pydantic модели для:
- TOTP setup, verify, disable
- SMS send, verify
- Email send, verify
- Универсальная MFA верификация при логине
- Резервные коды (получение, обновление)
- Ответы с токенами и метаданными

Связанные модули:
- app.routers.mfa - MFA роутер
- app.services.mfa_service - бизнес-логика MFA
"""

from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
import re


# ==================== ENUMS ====================

class MFAMethod(str, Enum):
    """Поддерживаемые методы двухфакторной аутентификации."""
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"


# ==================== REQUEST SCHEMAS ====================

class TOTPSetupRequest(BaseModel):
    """Запрос на генерацию TOTP секрета (без параметров)."""
    pass


class TOTPVerifyRequest(BaseModel):
    """Запрос на верификацию и активацию TOTP."""
    code: str = Field(
        ...,
        min_length=6,
        max_length=6,
        pattern=r"^\d{6}$",
        description="6-значный TOTP код",
        examples=["123456"],
    )

    @field_validator("code")
    @classmethod
    def validate_code_digits(cls, v: str) -> str:
        """Проверка что код состоит только из цифр."""
        if not v.isdigit():
            raise ValueError("TOTP code must contain only digits")
        if len(v) != 6:
            raise ValueError("TOTP code must be exactly 6 digits")
        return v


class TOTPDisableRequest(BaseModel):
    """Запрос на отключение TOTP (требует подтверждения паролем)."""
    password: str = Field(
        ...,
        min_length=1,
        description="Текущий пароль пользователя для подтверждения действия",
    )


class SMSSendRequest(BaseModel):
    """Запрос на отправку SMS кода (без параметров, телефон из профиля)."""
    pass


class SMSVerifyRequest(BaseModel):
    """Запрос на верификацию SMS кода и активацию SMS 2FA."""
    code: str = Field(
        ...,
        min_length=6,
        max_length=6,
        pattern=r"^\d{6}$",
        description="6-значный SMS код",
        examples=["123456"],
    )

    @field_validator("code")
    @classmethod
    def validate_code_digits(cls, v: str) -> str:
        """Проверка что код состоит только из цифр."""
        if not v.isdigit():
            raise ValueError("SMS code must contain only digits")
        if len(v) != 6:
            raise ValueError("SMS code must be exactly 6 digits")
        return v


class EmailSendRequest(BaseModel):
    """Запрос на отправку Email кода (без параметров, email из профиля)."""
    pass


class EmailVerifyRequest(BaseModel):
    """Запрос на верификацию Email кода и активацию Email 2FA."""
    code: str = Field(
        ...,
        min_length=6,
        max_length=6,
        pattern=r"^\d{6}$",
        description="6-значный Email код",
        examples=["654321"],
    )

    @field_validator("code")
    @classmethod
    def validate_code_digits(cls, v: str) -> str:
        """Проверка что код состоит только из цифр."""
        if not v.isdigit():
            raise ValueError("Email code must contain only digits")
        if len(v) != 6:
            raise ValueError("Email code must be exactly 6 digits")
        return v


class MFAVerifyRequest(BaseModel):
    """Универсальный запрос на проверку 2FA при логине."""
    mfa_session_id: str = Field(
        ...,
        min_length=1,
        description="Идентификатор MFA сессии",
    )
    code: str = Field(
        ...,
        min_length=6,
        max_length=6,
        pattern=r"^\d{6}$",
        description="6-значный код 2FA",
    )
    method: MFAMethod = Field(
        ...,
        description="Метод двухфакторной аутентификации",
    )

    @field_validator("code")
    @classmethod
    def validate_code_digits(cls, v: str) -> str:
        """Проверка что код состоит только из цифр."""
        if not v.isdigit():
            raise ValueError("2FA code must contain only digits")
        if len(v) != 6:
            raise ValueError("2FA code must be exactly 6 digits")
        return v


class BackupCodesRenewRequest(BaseModel):
    """Запрос на регенерацию резервных кодов (без параметров)."""
    pass


# ==================== RESPONSE SCHEMAS ====================

class TOTPSetupResponse(BaseModel):
    """Ответ с TOTP секретом и QR-кодом."""
    secret_key: str = Field(
        ...,
        description="TOTP секретный ключ (для ручного ввода)",
    )
    qr_code_url: str = Field(
        ...,
        description="URL для генерации QR-кода (otpauth:// формат)",
    )
    qr_code_base64: str = Field(
        ...,
        description="QR-код в формате base64 (для прямого отображения)",
    )


class TOTPVerifyResponse(BaseModel):
    """Ответ на успешную верификацию TOTP."""
    success: bool = Field(..., description="Статус операции")
    message: str = Field(
        default="TOTP enabled successfully",
        description="Сообщение о результате",
    )
    backup_codes: List[str] = Field(
        ...,
        description="Сгенерированные резервные коды (10 шт.)",
    )


class TOTPDisableResponse(BaseModel):
    """Ответ на отключение TOTP."""
    success: bool = Field(..., description="Статус операции")
    message: str = Field(
        default="TOTP disabled successfully",
        description="Сообщение о результате",
    )


class SMSSendResponse(BaseModel):
    """Ответ на отправку SMS кода."""
    success: bool = Field(..., description="Статус операции")
    method: str = Field(
        default="sms",
        description="Метод 2FA",
    )
    message: str = Field(
        default="SMS code sent successfully",
        description="Сообщение о результате",
    )
    expires_in: int = Field(
        default=300,
        description="Время жизни кода в секундах",
    )


class SMSVerifyResponse(BaseModel):
    """Ответ на успешную верификацию SMS."""
    success: bool = Field(..., description="Статус операции")
    message: str = Field(
        default="SMS 2FA enabled successfully",
        description="Сообщение о результате",
    )


class EmailSendResponse(BaseModel):
    """Ответ на отправку Email кода."""
    success: bool = Field(..., description="Статус операции")
    method: str = Field(
        default="email",
        description="Метод 2FA",
    )
    message: str = Field(
        default="Email code sent successfully",
        description="Сообщение о результате",
    )
    expires_in: int = Field(
        default=300,
        description="Время жизни кода в секундах",
    )


class EmailVerifyResponse(BaseModel):
    """Ответ на успешную верификацию Email."""
    success: bool = Field(..., description="Статус операции")
    message: str = Field(
        default="Email 2FA enabled successfully",
        description="Сообщение о результате",
    )


class MFAVerifyResponse(BaseModel):
    """Ответ на успешную универсальную проверку 2FA."""
    access_token: str = Field(
        ...,
        description="JWT access токен",
    )
    token_type: str = Field(
        default="bearer",
        description="Тип токена",
    )
    expires_in: int = Field(
        default=3600,
        description="Время жизни токена в секундах",
    )


class BackupCodesResponse(BaseModel):
    """Ответ с резервными кодами."""
    backup_codes: List[str] = Field(
        ...,
        description="Список резервных кодов",
    )


class BackupCodesRenewResponse(BaseModel):
    """Ответ на регенерацию резервных кодов."""
    success: bool = Field(..., description="Статус операции")
    backup_codes: List[str] = Field(
        ...,
        description="Новые резервные коды (старые аннулированы)",
    )
    message: str = Field(
        default="Backup codes regenerated successfully",
        description="Сообщение о результате",
    )


# ==================== ERROR RESPONSE SCHEMAS ====================

class MFAErrorResponse(BaseModel):
    """Стандартный ответ с ошибкой."""
    detail: str = Field(
        ...,
        description="Описание ошибки",
    )
    error_code: Optional[str] = Field(
        default=None,
        description="Код ошибки для машинной обработки",
    )


class MFARateLimitErrorResponse(BaseModel):
    """Ответ при превышении лимита запросов."""
    detail: str = Field(
        default="Too many requests. Please try again later.",
        description="Описание ошибки",
    )
    retry_after: Optional[int] = Field(
        default=None,
        description="Время в секундах до следующей попытки",
    )


class MFAUnauthorizedResponse(BaseModel):
    """Ответ при отсутствии авторизации."""
    detail: str = Field(
        default="Not authenticated",
        description="Описание ошибки",
    )


# ==================== COMMON RESPONSES (для документации) ====================

COMMON_RESPONSES = {
    401: {
        "model": MFAUnauthorizedResponse,
        "description": "Не авторизован - отсутствуют или неверные заголовки аутентификации",
    },
    429: {
        "model": MFARateLimitErrorResponse,
        "description": "Превышен лимит запросов (rate limit)",
    },
    500: {
        "model": MFAErrorResponse,
        "description": "Внутренняя ошибка сервера",
    },
}