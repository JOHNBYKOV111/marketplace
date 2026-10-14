"""
Схемы для аутентификации и управления сессиями.

Содержит Pydantic модели для:
- Запросов на аутентификацию (логин, refresh, logout)
- Ответов с токенами
- Верификации email и телефона
- Управления MFA
"""

from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict


class LoginRequest(BaseModel):
    """
    Запрос на аутентификацию.

    Поддерживает:
    - Обычный вход с email/паролем
    - MFA с TOTP кодом
    - Автоматическую нормализацию email
    - Валидацию форматов
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "password": "SecurePass123!",
                "totp_code": "123456",
            }
        }
    )

    email: EmailStr = Field(
        ...,
        description="Email пользователя",
        examples=["user@example.com"],
        max_length=255,
    )

    password: str = Field(
        ...,
        description="Пароль (от 8 до 128 символов)",
        min_length=8,
        max_length=128,
        examples=["SecurePass123!"],
    )

    totp_code: Optional[str] = Field(
        None,
        description="TOTP код (6 цифр, если включена двухфакторная аутентификация)",
        pattern=r"^\d{6}$",
        examples=["123456"],
    )

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        """Нормализация email (приведение к нижнему регистру)."""
        return v.lower().strip()


class LoginResponse(BaseModel):
    """
    Ответ на успешную аутентификацию.

    Содержит:
    - Access token для API запросов
    - Refresh token в HttpOnly cookie
    - Информацию о пользователе
    - Требования к MFA
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "bearer",
            "expires_in": 900,
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "email": "user@example.com",
            "is_email_verified": True,
            "requires_mfa": False,
        }
    })

    access_token: str = Field(
        ...,
        description="JWT access токен для API запросов",
    )

    token_type: str = Field(
        default="bearer",
        description="Тип токена (bearer)",
        examples=["bearer"],
    )

    expires_in: int = Field(
        ...,
        description="Время жизни access токена в секундах",
        ge=1,
        examples=[900],
    )

    user_id: UUID = Field(
        ...,
        description="ID пользователя",
    )

    email: str = Field(
        ...,
        description="Email пользователя",
        examples=["user@example.com"],
    )

    is_email_verified: bool = Field(
        default=False,
        description="Верифицирован ли email",
    )

    requires_mfa: bool = Field(
        default=False,
        description="Требуется ли MFA для полного доступа",
    )


class RefreshRequest(BaseModel):
    """
    Запрос на обновление access токена.

    Refresh token передается через HttpOnly cookie,
    поэтому тело запроса может быть пустым.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {}
    })


class RefreshResponse(BaseModel):
    """
    Ответ на обновление токена.

    Содержит новый access token.
    Refresh token обновляется автоматически (ротация)
    и возвращается в cookie.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "bearer",
            "expires_in": 900,
        }
    })

    access_token: str = Field(
        ...,
        description="Новый JWT access токен",
    )

    token_type: str = Field(
        default="bearer",
        description="Тип токена",
        examples=["bearer"],
    )

    expires_in: int = Field(
        ...,
        description="Время жизни access токена в секундах",
        ge=1,
        examples=[900],
    )


class LogoutRequest(BaseModel):
    """
    Запрос на выход.

    Тело запроса может быть пустым.
    Refresh token берется из cookie.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {}
    })


class LogoutResponse(BaseModel):
    """
    Ответ на выход.

    Подтверждает успешный выход.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "success": True,
            "message": "Successfully logged out",
            "revoked_tokens": 1,
        }
    })

    success: bool = Field(
        ...,
        description="Успешность операции",
    )

    message: str = Field(
        ...,
        description="Сообщение о результате",
        examples=["Successfully logged out"],
    )

    revoked_tokens: Optional[int] = Field(
        None,
        description="Количество отозванных токенов",
        ge=0,
    )


class VerifyEmailRequest(BaseModel):
    """
    Запрос на верификацию email.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        }
    })

    token: str = Field(
        ...,
        description="Токен верификации email (JWT)",
        min_length=20,
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."],
    )


class VerifyEmailResponse(BaseModel):
    """
    Ответ на верификацию email.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "success": True,
            "message": "Email successfully verified",
            "email": "user@example.com",
        }
    })

    success: bool = Field(
        ...,
        description="Успешность верификации",
    )

    message: str = Field(
        ...,
        description="Сообщение о результате",
        examples=["Email successfully verified"],
    )

    email: Optional[str] = Field(
        None,
        description="Верифицированный email",
        examples=["user@example.com"],
    )


class VerifyPhoneRequest(BaseModel):
    """
    Запрос на верификацию телефона.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "phone_number": "+79001234567",
            "code": "123456",
        }
    })

    phone_number: str = Field(
        ...,
        description="Номер телефона в международном формате",
        pattern=r"^\+[1-9]\d{1,14}$",
        examples=["+79001234567"],
        max_length=20,
    )

    code: str = Field(
        ...,
        description="Код верификации (6 цифр)",
        pattern=r"^\d{6}$",
        examples=["123456"],
    )

    @field_validator("phone_number")
    @classmethod
    def normalize_phone(cls, v: str) -> str:
        """Нормализация номера телефона."""
        # Удаляем все нецифровые символы, кроме +
        return v.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")


class VerifyPhoneResponse(BaseModel):
    """
    Ответ на верификацию телефона.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "success": True,
            "message": "Phone successfully verified",
            "phone_number": "+79001234567",
        }
    })

    success: bool = Field(
        ...,
        description="Успешность верификации",
    )

    message: str = Field(
        ...,
        description="Сообщение о результате",
        examples=["Phone successfully verified"],
    )

    phone_number: Optional[str] = Field(
        None,
        description="Верифицированный номер телефона",
        examples=["+79001234567"],
    )


class PasswordResetRequest(BaseModel):
    """
    Запрос на сброс пароля.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "email": "user@example.com",
        }
    })

    email: EmailStr = Field(
        ...,
        description="Email пользователя",
        examples=["user@example.com"],
        max_length=255,
    )

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        """Нормализация email."""
        return v.lower().strip()


class PasswordResetConfirmRequest(BaseModel):
    """
    Запрос на подтверждение сброса пароля.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "new_password": "NewSecurePass123!",
        }
    })

    token: str = Field(
        ...,
        description="Токен сброса пароля",
        min_length=20,
    )

    new_password: str = Field(
        ...,
        description="Новый пароль (от 8 до 128 символов)",
        min_length=8,
        max_length=128,
        examples=["NewSecurePass123!"],
    )


class MFAEnableRequest(BaseModel):
    """
    Запрос на включение MFA.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "totp_code": "123456",
        }
    })

    totp_code: str = Field(
        ...,
        description="TOTP код для подтверждения",
        pattern=r"^\d{6}$",
        examples=["123456"],
    )


class MFAEnableResponse(BaseModel):
    """
    Ответ на включение MFA.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "success": True,
            "message": "MFA enabled successfully",
            "totp_enabled": True,
            "backup_codes": ["1234567890", "0987654321"],
        }
    })

    success: bool = Field(
        ...,
        description="Успешность операции",
    )

    message: str = Field(
        ...,
        description="Сообщение о результате",
        examples=["MFA enabled successfully"],
    )

    totp_enabled: bool = Field(
        ...,
        description="Включен ли MFA",
    )

    backup_codes: Optional[List[str]] = Field(
        None,
        description="Резервные коды для восстановления доступа",
    )


class MFADisableRequest(BaseModel):
    """
    Запрос на отключение MFA.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "password": "SecurePass123!",
            "totp_code": "123456",
        }
    })

    password: str = Field(
        ...,
        description="Текущий пароль для подтверждения",
        min_length=8,
        max_length=128,
        examples=["SecurePass123!"],
    )

    totp_code: Optional[str] = Field(
        None,
        description="TOTP код (если включен)",
        pattern=r"^\d{6}$",
        examples=["123456"],
    )


class MFADisableResponse(BaseModel):
    """
    Ответ на отключение MFA.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "success": True,
            "message": "MFA disabled successfully",
            "totp_enabled": False,
        }
    })

    success: bool = Field(
        ...,
        description="Успешность операции",
    )

    message: str = Field(
        ...,
        description="Сообщение о результате",
        examples=["MFA disabled successfully"],
    )

    totp_enabled: bool = Field(
        ...,
        description="Включен ли MFA",
    )


class MFAInfoResponse(BaseModel):
    """
    Информация о MFA статусе.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "totp_enabled": True,
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "otpauth_url": "otpauth://totp/Marketplace:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Marketplace",
            "has_backup_codes": True,
        }
    })

    totp_enabled: bool = Field(
        ...,
        description="Включен ли MFA",
    )

    totp_secret: Optional[str] = Field(
        None,
        description="Секретный ключ TOTP (показывается только при первой настройке)",
    )

    otpauth_url: Optional[str] = Field(
        None,
        description="URL для настройки в приложении аутентификатора",
    )

    has_backup_codes: bool = Field(
        default=False,
        description="Есть ли резервные коды",
    )


class SessionInfo(BaseModel):
    """
    Информация о сессии.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "client_ip": "192.168.1.1",
            "user_agent": "Mozilla/5.0 ...",
            "created_at": "2024-01-01T00:00:00Z",
            "expires_at": "2024-01-08T00:00:00Z",
            "is_active": True,
        }
    })

    id: UUID = Field(
        ...,
        description="ID сессии",
    )

    user_id: UUID = Field(
        ...,
        description="ID пользователя",
    )

    client_ip: Optional[str] = Field(
        None,
        description="IP клиента",
    )

    user_agent: Optional[str] = Field(
        None,
        description="User-Agent",
    )

    created_at: datetime = Field(
        ...,
        description="Время создания",
    )

    expires_at: datetime = Field(
        ...,
        description="Время истечения",
    )

    is_active: bool = Field(
        default=True,
        description="Активна ли сессия",
    )


class SessionListResponse(BaseModel):
    """
    Список активных сессий.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "sessions": [
                {
                    "id": "...",
                    "user_id": "...",
                    "client_ip": "192.168.1.1",
                    "user_agent": "...",
                    "created_at": "2024-01-01T00:00:00Z",
                    "expires_at": "2024-01-08T00:00:00Z",
                    "is_active": True,
                }
            ],
            "total": 3,
            "limit": 20,
            "offset": 0,
        }
    })

    sessions: List[SessionInfo] = Field(
        ...,
        description="Список сессий",
    )

    total: int = Field(
        ...,
        description="Общее количество сессий",
        ge=0,
    )

    limit: int = Field(
        default=20,
        description="Лимит записей",
        ge=1,
        le=100,
    )

    offset: int = Field(
        default=0,
        description="Смещение",
        ge=0,
    )