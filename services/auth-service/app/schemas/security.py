"""
Схемы Pydantic для безопасности и MFA.

Содержит модели для:
- Настройки двухфакторной аутентификации (TOTP)
- Управления MFA
- Резервных кодов
- Доверенных устройств
- Настроек безопасности
"""

from typing import Optional, List
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict

from app.schemas.common import BaseSchema


class MFAStatusResponse(BaseSchema):
    """
    Статус MFA пользователя.

    Используется в эндпоинте GET /security/mfa/status.
    """
    totp_enabled: bool = Field(..., description="Включена ли двухфакторная аутентификация")
    has_backup_codes: bool = Field(..., description="Есть ли резервные коды")
    is_setup_complete: bool = Field(..., description="Завершена ли настройка MFA")
    backup_codes_count: Optional[int] = Field(None, description="Количество резервных кодов")
    last_password_change: Optional[datetime] = Field(None, description="Дата последней смены пароля")


class MFAEnableRequest(BaseSchema):
    """
    Запрос на включение MFA.

    Используется в эндпоинте POST /security/mfa/verify.
    """
    totp_code: str = Field(
        ...,
        pattern=r"^\d{6}$",
        description="TOTP код для верификации (6 цифр)",
        examples=["123456"],
    )


class MFAEnableResponse(BaseSchema):
    """
    Ответ на включение MFA.

    Используется в эндпоинте POST /security/mfa/setup.
    """
    success: bool = Field(..., description="Успешность операции")
    message: str = Field(..., description="Сообщение о результате")
    secret: Optional[str] = Field(None, description="Секретный ключ TOTP (показывается один раз)")
    otpauth_url: Optional[str] = Field(None, description="URL для настройки в приложении-аутентификаторе")
    backup_codes: Optional[List[str]] = Field(None, description="Резервные коды (показываются один раз)")


class MFADisableRequest(BaseSchema):
    """
    Запрос на отключение MFA.

    Используется в эндпоинте POST /security/mfa/disable.
    """
    password: str = Field(..., description="Текущий пароль для подтверждения")
    totp_code: Optional[str] = Field(
        None,
        pattern=r"^\d{6}$",
        description="TOTP код для подтверждения (6 цифр)",
    )


class MFADisableResponse(BaseSchema):
    """
    Ответ на отключение MFA.
    """
    success: bool = Field(..., description="Успешность операции")
    message: str = Field(..., description="Сообщение о результате")


class MFAVerifyRequest(BaseSchema):
    """
    Запрос на верификацию MFA.

    Используется в эндпоинте POST /security/mfa/verify.
    """
    totp_code: str = Field(
        ...,
        pattern=r"^\d{6}$",
        description="TOTP код для верификации (6 цифр)",
        examples=["123456"],
    )


class MFAVerifyResponse(BaseSchema):
    """
    Ответ на верификацию MFA.
    """
    success: bool = Field(..., description="Успешность верификации")
    message: str = Field(..., description="Сообщение о результате")
    backup_codes: Optional[List[str]] = Field(None, description="Резервные коды (показываются один раз при первой настройке)")


class BackupCodesResponse(BaseSchema):
    """
    Ответ с резервными кодами.

    Используется в эндпоинте POST /security/mfa/backup-codes.
    """
    backup_codes: List[str] = Field(..., description="Список резервных кодов")
    message: str = Field(..., description="Сообщение о результате")


class TrustedDeviceRequest(BaseSchema):
    """
    Запрос на добавление доверенного устройства.
    """
    device_name: str = Field(..., max_length=100, description="Название устройства")
    device_type: str = Field(..., max_length=50, description="Тип устройства (mobile, desktop, tablet)")
    device_id: Optional[str] = Field(None, max_length=255, description="Уникальный ID устройства")


class TrustedDeviceResponse(BaseSchema):
    """
    Ответ с информацией о доверенном устройстве.
    """
    id: UUID = Field(..., description="ID устройства")
    user_id: UUID = Field(..., description="ID пользователя")
    device_name: str = Field(..., description="Название устройства")
    device_type: str = Field(..., description="Тип устройства")
    device_id: Optional[str] = Field(None, description="Уникальный ID устройства")
    is_active: bool = Field(..., description="Активно ли устройство")
    last_used_at: Optional[datetime] = Field(None, description="Дата последнего использования")
    created_at: datetime = Field(..., description="Дата добавления")
    expires_at: Optional[datetime] = Field(None, description="Дата истечения доверия")


class SecuritySettingsResponse(BaseSchema):
    """
    Настройки безопасности пользователя.

    Используется в эндпоинтах GET/PATCH /security/settings.
    """
    totp_enabled: bool = Field(..., description="Включена ли двухфакторная аутентификация")
    totp_secret: Optional[str] = Field(None, description="Секретный ключ TOTP")
    has_backup_codes: bool = Field(..., description="Есть ли резервные коды")
    last_password_change: Optional[datetime] = Field(None, description="Дата последней смены пароля")
    session_timeout_minutes: Optional[int] = Field(None, description="Таймаут сессии в минутах")
    trusted_devices: Optional[List[TrustedDeviceResponse]] = Field(None, description="Список доверенных устройств")


class SecuritySettingsUpdateRequest(BaseSchema):
    """
    Запрос на обновление настроек безопасности.
    """
    session_timeout_minutes: Optional[int] = Field(None, ge=5, le=1440, description="Таймаут сессии в минутах (от 5 до 1440)")
    max_sessions: Optional[int] = Field(None, ge=1, le=10, description="Максимальное количество одновременных сессий")


class MFAChallengeResponse(BaseSchema):
    """
    Ответ на создание MFA запроса.

    Используется в эндпоинте POST /security/mfa/challenge.
    """
    challenge_id: str = Field(..., description="ID MFA запроса")
    expires_in: int = Field(..., description="Время жизни запроса в секундах")
    message: str = Field(..., description="Сообщение для пользователя")