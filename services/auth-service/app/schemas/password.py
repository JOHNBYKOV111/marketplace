"""
Password схемы для управления паролями пользователей.

Содержит Pydantic модели для:
- Смена пароля авторизованным пользователем
- Запрос сброса пароля по email
- Подтверждение сброса пароля с токеном
- Ответы на все операции

Совместимость с тестами:
- TestChangePassword: ChangePasswordRequest (old_password, new_password)
- TestResetPasswordRequest: ResetPasswordRequest (email)
- TestResetPasswordConfirm: ResetPasswordConfirmRequest (token, new_password)
- TestPasswordValidationEdgeCases: валидация полей (missing fields, invalid formats)

Валидация паролей:
- Минимальная длина: PASSWORD_MIN_LENGTH (8)
- Максимальная длина: PASSWORD_MAX_LENGTH (128)
- Требования к сложности: заглавные, строчные, цифры, спецсимволы
- Проверка на отличие от старого пароля (на уровне роутера)

Связанные модули:
- app.routers.password - Password роутер
- app.services.password_service - бизнес-логика паролей
- app.core.config - настройки PASSWORD_*
"""

import re
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.config import settings


# ==================== REQUEST SCHEMAS ====================

class ChangePasswordRequest(BaseModel):
    """
    Запрос на смену пароля авторизованным пользователем.

    Используется в POST /password/change.

    Совместимость с тестами:
    - test_change_password_success: old_password="OldPass123!", new_password="NewPass456!@#"
    - test_change_password_invalid_old_password: old_password="WrongPass123!"
    - test_change_password_same_as_old: одинаковые пароли
    - test_change_password_invalid_new_password: new_password="weak" → 422
    - test_change_password_missing_fields: {} → 422
    """
    old_password: str = Field(
        ...,
        min_length=1,
        description="Текущий пароль пользователя",
        examples=["OldPass123!"],
    )
    new_password: str = Field(
        ...,
        min_length=settings.PASSWORD_MIN_LENGTH,
        max_length=settings.PASSWORD_MAX_LENGTH,
        description="Новый пароль (должен соответствовать требованиям сложности)",
        examples=["NewPass456!@#"],
    )

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """
        Проверка сложности нового пароля.

        Требования:
        - Минимум одна заглавная буква (A-Z)
        - Минимум одна строчная буква (a-z)
        - Минимум одна цифра (0-9)
        - Минимум один спецсимвол (!@#$%^&*()_+-=[]{}|;:,.<>?)

        Args:
            v: Новый пароль

        Returns:
            str: Валидированный пароль

        Raises:
            ValueError: Если пароль не соответствует требованиям
        """
        if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")

        if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")

        if settings.PASSWORD_REQUIRE_DIGITS and not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")

        if settings.PASSWORD_REQUIRE_SPECIAL_CHARS and not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", v):
            raise ValueError("Password must contain at least one special character")

        return v

    @field_validator("new_password")
    @classmethod
    def validate_not_common_password(cls, v: str) -> str:
        """
        Проверка что пароль не из списка распространённых.

        Args:
            v: Новый пароль

        Returns:
            str: Валидированный пароль
        """
        common_passwords = {
            "password", "password123", "12345678", "qwerty123",
            "admin123", "letmein123", "welcome123", "monkey123",
            "changeme123", "secret123", "P@ssw0rd", "Qwerty123!",
        }

        if v.lower() in common_passwords:
            raise ValueError("Password is too common. Please choose a stronger password")

        return v


class ResetPasswordRequest(BaseModel):
    """
    Запрос на сброс пароля по email.

    Используется в POST /password/reset-request.

    Совместимость с тестами:
    - test_reset_request_success_existing_user: email="user@example.com"
    - test_reset_request_non_existent_user: email="nonexistent@example.com"
    - test_reset_request_invalid_email: email="invalid-email" → 422
    - test_reset_request_missing_email: {} → 422
    """
    email: str = Field(
        ...,
        min_length=5,
        max_length=254,
        description="Email пользователя для отправки ссылки сброса",
        examples=["user@example.com"],
    )

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        """
        Проверка формата email.

        Должен содержать @ и домен с точкой.

        Args:
            v: Email адрес

        Returns:
            str: Валидированный email

        Raises:
            ValueError: Если формат email неверный
        """
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

        if not re.match(email_pattern, v):
            raise ValueError("Invalid email format")

        return v.lower().strip()


class ResetPasswordConfirmRequest(BaseModel):
    """
    Запрос на подтверждение сброса пароля.

    Используется в POST /password/reset-confirm.

    Совместимость с тестами:
    - test_reset_confirm_success: token="a"*32, new_password="NewPass456!@#"
    - test_reset_confirm_invalid_token: token="invalid_token"
    - test_reset_confirm_invalid_token_format: token="short" → 422
    - test_reset_confirm_invalid_new_password: new_password="weak" → 422
    - test_reset_confirm_missing_fields: {} → 422
    """
    token: str = Field(
        ...,
        min_length=settings.PASSWORD_RESET_TOKEN_LENGTH,
        max_length=256,
        description="Токен сброса пароля из email",
        examples=["a" * 32],
    )
    new_password: str = Field(
        ...,
        min_length=settings.PASSWORD_MIN_LENGTH,
        max_length=settings.PASSWORD_MAX_LENGTH,
        description="Новый пароль (должен соответствовать требованиям сложности)",
        examples=["NewPass456!@#"],
    )

    @field_validator("token")
    @classmethod
    def validate_token_format(cls, v: str) -> str:
        """
        Проверка формата токена сброса.

        Токен должен содержать только буквенно-цифровые символы,
        дефисы и подчёркивания (base64url-safe).

        Args:
            v: Токен сброса

        Returns:
            str: Валидированный токен

        Raises:
            ValueError: Если формат токена неверный
        """
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError("Invalid reset token format")

        return v

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """
        Проверка сложности нового пароля (такая же как в ChangePasswordRequest).

        Args:
            v: Новый пароль

        Returns:
            str: Валидированный пароль
        """
        if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")

        if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")

        if settings.PASSWORD_REQUIRE_DIGITS and not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")

        if settings.PASSWORD_REQUIRE_SPECIAL_CHARS and not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", v):
            raise ValueError("Password must contain at least one special character")

        return v


# ==================== RESPONSE SCHEMAS ====================

class ChangePasswordResponse(BaseModel):
    """
    Ответ на успешную смену пароля.

    Используется в POST /password/change.

    Совместимость с тестами:
    - test_change_password_success: success=True, "changed successfully" in message
    """
    success: bool = Field(
        default=True,
        description="Статус операции",
    )
    message: str = Field(
        default="Password changed successfully. All sessions have been revoked.",
        description="Сообщение о результате",
    )
    sessions_revoked: bool = Field(
        default=True,
        description="Флаг: все сессии отозваны",
    )
    timestamp: Optional[str] = Field(
        default=None,
        description="Время смены пароля в ISO 8601",
    )


class ResetPasswordResponse(BaseModel):
    """
    Ответ на запрос сброса пароля.

    Используется в POST /password/reset-request.

    Совместимость с тестами:
    - test_reset_request_success_existing_user: success=True, "reset link" in message
    - test_reset_request_non_existent_user: success=True (всегда одинаковый ответ)
    """
    success: bool = Field(
        default=True,
        description="Статус операции",
    )
    message: str = Field(
        default="If the email exists, a password reset link has been sent.",
        description="Сообщение о результате (одинаковое для существующих и несуществующих email)",
    )


class ResetPasswordConfirmResponse(BaseModel):
    """
    Ответ на успешное подтверждение сброса пароля.

    Используется в POST /password/reset-confirm.

    Совместимость с тестами:
    - test_reset_confirm_success: success=True, "reset successfully" in message
    """
    success: bool = Field(
        default=True,
        description="Статус операции",
    )
    message: str = Field(
        default="Password reset successfully. All sessions have been revoked.",
        description="Сообщение о результате",
    )
    sessions_revoked: bool = Field(
        default=True,
        description="Флаг: все сессии отозваны",
    )
    timestamp: Optional[str] = Field(
        default=None,
        description="Время сброса пароля в ISO 8601",
    )


# ==================== ERROR RESPONSE SCHEMAS ====================

class PasswordErrorResponse(BaseModel):
    """Стандартный ответ с ошибкой пароля."""
    detail: str = Field(
        ...,
        description="Описание ошибки",
    )
    error_code: Optional[str] = Field(
        default=None,
        description="Код ошибки для машинной обработки",
    )
    remaining_attempts: Optional[int] = Field(
        default=None,
        description="Оставшееся количество попыток",
    )


class PasswordRateLimitErrorResponse(BaseModel):
    """Ответ при превышении лимита попыток смены/сброса пароля."""
    detail: str = Field(
        default="Too many attempts. Please try again later.",
        description="Описание ошибки",
    )
    retry_after: Optional[int] = Field(
        default=None,
        description="Время в секундах до следующей попытки",
    )


class PasswordValidationErrorResponse(BaseModel):
    """Ответ при ошибке валидации пароля."""
    detail: str = Field(
        ...,
        description="Описание ошибки валидации",
    )
    requirements: Optional[list] = Field(
        default=None,
        description="Список требований к паролю",
    )


class PasswordUnauthorizedResponse(BaseModel):
    """Ответ при отсутствии авторизации."""
    detail: str = Field(
        default="Not authenticated",
        description="Описание ошибки",
    )


# ==================== COMMON RESPONSES (для документации) ====================

COMMON_PASSWORD_RESPONSES = {
    400: {
        "model": PasswordErrorResponse,
        "description": "Неверный запрос (неверный пароль, тот же пароль, истекший токен)",
    },
    401: {
        "model": PasswordUnauthorizedResponse,
        "description": "Не авторизован или неверный текущий пароль",
    },
    422: {
        "model": PasswordValidationErrorResponse,
        "description": "Ошибка валидации (слабый пароль, неверный формат email, короткий токен)",
    },
    429: {
        "model": PasswordRateLimitErrorResponse,
        "description": "Превышен лимит попыток",
    },
    500: {
        "model": PasswordErrorResponse,
        "description": "Внутренняя ошибка сервера",
    },
}