"""
Схемы Pydantic для пользователей.
"""

from typing import Optional, List
from uuid import UUID
from datetime import datetime
import hashlib

from pydantic import BaseModel, Field, EmailStr, ConfigDict

from app.schemas.common import BaseSchema, UUIDSchema


class UserBase(BaseSchema):
    """Базовая схема пользователя."""
    
    email: EmailStr = Field(..., description="Email пользователя")
    is_active: bool = Field(default=True, description="Активен ли пользователь")
    is_email_verified: bool = Field(default=False, description="Подтвержден ли email")
    is_superuser: bool = Field(default=False, description="Является ли администратором")


class UserCreate(BaseSchema):
    """Схема для создания пользователя."""
    
    email: EmailStr = Field(..., description="Email пользователя")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Пароль пользователя",
    )


class UserUpdate(BaseSchema):
    """Схема для обновления пользователя."""
    
    email: Optional[EmailStr] = Field(None, description="Новый email")
    password: Optional[str] = Field(
        None,
        min_length=8,
        max_length=128,
        description="Новый пароль",
    )
    is_active: Optional[bool] = Field(None, description="Статус активности")
    is_email_verified: Optional[bool] = Field(None, description="Статус подтверждения email")
    is_superuser: Optional[bool] = Field(None, description="Статус администратора")


class UserResponse(BaseSchema, UUIDSchema):
    """Схема ответа с данными пользователя."""
    
    email: str
    is_active: bool
    is_email_verified: bool
    is_superuser: bool
    email_hash: Optional[str] = Field(None, description="Хеш email для безопасного отображения")
    
    @classmethod
    def from_orm(cls, user):
        """Преобразует ORM модель в схему."""
        email_hash = hashlib.sha256(user.email.encode()).hexdigest()[:16] if user.email else None
        
        return cls(
            id=user.id,
            email=user.email,
            is_active=user.is_active,
            is_email_verified=user.is_email_verified,
            is_superuser=user.is_superuser,
            email_hash=email_hash,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )


class UserListResponse(BaseModel):
    """Схема списка пользователей."""
    
    items: list[UserResponse]
    total: int
    limit: int
    offset: int


# ==================== СХЕМЫ ДЛЯ РОУТЕРА USER ====================

class UserProfileResponse(BaseSchema):
    """
    Схема профиля пользователя для ответа API.
    
    Используется в эндпоинте GET /users/me.
    """
    id: UUID = Field(..., description="ID пользователя")
    email: str = Field(..., description="Email пользователя")
    username: Optional[str] = Field(None, description="Имя пользователя")
    is_active: bool = Field(..., description="Активен ли пользователь")
    is_email_verified: bool = Field(..., description="Подтвержден ли email")
    is_superuser: bool = Field(..., description="Является ли администратором")
    created_at: datetime = Field(..., description="Дата создания")
    updated_at: datetime = Field(..., description="Дата обновления")
    last_login_at: Optional[datetime] = Field(None, description="Дата последнего входа")


class UserUpdateRequest(BaseSchema):
    """
    Запрос на обновление профиля пользователя.
    
    Используется в эндпоинте PATCH /users/me.
    """
    email: Optional[EmailStr] = Field(None, description="Новый email")
    username: Optional[str] = Field(None, max_length=100, description="Новое имя пользователя")
    is_active: Optional[bool] = Field(None, description="Статус активности")


class PasswordChangeRequest(BaseSchema):
    """
    Запрос на смену пароля.
    
    Используется в эндпоинте POST /users/me/change-password.
    """
    current_password: str = Field(..., description="Текущий пароль")
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Новый пароль",
    )


class SessionInfoResponse(BaseSchema):
    """
    Информация о сессии пользователя.
    
    Используется в эндпоинте GET /users/me/sessions.
    """
    id: UUID = Field(..., description="ID сессии")
    user_id: UUID = Field(..., description="ID пользователя")
    client_ip: Optional[str] = Field(None, description="IP клиента")
    user_agent: Optional[str] = Field(None, description="User-Agent")
    created_at: datetime = Field(..., description="Дата создания")
    expires_at: datetime = Field(..., description="Дата истечения")
    is_active: bool = Field(..., description="Активна ли сессия")
    last_used_at: Optional[datetime] = Field(None, description="Дата последнего использования")


class SessionListResponse(BaseSchema):
    """
    Список активных сессий пользователя.
    
    Используется в эндпоинте GET /users/me/sessions.
    """
    sessions: List[SessionInfoResponse] = Field(..., description="Список сессий")
    total: int = Field(..., description="Общее количество сессий")


class DeleteAccountRequest(BaseSchema):
    """
    Запрос на удаление аккаунта.
    
    Используется в эндпоинте DELETE /users/me.
    """
    password: str = Field(..., description="Пароль для подтверждения")


class DeleteAccountResponse(BaseSchema):
    """
    Ответ на удаление аккаунта.
    
    Используется в эндпоинте DELETE /users/me.
    """
    success: bool = Field(..., description="Успешность операции")
    message: str = Field(..., description="Сообщение о результате")
    user_id: UUID = Field(..., description="ID удаленного пользователя")