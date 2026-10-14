"""
Общие схемы Pydantic для всего приложения.
"""

from typing import Optional, Generic, TypeVar, List, Dict, Any
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel, Field, ConfigDict


T = TypeVar('T')


class BaseSchema(BaseModel):
    """Базовая схема с общими полями."""
    
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        extra="ignore",
    )


class PaginationParams(BaseModel):
    """Параметры пагинации."""
    
    limit: int = Field(default=20, ge=1, le=100, description="Количество записей на странице")
    offset: int = Field(default=0, ge=0, description="Смещение от начала")
    

class PaginatedResponse(BaseModel, Generic[T]):
    """Ответ с пагинацией."""
    
    items: List[T]
    total: int
    limit: int
    offset: int
    
    @classmethod
    def create(cls, items: List[T], total: int, limit: int, offset: int) -> "PaginatedResponse[T]":
        """Создает пагинированный ответ."""
        return cls(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )


class MessageResponse(BaseModel):
    """Ответ с сообщением."""
    
    success: bool = True
    message: str
    details: Optional[dict] = None


class ErrorResponse(BaseModel):
    """Ответ с ошибкой."""
    
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None


class UUIDSchema(BaseModel):
    """Схема с UUID."""
    
    id: UUID
    created_at: datetime
    updated_at: datetime


# ==================== НОВАЯ ЛОГИКА ДЛЯ test_auth_routes.py ====================

class SuccessResponse(BaseModel):
    """
    Универсальный успешный ответ для API.

    Используется для эндпоинтов, которые возвращают только статус операции.
    """
    success: bool = Field(default=True, description="Успешность операции")
    message: str = Field(..., description="Сообщение о результате")
    data: Optional[Dict[str, Any]] = Field(None, description="Дополнительные данные")


class TokenResponse(BaseModel):
    """
    Ответ с токеном доступа.

    Используется для эндпоинтов аутентификации.
    """
    access_token: str = Field(..., description="JWT access токен")
    token_type: str = Field(default="bearer", description="Тип токена")
    expires_in: int = Field(..., description="Время жизни в секундах")
    refresh_token: Optional[str] = Field(None, description="Refresh токен (если передан в теле)")


class RefreshTokenResponse(BaseModel):
    """
    Ответ с новым access токеном.

    Используется для эндпоинта /refresh.
    """
    access_token: str = Field(..., description="Новый JWT access токен")
    token_type: str = Field(default="bearer", description="Тип токена")
    expires_in: int = Field(..., description="Время жизни в секундах")


class VerificationResponse(BaseModel):
    """
    Ответ на верификацию email или телефона.
    """
    success: bool = Field(..., description="Успешность верификации")
    message: str = Field(..., description="Сообщение о результате")
    verified: bool = Field(default=True, description="Подтверждено ли")


class LogoutResponse(BaseModel):
    """
    Ответ на выход из системы.
    """
    success: bool = Field(default=True, description="Успешность операции")
    message: str = Field(..., description="Сообщение о результате")
    revoked_tokens: Optional[int] = Field(None, description="Количество отозванных токенов")