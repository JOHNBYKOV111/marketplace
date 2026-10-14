"""
Схемы Pydantic для административных эндпоинтов.
"""

from typing import Optional
from uuid import UUID

from pydantic import Field, ConfigDict

from app.schemas.common import BaseSchema, MessageResponse
from app.schemas.user import UserResponse


class BlockRequest(BaseSchema):
    """Схема запроса на блокировку пользователя."""
    
    reason: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Причина блокировки",
    )


class UnblockRequest(BaseSchema):
    """Схема запроса на разблокировку пользователя."""
    
    reason: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Причина разблокировки",
    )


class AdminUserResponse(UserResponse):
    """Схема ответа с данными пользователя для админа."""
    
    password_hash: Optional[str] = Field(None, description="Хеш пароля (только для админа)")


class BlockResponse(MessageResponse):
    """Схема ответа на блокировку."""
    
    user_id: UUID = Field(..., description="ID заблокированного пользователя")


class UnblockResponse(MessageResponse):
    """Схема ответа на разблокировку."""
    
    user_id: UUID = Field(..., description="ID разблокированного пользователя")


class AdminMetricsResponse(BaseSchema):
    """Схема ответа с метриками системы."""
    
    total_users: int = Field(..., description="Общее количество пользователей")
    active_users: int = Field(..., description="Количество активных пользователей")
    blocked_users: int = Field(..., description="Количество заблокированных пользователей")
    verified_users: int = Field(..., description="Количество подтверждённых пользователей")
    superusers: int = Field(..., description="Количество администраторов")