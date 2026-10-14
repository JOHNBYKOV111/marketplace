"""
Схемы Pydantic для аудит-логов.
"""

from typing import Optional, List
from uuid import UUID
from datetime import datetime

from pydantic import Field

from app.schemas.common import BaseSchema, UUIDSchema


class AuditLogBase(BaseSchema):
    """Базовая схема аудит-лога."""
    
    action: str = Field(..., description="Выполненное действие")
    success: bool = Field(default=True, description="Успешно ли выполнено действие")
    details: Optional[dict] = Field(default=None, description="Дополнительные детали")
    ip_address: Optional[str] = Field(None, description="IP-адрес пользователя")
    user_agent: Optional[str] = Field(None, description="User-Agent пользователя")


class AuditLogCreate(BaseSchema):
    """Схема для создания аудит-лога."""
    
    user_id: UUID = Field(..., description="ID пользователя")
    action: str = Field(..., description="Выполненное действие")
    success: bool = Field(default=True, description="Успешно ли выполнено действие")
    details: Optional[dict] = Field(default=None, description="Дополнительные детали")
    ip_address: Optional[str] = Field(None, description="IP-адрес пользователя")
    user_agent: Optional[str] = Field(None, description="User-Agent пользователя")


class AuditLogResponse(BaseSchema, UUIDSchema):
    """Схема ответа с аудит-логом."""
    
    user_id: Optional[UUID] = None
    action: str
    success: bool
    details: Optional[dict] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class AuditLogListResponse(BaseSchema):
    """Схема списка аудит-логов."""
    
    items: List[AuditLogResponse]
    total: int
    limit: int
    offset: int
    
    @classmethod
    def create(cls, items: List[AuditLogResponse], total: int, limit: int, offset: int) -> "AuditLogListResponse":
        """Создает пагинированный ответ с аудит-логами."""
        return cls(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )


class AuditActionsResponse(BaseSchema):
    """Схема ответа со списком доступных действий."""
    
    actions: List[str] = Field(..., description="Список доступных действий")
    
    def to_list(self) -> List[str]:
        """Преобразует ответ в список действий."""
        return self.actions
    
    @classmethod
    def from_actions(cls, actions: List[str]) -> "AuditActionsResponse":
        """Создает ответ из списка действий."""
        return cls(actions=actions)