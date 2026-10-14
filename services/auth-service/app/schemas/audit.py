"""
Схемы для аудит-логов.

Содержит Pydantic модели для:
- Представления аудит-логов в ответах API
- Валидации запросов на экспорт и очистку
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class AuditLogResponse(BaseModel):
    """
    Схема аудит-лога для ответа API.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "action": "LOGIN",
                "success": True,
                "details": {"client": "web"},
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0",
                "error_message": None,
                "created_at": "2024-01-01T00:00:00Z",
            }
        },
    )

    id: UUID = Field(..., description="Уникальный идентификатор записи")
    user_id: UUID = Field(..., description="ID пользователя")
    action: str = Field(..., description="Выполненное действие")
    success: bool = Field(..., description="Успешность операции")
    details: Optional[Dict[str, Any]] = Field(None, description="Дополнительные детали")
    ip_address: Optional[str] = Field(None, description="IP-адрес")
    user_agent: Optional[str] = Field(None, description="User-Agent")
    error_message: Optional[str] = Field(None, description="Сообщение об ошибке")
    created_at: datetime = Field(..., description="Время создания")


class AuditLogListResponse(BaseModel):
    """
    Список аудит-логов с пагинацией.
    """

    model_config = ConfigDict(from_attributes=True)

    items: List[AuditLogResponse] = Field(..., description="Список логов")
    total: int = Field(..., description="Общее количество записей", ge=0)
    limit: int = Field(..., description="Лимит записей на странице", ge=1, le=200)
    offset: int = Field(..., description="Смещение от начала", ge=0)


class AuditStatisticsResponse(BaseModel):
    """
    Статистика по аудит-логам.
    """

    model_config = ConfigDict(from_attributes=True)

    total_actions: int = Field(..., description="Общее количество действий", ge=0)
    successful_actions: int = Field(..., description="Количество успешных действий", ge=0)
    failed_actions: int = Field(..., description="Количество неудачных действий", ge=0)
    unique_users: int = Field(..., description="Количество уникальных пользователей", ge=0)
    top_actions: List[Dict[str, Any]] = Field(default_factory=list, description="Топ действий")
    by_date: List[Dict[str, Any]] = Field(default_factory=list, description="Статистика по датам")
    period_days: int = Field(..., description="Период в днях", ge=1)


class AuditActionListResponse(BaseModel):
    """
    Список доступных действий аудита.
    """

    model_config = ConfigDict(from_attributes=True)

    actions: List[str] = Field(..., description="Список уникальных действий")
    total: int = Field(..., description="Общее количество действий", ge=0)


class AuditExportRequest(BaseModel):
    """
    Запрос на экспорт аудит-логов.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "action": "LOGIN",
                "from_date": "2024-01-01T00:00:00Z",
                "to_date": "2024-01-31T23:59:59Z",
                "format": "json",
                "limit": 1000,
            }
        }
    )

    user_id: Optional[UUID] = Field(None, description="ID пользователя для фильтрации")
    action: Optional[str] = Field(None, description="Действие для фильтрации", max_length=100)
    from_date: Optional[datetime] = Field(None, description="Дата начала")
    to_date: Optional[datetime] = Field(None, description="Дата окончания")
    success: Optional[bool] = Field(None, description="Успешность операции")
    format: str = Field(default="json", description="Формат экспорта (json или csv)", pattern="^(json|csv)$")
    limit: int = Field(default=1000, description="Максимальное количество записей", ge=1, le=10000)


class AuditExportResponse(BaseModel):
    """
    Ответ на экспорт аудит-логов.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "data": "[{...}]",
                "format": "json",
                "total_records": 150,
                "exported_records": 150,
                "file_name": "audit_logs_2024-01-01T00:00:00.json",
            }
        }
    )

    data: str = Field(..., description="Экспортированные данные")
    format: str = Field(..., description="Формат данных", pattern="^(json|csv)$")
    total_records: int = Field(..., description="Общее количество записей", ge=0)
    exported_records: int = Field(..., description="Количество экспортированных записей", ge=0)
    file_name: str = Field(..., description="Имя файла для скачивания")


class AuditCleanupRequest(BaseModel):
    """
    Запрос на очистку старых аудит-логов.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "days": 90,
                "batch_size": 1000,
            }
        }
    )

    days: int = Field(default=90, description="Срок хранения в днях", ge=30, le=365)
    batch_size: int = Field(default=1000, description="Размер батча для удаления", ge=100, le=10000)


class AuditCleanupResponse(BaseModel):
    """
    Ответ на очистку аудит-логов.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": True,
                "message": "Cleaned up 150 audit logs",
                "deleted_count": 150,
                "days_retained": 90,
            }
        }
    )

    success: bool = Field(..., description="Успешность операции")
    message: str = Field(..., description="Сообщение о результате")
    deleted_count: int = Field(..., description="Количество удаленных записей", ge=0)
    days_retained: int = Field(..., description="Срок хранения в днях", ge=1)