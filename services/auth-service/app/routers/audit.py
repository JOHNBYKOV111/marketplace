"""
Аудит-логи для отслеживания действий пользователей и администраторов.

Обеспечивает:
- Запись всех критических действий в системе
- Хранение истории изменений
- Просмотр логов аудита
- Фильтрацию по пользователю, действию, дате
- Экспорт логов
- Автоматическую ротацию
"""

from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.responses import JSONResponse, StreamingResponse
import csv
import io

from app.core.database import get_db
from app.core.debug import LoggingRoute
from app.core.dependencies import get_current_admin
from app.core.logging import get_logger
from app.core.metrics import business_metrics
from app.schemas.audit_log import (
    AuditLogResponse,
    AuditLogListResponse,
    AuditActionsResponse,
    AuditLogExportResponse,
    AuditLogStatsResponse,
)
from app.services.audit_service import AuditService
from app.models.user import User

logger = get_logger(__name__)
router = APIRouter(route_class=LoggingRoute, prefix="/audit-logs", tags=["audit"])


# ==================== ПОЛУЧЕНИЕ ЛОГОВ ====================

@router.get(
    "/",
    response_model=AuditLogListResponse,
    summary="Получение логов аудита",
    description="Возвращает логи аудита с фильтрацией и пагинацией",
)
async def get_audit_logs(
    request: Request,
    admin: User = Depends(get_current_admin),
    user_id: Optional[UUID] = Query(None, description="Фильтр по пользователю"),
    action: Optional[str] = Query(None, description="Фильтр по действию"),
    success: Optional[bool] = Query(None, description="Фильтр по успешности"),
    limit: int = Query(20, ge=1, le=100, description="Количество записей"),
    offset: int = Query(0, ge=0, description="Смещение"),
    session: AsyncSession = Depends(get_db),
) -> AuditLogListResponse:
    """
    Получение логов аудита с фильтрацией.
    
    Args:
        request: FastAPI Request
        admin: Текущий администратор
        user_id: Фильтр по пользователю
        action: Фильтр по действию
        success: Фильтр по успешности
        limit: Количество записей
        offset: Смещение
        session: Сессия БД
    
    Returns:
        AuditLogListResponse: Список логов и общее количество
    """
    audit_service = AuditService(session)
    
    logs = await audit_service.get_all_logs(
        user_id=user_id,
        action=action,
        success=success,
        limit=limit,
        offset=offset,
    )
    
    total = await audit_service.get_all_logs_count(
        user_id=user_id,
        action=action,
        success=success,
    )
    
    logger.debug(f"Admin {admin.id} retrieved {len(logs)} audit logs")
    
    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(log) for log in logs],
        total=total,
        limit=limit,
        offset=offset,
        next_offset=offset + limit if offset + limit < total else None,
    )


# ==================== СПИСОК ДЕЙСТВИЙ ====================

@router.get(
    "/actions",
    response_model=AuditActionsResponse,
    summary="Список действий",
    description="Возвращает список уникальных действий в аудит-логах",
)
async def get_audit_actions(
    request: Request,
    admin: User = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db),
) -> AuditActionsResponse:
    """
    Получение списка уникальных действий.
    
    Args:
        request: FastAPI Request
        admin: Текущий администратор
        session: Сессия БД
    
    Returns:
        AuditActionsResponse: Список действий
    """
    audit_service = AuditService(session)
    actions = await audit_service.get_actions()
    
    return AuditActionsResponse(actions=actions, count=len(actions))


# ==================== ЛОГИ ПОЛЬЗОВАТЕЛЯ ====================

@router.get(
    "/user/{user_id}",
    response_model=AuditLogListResponse,
    summary="Логи пользователя",
    description="Возвращает логи аудита для конкретного пользователя",
)
async def get_user_audit_logs(
    user_id: UUID,
    request: Request,
    admin: User = Depends(get_current_admin),
    limit: int = Query(20, ge=1, le=100, description="Количество записей"),
    offset: int = Query(0, ge=0, description="Смещение"),
    session: AsyncSession = Depends(get_db),
) -> AuditLogListResponse:
    """
    Получение логов аудита пользователя.
    
    Args:
        user_id: UUID пользователя
        request: FastAPI Request
        admin: Текущий администратор
        limit: Количество записей
        offset: Смещение
        session: Сессия БД
    
    Returns:
        AuditLogListResponse: Список логов и общее количество
    """
    audit_service = AuditService(session)
    
    logs = await audit_service.get_user_logs(
        user_id=user_id,
        limit=limit,
        offset=offset,
    )
    
    total = await audit_service.get_user_logs_count(user_id)
    
    logger.debug(f"Admin {admin.id} retrieved logs for user {user_id}")
    
    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(log) for log in logs],
        total=total,
        limit=limit,
        offset=offset,
    )


# ==================== СТАТИСТИКА ЛОГОВ ====================

@router.get(
    "/stats",
    response_model=AuditLogStatsResponse,
    summary="Статистика логов",
    description="Возвращает статистику по аудит-логам",
)
async def get_audit_stats(
    request: Request,
    admin: User = Depends(get_current_admin),
    days: int = Query(7, ge=1, le=90, description="Количество дней для статистики"),
    session: AsyncSession = Depends(get_db),
) -> AuditLogStatsResponse:
    """
    Получение статистики по аудит-логам.
    
    Args:
        request: FastAPI Request
        admin: Текущий администратор
        days: Количество дней для статистики
        session: Сессия БД
    
    Returns:
        AuditLogStatsResponse: Статистика
    """
    audit_service = AuditService(session)
    
    from_date = datetime.now() - timedelta(days=days)
    stats = await audit_service.get_statistics(from_date=from_date)
    
    return AuditLogStatsResponse(
        total_logs=stats.get("total_logs", 0),
        success_count=stats.get("success_count", 0),
        failure_count=stats.get("failure_count", 0),
        unique_users=stats.get("unique_users", 0),
        unique_actions=stats.get("unique_actions", 0),
        logs_by_day=stats.get("logs_by_day", []),
        logs_by_action=stats.get("logs_by_action", []),
        period_days=days,
    )


# ==================== ЭКСПОРТ ЛОГОВ ====================

@router.get(
    "/export",
    response_model=AuditLogExportResponse,
    summary="Экспорт логов",
    description="Экспортирует логи аудита в CSV или JSON формате",
)
async def export_audit_logs(
    request: Request,
    admin: User = Depends(get_current_admin),
    format: str = Query("csv", regex="^(csv|json)$", description="Формат экспорта"),
    user_id: Optional[UUID] = Query(None, description="Фильтр по пользователю"),
    action: Optional[str] = Query(None, description="Фильтр по действию"),
    limit: int = Query(1000, ge=1, le=10000, description="Максимальное количество записей"),
    session: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Экспорт логов аудита в CSV или JSON.
    
    Args:
        request: FastAPI Request
        admin: Текущий администратор
        format: Формат экспорта (csv или json)
        user_id: Фильтр по пользователю
        action: Фильтр по действию
        limit: Максимальное количество записей
        session: Сессия БД
    
    Returns:
        JSONResponse: Данные в выбранном формате
    """
    audit_service = AuditService(session)
    
    # Получаем логи с фильтрацией
    logs = await audit_service.get_all_logs(
        user_id=user_id,
        action=action,
        limit=limit,
        offset=0,
    )
    
    logger.info(f"Admin {admin.id} exported {len(logs)} audit logs in {format} format")
    
    # Форматируем данные для экспорта
    export_data = [
        {
            "id": str(log.id),
            "user_id": str(log.user_id) if log.user_id else None,
            "action": log.action,
            "details": log.details,
            "success": log.success,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]
    
    if format == "json":
        return JSONResponse(content=export_data)
    
    # CSV экспорт
    output = io.StringIO()
    if export_data:
        headers = list(export_data[0].keys())
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        writer.writerows(export_data)
    
    return JSONResponse(content={
        "format": "csv",
        "content": output.getvalue(),
        "filename": f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        "count": len(logs),
    })


# ==================== ПРЯМАЯ ЗАПИСЬ ЛОГА ====================

@router.post(
    "/log",
    status_code=status.HTTP_201_CREATED,
    summary="Запись лога",
    description="Записывает действие в аудит-лог (для внутреннего использования)",
    include_in_schema=False,
)
async def create_audit_log(
    request: Request,
    user_id: Optional[UUID] = None,
    action: str = "",
    details: Optional[Dict[str, Any]] = None,
    success: bool = True,
    session: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Запись лога аудита (внутренний эндпоинт).
    
    Args:
        request: FastAPI Request
        user_id: ID пользователя
        action: Действие
        details: Детали
        success: Успешность
        session: Сессия БД
    
    Returns:
        JSONResponse: Статус записи
    """
    audit_service = AuditService(session)
    
    await audit_service.log_action(
        user_id=user_id,
        action=action,
        details=details or {},
        success=success,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    
    return JSONResponse(content={"status": "logged"})


# ==================== ОЧИСТКА СТАРЫХ ЛОГОВ ====================

@router.delete(
    "/cleanup",
    summary="Очистка старых логов",
    description="Удаляет логи старше указанного количества дней",
)
async def cleanup_audit_logs(
    request: Request,
    admin: User = Depends(get_current_admin),
    days: int = Query(90, ge=30, le=365, description="Количество дней для хранения"),
    session: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Очистка старых логов аудита.
    
    Args:
        request: FastAPI Request
        admin: Текущий администратор
        days: Количество дней для хранения
        session: Сессия БД
    
    Returns:
        JSONResponse: Результат очистки
    """
    audit_service = AuditService(session)
    
    deleted_count = await audit_service.cleanup_old_logs(days=days)
    
    logger.info(f"Admin {admin.id} cleaned up {deleted_count} old audit logs")
    
    return JSONResponse(content={
        "status": "success",
        "message": f"Deleted {deleted_count} logs older than {days} days",
        "deleted_count": deleted_count,
        "retention_days": days,
    })