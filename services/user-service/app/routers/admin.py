"""
Admin API router.

Provides endpoints for user management by administrators.
All endpoints require admin role (X-User-Roles header contains 'admin').
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.dependencies import require_admin
from app.core.exceptions import NotFoundException
from app.schemas.user import UserListResponse, UserResponse
from app.schemas.audit_log import AuditLogItem, AuditLogListResponse
from app.schemas.admin import BlockUserRequest, UnblockUserRequest
from app.services.user_service import UserService
from app.core.database import get_db

router = APIRouter(prefix="/admin", tags=["Admin"])


def get_user_service(db=Depends(get_db)) -> UserService:
    """Dependency injection for UserService."""
    from app.repositories.user_repository import UserRepository
    from app.repositories.audit_log_repository import AuditLogRepository

    user_repo = UserRepository(db)
    audit_repo = AuditLogRepository(db)
    return UserService(db=db, user_repo=user_repo, audit_repo=audit_repo)


@router.get("/users", response_model=UserListResponse)
async def list_users(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user_service: UserService = Depends(get_user_service),
    _: None = Depends(require_admin),
):
    """List users with pagination. Admin only."""
    users, total = await user_service.list_users(
        limit=limit,
        offset=offset,
    )
    return UserListResponse(
        items=[UserResponse.model_validate(u) for u in users],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    user_service: UserService = Depends(get_user_service),
    _: None = Depends(require_admin),
):
    """Get user by ID. Admin only."""
    user = await user_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user)


@router.post("/users/{user_id}/block")
async def block_user(
    user_id: UUID,
    body: BlockUserRequest,
    user_service: UserService = Depends(get_user_service),
    _: None = Depends(require_admin),
):
    """Block a user. Admin only."""
    try:
        await user_service.block_user(user_id, reason=body.reason)
    except NotFoundException as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"success": True, "message": "User blocked successfully"}


@router.post("/users/{user_id}/unblock")
async def unblock_user(
    user_id: UUID,
    body: UnblockUserRequest,
    user_service: UserService = Depends(get_user_service),
    _: None = Depends(require_admin),
):
    """Unblock a user. Admin only."""
    try:
        await user_service.unblock_user(user_id, reason=body.reason)
    except NotFoundException as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"success": True, "message": "User unblocked successfully"}


@router.get("/users/{user_id}/audit", response_model=AuditLogListResponse)
async def get_user_audit_trail(
    user_id: UUID,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user_service: UserService = Depends(get_user_service),
    _: None = Depends(require_admin),
):
    """Get audit trail for a user. Admin only."""
    logs, total = await user_service.get_audit_logs(
        user_id=user_id,
        limit=limit,
        offset=offset,
    )
    return AuditLogListResponse(
        items=[AuditLogItem.model_validate(log) for log in logs],
        total=total,
        limit=limit,
        offset=offset,
    )