"""
User API router.

Provides endpoints for user profile management.
All endpoints require authentication (X-User-Id header or Bearer JWT).
Email and status flags are fetched from auth-service, not stored locally.
"""

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status

from app.core.dependencies import get_current_user_id, get_current_user_from_jwt, get_user_service
from app.schemas.user import (
    DeleteAccountResponse,
    PasswordChangeRequest,
    PasswordChangeResponse,
    SessionListResponse,
    UserProfileResponse,
    UserUpdateRequest,
)
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["Users"])


async def _resolve_user_id(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_user_id: Optional[UUID] = Header(None, alias="X-User-Id"),
) -> UUID:
    if authorization and authorization.startswith("Bearer "):
        try:
            return await get_current_user_from_jwt(authorization)
        except HTTPException:
            pass

    if x_user_id is not None:
        return x_user_id

    raise HTTPException(status_code=401, detail="Authentication required")


@router.get("/me", response_model=UserProfileResponse)
async def get_profile(
    user_service: UserService = Depends(get_user_service),
    user_id: UUID = Depends(_resolve_user_id),
):
    user = await user_service.ensure_user_exists(user_id)
    if getattr(user, "is_deleted", False):
        raise HTTPException(status_code=404, detail="User not found")

    info = await user_service._fetch_user_info_from_auth(user_id)
    if not info.get("is_active", True):
        raise HTTPException(status_code=403, detail="User account is blocked")

    response = UserProfileResponse.model_validate(user)
    response.email = info.get("email", f"{user_id}@unknown.com")
    response.is_active = info.get("is_active", True)
    response.is_email_verified = info.get("is_email_verified", False)
    return response


@router.patch("/me", response_model=UserProfileResponse)
async def update_profile(
    body: UserUpdateRequest,
    user_service: UserService = Depends(get_user_service),
    user_id: UUID = Depends(_resolve_user_id),
):
    updates = body.model_dump(exclude_unset=True)
    user = await user_service.update_user(user_id, **updates)
    info = await user_service._fetch_user_info_from_auth(user_id)
    response = UserProfileResponse.model_validate(user)
    response.email = info.get("email", f"{user_id}@unknown.com")
    response.is_active = info.get("is_active", True)
    response.is_email_verified = info.get("is_email_verified", False)
    return response


@router.delete("/me", response_model=DeleteAccountResponse)
async def delete_account(
    user_service: UserService = Depends(get_user_service),
    user_id: UUID = Depends(_resolve_user_id),
):
    await user_service.delete_user(user_id)
    return DeleteAccountResponse(
        success=True,
        message="Account deleted successfully",
        user_id=user_id,
    )


@router.post("/me/change-password", response_model=PasswordChangeResponse)
async def change_password(
    body: PasswordChangeRequest,
    user_service: UserService = Depends(get_user_service),
    user_id: UUID = Depends(_resolve_user_id),
):
    raise HTTPException(status_code=400, detail="Password management is in auth-service only")


@router.get("/me/sessions", response_model=SessionListResponse)
async def list_sessions(
    user_service: UserService = Depends(get_user_service),
    user_id: UUID = Depends(_resolve_user_id),
):
    sessions = await user_service.get_sessions(user_id)
    total = len(sessions)
    return SessionListResponse(sessions=sessions, total=total)