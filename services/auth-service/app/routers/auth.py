"""
Роутер для аутентификации.

Регистрирует эндпоинты для:
- Регистрации пользователей
- Входа в систему (с поддержкой MFA)
- Выхода из системы
- Обновления токенов
- Подтверждения email
- Запроса сброса пароля
- Сброса пароля
- Управления сессиями
"""

from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request, HTTPException, status, Body, Cookie, Response
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.responses import JSONResponse

from app.core.database import get_db
from app.core.debug import LoggingRoute
from app.core.dependencies import (
    get_current_user,
    get_current_user_context,
    get_auth_service,
    get_refresh_token_from_request,
)
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    ValidationError,
    UserNotFoundError,
    UserBlockedException,
    MFARequiredError,
)
from app.core.logging import get_logger
from app.core.security import create_access_token, decode_token
from app.core.metrics import business_metrics, token_metrics
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RefreshResponse,
    LogoutRequest,
    LogoutResponse,
    VerifyEmailRequest,
    VerifyEmailResponse,
    VerifyPhoneRequest,
    VerifyPhoneResponse,
    PasswordResetRequest,
    PasswordResetConfirmRequest,
    MFAEnableRequest,
    MFAEnableResponse,
    MFADisableRequest,
    MFADisableResponse,
    MFAInfoResponse,
    SessionInfo,
    SessionListResponse,
)
from app.schemas.common import MessageResponse
from app.schemas.user import UserResponse
from app.services.auth_service import AuthService
from app.models.user import User

logger = get_logger(__name__)
router = APIRouter(route_class=LoggingRoute, prefix="/auth", tags=["auth"])


# ==================== ВХОД В СИСТЕМУ ====================

@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> LoginResponse:
    try:
        result = await auth_service.authenticate(
            email=login_data.email,
            password=login_data.password,
            totp_code=login_data.totp_code,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        business_metrics.increment_login()
        logger.info(f"User logged in: {result.user.id} - {result.user.email}")

        response = JSONResponse(
            content=LoginResponse(
                access_token=result.access_token,
                refresh_token=result.refresh_token,
                expires_in=result.access_expires_in,
                user_id=result.user.id,
                email=result.user.email,
            ).model_dump(mode="json")
        )

        response.set_cookie(
            key="refresh_token",
            value=result.refresh_token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=result.refresh_expires_in,
        )

        return response

    except AuthenticationError as e:
        logger.warning(f"Login failed for {login_data.email}: {str(e)}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    except UserBlockedException as e:
        logger.warning(f"Login blocked for {login_data.email}: {str(e)}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    except MFARequiredError:
        logger.info(f"MFA required for {login_data.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA verification required",
            headers={"X-MFA-Required": "true"},
        )


# ==================== ВЫХОД ИЗ СИСТЕМЫ ====================

@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    logout_data: Optional[LogoutRequest] = None,
    refresh_token: Optional[str] = Cookie(None),
    auth_service: AuthService = Depends(get_auth_service),
) -> LogoutResponse:
    token = refresh_token

    if token:
        await auth_service.revoke_refresh_token(token)
        logger.info(f"User logged out, token revoked: {token[:10]}...")

    business_metrics.increment_logout()

    response = JSONResponse(content=LogoutResponse(success=True, message="Logged out successfully").model_dump())
    response.delete_cookie("refresh_token")
    return response


# ==================== ОБНОВЛЕНИЕ ТОКЕНОВ ====================

@router.post("/refresh", response_model=RefreshResponse)
async def refresh(
    request: Request,
    refresh_data: Optional[RefreshRequest] = None,
    refresh_token: Optional[str] = Cookie(None),
    auth_service: AuthService = Depends(get_auth_service),
) -> RefreshResponse:
    token = refresh_data.refresh_token if refresh_data and refresh_data.refresh_token else refresh_token

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token required")

    try:
        result = await auth_service.refresh_tokens(
            refresh_token=token,
            client_ip=request.client.host if request.client else None,
        )

        logger.info(f"Tokens refreshed for user: {result.user_id}")

        response = JSONResponse(
            content=RefreshResponse(
                access_token=result.access_token,
                refresh_token=result.refresh_token,
                expires_in=result.access_expires_in,
            ).model_dump()
        )

        response.set_cookie(
            key="refresh_token",
            value=result.refresh_token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=result.refresh_expires_in,
        )

        return response

    except AuthenticationError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


# ==================== ПРОВЕРКА ТОКЕНА ====================

@router.post("/verify")
async def verify_token(
    request: Request,
    user: User = Depends(get_current_user),
) -> JSONResponse:
    return JSONResponse(content={"valid": True, "user_id": str(user.id), "email": user.email})


# ==================== ПОДТВЕРЖДЕНИЕ EMAIL ====================

@router.post("/verify-email", response_model=VerifyEmailResponse)
async def verify_email(
    request: Request,
    verify_data: VerifyEmailRequest,
    session: AsyncSession = Depends(get_db),
) -> VerifyEmailResponse:
    from app.repositories.user_repository import UserRepository

    user_repo = UserRepository(session)
    user = await user_repo.get_by_verification_token(verify_data.token)

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")

    await user_repo.verify_email(user_id=user.id)
    return VerifyEmailResponse(success=True, message="Email verified successfully")


# ==================== ПОДТВЕРЖДЕНИЕ ТЕЛЕФОНА ====================

@router.post("/verify-phone", response_model=VerifyPhoneResponse)
async def verify_phone(
    request: Request,
    verify_data: VerifyPhoneRequest,
    session: AsyncSession = Depends(get_db),
) -> VerifyPhoneResponse:
    from app.repositories.user_repository import UserRepository

    user_repo = UserRepository(session)
    user = await user_repo.get_by_phone_verification_token(verify_data.code)

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification code")

    await user_repo.verify_phone(user_id=user.id)
    return VerifyPhoneResponse(success=True, message="Phone verified successfully")


# ==================== ЗАПРОС СБРОСА ПАРОЛЯ ====================

@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(
    request: Request,
    forgot_data: PasswordResetRequest,
    session: AsyncSession = Depends(get_db),
) -> MessageResponse:
    from app.repositories.user_repository import UserRepository
    from app.services.password_service import PasswordService

    user_repo = UserRepository(session)
    password_service = PasswordService(session)

    try:
        user = await user_repo.get_by_email(forgot_data.email)
        if user:
            token = await password_service.generate_reset_token(user.id)
            logger.info(f"Password reset token generated for user: {user.id}")

        return MessageResponse(message="If account exists, password reset link sent to your email")
    except Exception as e:
        logger.error(f"Password reset request failed: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to process password reset request")


# ==================== СБРОС ПАРОЛЯ ====================

@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    request: Request,
    reset_data: PasswordResetConfirmRequest,
    session: AsyncSession = Depends(get_db),
) -> MessageResponse:
    from app.services.password_service import PasswordService

    password_service = PasswordService(session)

    try:
        success = await password_service.reset_password(token=reset_data.token, new_password=reset_data.new_password)
        if not success:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")
        logger.info("Password reset successful")
        return MessageResponse(message="Password reset successfully")
    except ValueError as e:
        logger.warning(f"Password reset failed: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ==================== ПОЛУЧЕНИЕ ТЕКУЩЕГО ПОЛЬЗОВАТЕЛЯ ====================

@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse.model_validate(user)


# ==================== УПРАВЛЕНИЕ СЕССИЯМИ ====================

@router.get("/sessions", response_model=SessionListResponse)
async def get_sessions(
    request: Request,
    user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> SessionListResponse:
    sessions = await auth_service.get_user_sessions(user.id)

    return SessionListResponse(
        sessions=[
            SessionInfo(
                id=str(session.id),
                user_id=str(session.user_id),
                client_ip=session.ip_address or "",
                user_agent=session.user_agent or "",
                created_at=session.created_at,
                expires_at=session.expires_at,
                is_active=not session.is_revoked,
            )
            for session in sessions
        ],
        total=len(sessions),
    )


@router.post("/sessions/revoke-all", response_model=MessageResponse)
async def revoke_all_sessions(
    request: Request,
    user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    count = await auth_service.revoke_all_sessions(user_id=user.id)
    logger.info(f"All sessions revoked for user {user.id}, count: {count}")
    return MessageResponse(message=f"All sessions revoked successfully ({count} sessions)")


# ==================== УПРАВЛЕНИЕ MFA ====================

@router.post("/mfa/enable", response_model=MFAEnableResponse)
async def mfa_enable(
    request: Request,
    enable_data: MFAEnableRequest,
    user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> MFAEnableResponse:
    try:
        result = await auth_service.setup_mfa(user.id)
        logger.info(f"MFA enable initiated for user: {user.id}")
        return MFAEnableResponse(secret=result["secret"], qr_code=result["qr_code"], backup_codes=result["backup_codes"])
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/mfa/verify", response_model=MessageResponse)
async def mfa_verify(
    request: Request,
    verify_data: MFAEnableRequest,
    user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    try:
        await auth_service.verify_mfa_setup(user_id=user.id, code=verify_data.code)
        logger.info(f"MFA enabled for user: {user.id}")
        return MessageResponse(message="MFA enabled successfully")
    except ValueError as e:
        logger.warning(f"MFA verification failed for user {user.id}: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/mfa/info", response_model=MFAInfoResponse)
async def mfa_info(
    request: Request,
    user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> MFAInfoResponse:
    try:
        info = await auth_service.get_mfa_info(user.id)
        return MFAInfoResponse(enabled=info["enabled"], has_backup_codes=info["has_backup_codes"], backup_codes_count=info["backup_codes_count"])
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/mfa/backup-codes/regenerate", response_model=MessageResponse)
async def mfa_backup_codes_regenerate(
    request: Request,
    user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    try:
        await auth_service.regenerate_backup_codes(user.id)
        logger.info(f"Backup codes regenerated for user: {user.id}")
        return MessageResponse(message="Backup codes regenerated successfully")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/mfa/disable", response_model=MessageResponse)
async def mfa_disable(
    request: Request,
    disable_data: MFADisableRequest,
    user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    try:
        await auth_service.disable_mfa(user_id=user.id, code=disable_data.code)
        logger.info(f"MFA disabled for user: {user.id}")
        return MessageResponse(message="MFA disabled successfully")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))