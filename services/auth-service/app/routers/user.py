"""
Роутер для управления пользователями.

Обрабатывает:
- Получение профиля пользователя
- Обновление профиля
- Смена пароля
- Получение активных сессий
- Завершение сессии
- Удаление аккаунта
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import (
    get_current_user,
    get_current_user_id,
    get_user_repository,
    get_auth_service,
    get_audit_service,
    get_password_service,
    get_token_service,
    get_refresh_token_repository,
)
from app.core.exceptions import UnauthorizedException, AppException, BadRequestException
from app.core.logging import get_logger
from app.core.rate_limit import RateLimiter
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.schemas.user import (
    UserProfileResponse,
    UserUpdateRequest,
    PasswordChangeRequest,
    SessionInfoResponse,
    SessionListResponse,
    DeleteAccountRequest,
    DeleteAccountResponse,
)
from app.services.auth_service import AuthService
from app.services.audit_service import AuditService
from app.services.password_service import PasswordService
from app.services.token_service import TokenService

router = APIRouter(prefix="/users", tags=["users"])
logger = get_logger(__name__)

# Rate limiters
profile_limiter = RateLimiter(limit=30, window=60)
password_limiter = RateLimiter(limit=5, window=300)
session_limiter = RateLimiter(limit=20, window=60)


@router.get(
    "/me",
    response_model=UserProfileResponse,
    responses={
        200: {"description": "Профиль пользователя"},
        401: {"description": "Не авторизован"},
    },
)
async def get_profile(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
) -> UserProfileResponse:
    """
    Получение профиля текущего пользователя.

    Args:
        request: HTTP запрос
        current_user: Текущий пользователь
        user_repo: Репозиторий пользователей

    Returns:
        UserProfileResponse: Профиль пользователя
    """
    client_ip = request.client.host if request.client else "unknown"
    if not await profile_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
        )

    logger.info(f"Profile retrieved for user: {current_user.id}")

    return UserProfileResponse.model_validate(current_user)


@router.patch(
    "/me",
    response_model=UserProfileResponse,
    responses={
        200: {"description": "Профиль обновлен"},
        400: {"description": "Ошибка валидации"},
        401: {"description": "Не авторизован"},
        422: {"description": "Неверные данные"},
    },
)
async def update_profile(
    request: Request,
    update_data: UserUpdateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> UserProfileResponse:
    """
    Обновление профиля текущего пользователя.

    Args:
        request: HTTP запрос
        update_data: Данные для обновления
        current_user: Текущий пользователь
        user_repo: Репозиторий пользователей
        audit_service: Сервис аудита

    Returns:
        UserProfileResponse: Обновленный профиль
    """
    client_ip = request.client.host if request.client else "unknown"

    if not await profile_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
        )

    try:
        if update_data.email and update_data.email != current_user.email:
            existing = await user_repo.get_by_email(update_data.email)
            if existing:
                raise AppException("Email already in use", code="EMAIL_ALREADY_IN_USE", status_code=400)

        update_dict = update_data.model_dump(exclude_unset=True)
        updated_user = await user_repo.update(current_user.id, **update_dict)

        if not updated_user:
            raise AppException("Failed to update profile", code="PROFILE_UPDATE_FAILED", status_code=400)

        await audit_service.log_profile_update(current_user.id, client_ip, update_dict)

        logger.info(f"Profile updated for user: {current_user.id}")

        return UserProfileResponse.model_validate(updated_user)

    except AppException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
        )

    except BadRequestException as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )

    except Exception as e:
        logger.error(f"Failed to update profile for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile",
        )


@router.post(
    "/me/change-password",
    responses={
        200: {"description": "Пароль изменен"},
        400: {"description": "Неверный текущий пароль"},
        401: {"description": "Не авторизован"},
        422: {"description": "Новый пароль не прошел валидацию"},
        429: {"description": "Превышен лимит попыток"},
    },
)
async def change_password(
    request: Request,
    password_data: PasswordChangeRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    password_service: Annotated[PasswordService, Depends(get_password_service)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> dict:
    """
    Смена пароля текущего пользователя.

    Args:
        request: HTTP запрос
        password_data: Данные для смены пароля
        current_user: Текущий пользователь
        password_service: Сервис паролей
        auth_service: Сервис аутентификации
        audit_service: Сервис аудита

    Returns:
        dict: Статус операции
    """
    client_ip = request.client.host if request.client else "unknown"

    if not await password_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password change attempts. Please try again later.",
        )

    try:
        is_valid = await password_service.verify_password(
            password_data.current_password,
            current_user.password_hash,
        )

        if not is_valid:
            await audit_service.log_failed_password_change(current_user.id, client_ip, "INVALID_CURRENT_PASSWORD")
            raise AppException("Current password is incorrect", code="INVALID_PASSWORD", status_code=400)

        await password_service.validate_password(
            password_data.new_password,
            user_id=current_user.id,
        )

        new_hash = await password_service.hash_password(password_data.new_password)

        await auth_service.update_password(current_user.id, new_hash)

        await audit_service.log_successful_password_change(current_user.id, client_ip)

        logger.info(f"Password changed for user: {current_user.id}")

        return {
            "success": True,
            "message": "Password changed successfully",
        }

    except AppException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
        )

    except BadRequestException as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )

    except Exception as e:
        logger.error(f"Failed to change password for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password",
        )


@router.get(
    "/me/sessions",
    response_model=SessionListResponse,
    responses={
        200: {"description": "Список активных сессий"},
        401: {"description": "Не авторизован"},
    },
)
async def get_sessions(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
    refresh_repo: Annotated[RefreshTokenRepository, Depends(get_refresh_token_repository)],
) -> SessionListResponse:
    """
    Получение списка активных сессий пользователя.

    Args:
        request: HTTP запрос
        current_user: Текущий пользователь
        token_service: Сервис токенов
        refresh_repo: Репозиторий refresh токенов

    Returns:
        SessionListResponse: Список сессий
    """
    client_ip = request.client.host if request.client else "unknown"

    if not await session_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
        )

    try:
        tokens = await refresh_repo.get_active_tokens_by_user(current_user.id)

        sessions = [
            SessionInfoResponse(
                id=token.id,
                user_id=token.user_id,
                client_ip=token.client_ip,
                user_agent=token.user_agent,
                created_at=token.created_at,
                expires_at=token.expires_at,
                is_active=token.is_active,
                last_used_at=token.last_used_at,
            )
            for token in tokens
        ]

        return SessionListResponse(
            sessions=sessions,
            total=len(sessions),
        )

    except Exception as e:
        logger.error(f"Failed to get sessions for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get sessions",
        )


@router.delete(
    "/me/sessions/{session_id}",
    responses={
        200: {"description": "Сессия завершена"},
        401: {"description": "Не авторизован"},
        404: {"description": "Сессия не найдена"},
    },
)
async def terminate_session(
    request: Request,
    session_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
    refresh_repo: Annotated[RefreshTokenRepository, Depends(get_refresh_token_repository)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> dict:
    """
    Завершение конкретной сессии.

    Args:
        request: HTTP запрос
        session_id: ID сессии
        current_user: Текущий пользователь
        token_service: Сервис токенов
        refresh_repo: Репозиторий refresh токенов
        audit_service: Сервис аудита

    Returns:
        dict: Статус операции
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        token = await refresh_repo.get_by_id(session_id)

        if not token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found",
            )

        if token.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot terminate session of another user",
            )

        await refresh_repo.revoke_token(session_id)

        await audit_service.log_session_terminated(current_user.id, session_id, client_ip)

        logger.info(f"Session terminated for user {current_user.id}: {session_id}")

        return {
            "success": True,
            "message": "Session terminated successfully",
        }

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Failed to terminate session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to terminate session",
        )


@router.delete(
    "/me",
    response_model=DeleteAccountResponse,
    responses={
        200: {"description": "Аккаунт удален"},
        400: {"description": "Неверный пароль"},
        401: {"description": "Не авторизован"},
        429: {"description": "Превышен лимит попыток"},
    },
)
async def delete_account(
    request: Request,
    delete_data: DeleteAccountRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    password_service: Annotated[PasswordService, Depends(get_password_service)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> DeleteAccountResponse:
    """
    Удаление аккаунта текущего пользователя.

    Args:
        request: HTTP запрос
        delete_data: Данные для удаления
        current_user: Текущий пользователь
        password_service: Сервис паролей
        auth_service: Сервис аутентификации
        audit_service: Сервис аудита

    Returns:
        DeleteAccountResponse: Статус операции
    """
    client_ip = request.client.host if request.client else "unknown"

    if not await password_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Please try again later.",
        )

    try:
        is_valid = await password_service.verify_password(
            delete_data.password,
            current_user.password_hash,
        )

        if not is_valid:
            await audit_service.log_failed_account_deletion(current_user.id, client_ip, "INVALID_PASSWORD")
            raise AppException("Invalid password", code="INVALID_PASSWORD", status_code=400)

        deleted = await auth_service.delete_user(current_user.id)

        if not deleted:
            raise AppException("Failed to delete account", code="ACCOUNT_DELETE_FAILED", status_code=400)

        await audit_service.log_account_deletion(current_user.id, client_ip)

        logger.info(f"Account deleted for user: {current_user.id}")

        return DeleteAccountResponse(
            success=True,
            message="Account deleted successfully",
            user_id=current_user.id,
        )

    except AppException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
        )

    except Exception as e:
        logger.error(f"Failed to delete account for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account",
        )