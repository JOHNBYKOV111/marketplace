"""
Internal API роутер для межсервисного взаимодействия.

Обеспечивает:
- Создание пользователя (из User Service)
- Удаление пользователя (из User Service)
- Блокировку пользователя (из User Service)
- Разблокировку пользователя (из User Service)
- Обновление пароля (из User Service)
- Отзыв всех сессий (из User Service)
- Проверку существования пользователя
- Количество активных сессий пользователя
- Аутентификацию через Internal API Key
- IP whitelist для дополнительной безопасности
- Публикацию событий в Kafka
- Graceful error handling
- Идемпотентный ответ при конфликте создания пользователя (409)
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, status
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.debug import LoggingRoute
from app.core.logging import get_logger
from app.core.exceptions import (
    BadRequestException,
    NotFoundException,
    UnauthorizedException,
    ForbiddenException,
    ConflictException,
)
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.services.token_service import TokenService
from app.core.kafka_client import kafka_client
from app.core.dependencies import get_user_repository, get_token_service, verify_internal_api_key

from app.schemas.internal import (
    CreateUserRequest,
    CreateUserResponse,
    DeleteUserRequest,
    DeleteUserResponse,
    BlockUserRequest,
    BlockUserResponse,
    UnblockUserRequest,
    UnblockUserResponse,
    UpdatePasswordRequest,
    UpdatePasswordResponse,
    RevokeAllSessionsRequest,
    RevokeAllSessionsResponse,
    UserExistsResponse,
    SessionsCountResponse,
    ErrorResponse,
)


logger = get_logger(__name__)
router = APIRouter(route_class=LoggingRoute)


@router.post(
    "/user/create",
    response_model=CreateUserResponse,
    responses={
        201: {"description": "User created successfully"},
        400: {"model": ErrorResponse, "description": "Bad request"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
        409: {"model": ErrorResponse, "description": "User already exists"},
    },
    status_code=status.HTTP_201_CREATED,
)
async def create_user(
    payload: CreateUserRequest,
    _: None = Depends(verify_internal_api_key),
    repo: UserRepository = Depends(get_user_repository),
) -> JSONResponse:
    try:
        existing_user = await repo.get_by_email_hash(payload.email_hash)
        if existing_user:
            # Idempotent Conflict Resolution: return existing user_id in response body
            # so caller can continue using the real UUID without re-querying.
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content=CreateUserResponse(
                    success=True,
                    user_id=str(existing_user.id),
                    message="User already exists",
                ).model_dump(),
            )

        user = await repo.create_user(
            user_id=payload.user_id,
            email=payload.email,
            email_hash=payload.email_hash,
            password_hash=payload.password_hash,
            is_active=payload.is_active,
            is_email_verified=payload.is_email_verified,
            metadata=payload.metadata,
        )

        try:
            await kafka_client.publish_event(
                event_type="user_created",
                data={
                    "user_id": str(user.id),
                    "email_hash": payload.email_hash,
                    "is_active": user.is_active,
                },
                user_id=str(user.id),
            )
        except Exception as e:
            logger.warning(f"Failed to publish user_created event: {e}")

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=CreateUserResponse(
                success=True,
                user_id=str(user.id),
                message="User created successfully",
            ).model_dump(),
        )

    except ConflictException:
        raise
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        raise BadRequestException(f"Failed to create user: {str(e)}")


@router.post(
    "/user/block",
    response_model=BlockUserResponse,
    responses={
        200: {"description": "User blocked successfully"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
    status_code=status.HTTP_200_OK,
)
async def block_user(
    payload: BlockUserRequest,
    _: None = Depends(verify_internal_api_key),
    repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service),
) -> JSONResponse:
    try:
        user = await repo.get_by_id(payload.user_id)
        if not user:
            raise NotFoundException(f"User {payload.user_id} not found")

        await repo.block_user(payload.user_id)

        revoked_count = 0
        try:
            revoked_count = await token_service.revoke_all_user_tokens(
                user_id=payload.user_id,
                reason=payload.reason or "user_blocked",
            )
        except Exception as e:
            logger.warning(f"Failed to revoke tokens for user {payload.user_id}: {e}")

        try:
            await kafka_client.publish_event(
                event_type="user_blocked",
                data={
                    "user_id": str(payload.user_id),
                    "reason": payload.reason,
                },
                user_id=str(payload.user_id),
            )
        except Exception as e:
            logger.warning(f"Failed to publish user_blocked event: {e}")

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=BlockUserResponse(
                success=True,
                user_id=str(payload.user_id),
                revoked_sessions_count=revoked_count,
                message="User blocked successfully",
            ).model_dump(),
        )

    except NotFoundException:
        raise
    except Exception as e:
        logger.error(f"Failed to block user: {e}")
        raise BadRequestException(f"Failed to block user: {str(e)}")


@router.post(
    "/user/unblock",
    response_model=UnblockUserResponse,
    responses={
        200: {"description": "User unblocked successfully"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
    status_code=status.HTTP_200_OK,
)
async def unblock_user(
    payload: UnblockUserRequest,
    _: None = Depends(verify_internal_api_key),
    repo: UserRepository = Depends(get_user_repository),
) -> JSONResponse:
    try:
        user = await repo.get_by_id(payload.user_id)
        if not user:
            raise NotFoundException(f"User {payload.user_id} not found")

        await repo.unblock_user(payload.user_id)

        try:
            await kafka_client.publish_event(
                event_type="user_unblocked",
                data={
                    "user_id": str(payload.user_id),
                    "reason": payload.reason,
                },
                user_id=str(payload.user_id),
            )
        except Exception as e:
            logger.warning(f"Failed to publish user_unblocked event: {e}")

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=UnblockUserResponse(
                success=True,
                user_id=str(payload.user_id),
                message="User unblocked successfully",
            ).model_dump(),
        )

    except NotFoundException:
        raise
    except Exception as e:
        logger.error(f"Failed to unblock user: {e}")
        raise BadRequestException(f"Failed to unblock user: {str(e)}")


@router.post(
    "/user/delete",
    response_model=DeleteUserResponse,
    responses={
        200: {"description": "User deleted successfully"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
    status_code=status.HTTP_200_OK,
)
async def delete_user(
    payload: DeleteUserRequest,
    _: None = Depends(verify_internal_api_key),
    repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service),
) -> JSONResponse:
    try:
        user = await repo.get_by_id(payload.user_id)
        if not user:
            raise NotFoundException(f"User {payload.user_id} not found")

        revoked_count = 0
        try:
            revoked_count = await token_service.revoke_all_user_tokens(
                user_id=payload.user_id,
                except_session_id=payload.except_session_id,
                reason="user_deleted",
            )
        except Exception as e:
            logger.warning(f"Failed to revoke tokens for user {payload.user_id}: {e}")

        await repo.delete_user(payload.user_id)

        try:
            await kafka_client.publish_event(
                event_type="user_deleted",
                data={"user_id": str(payload.user_id)},
                user_id=str(payload.user_id),
            )
        except Exception as e:
            logger.warning(f"Failed to publish user_deleted event: {e}")

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=DeleteUserResponse(
                success=True,
                user_id=str(payload.user_id),
                revoked_sessions_count=revoked_count,
                message="User deleted successfully",
            ).model_dump(),
        )

    except NotFoundException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete user: {e}")
        raise BadRequestException(f"Failed to delete user: {str(e)}")


@router.post(
    "/user/update-password",
    response_model=UpdatePasswordResponse,
    responses={
        200: {"description": "Password updated successfully"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
    status_code=status.HTTP_200_OK,
)
async def update_password(
    payload: UpdatePasswordRequest,
    _: None = Depends(verify_internal_api_key),
    repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service),
) -> JSONResponse:
    try:
        user = await repo.get_by_id(payload.user_id)
        if not user:
            raise NotFoundException(f"User {payload.user_id} not found")

        await repo.update_user(
            user_id=payload.user_id,
            password_hash=payload.new_password_hash,
        )

        revoked_count = 0
        try:
            revoked_count = await token_service.revoke_all_user_tokens(
                user_id=payload.user_id,
                except_session_id=payload.except_session_id,
                reason="password_changed",
            )
        except Exception as e:
            logger.warning(f"Failed to revoke tokens for user {payload.user_id}: {e}")

        try:
            await kafka_client.publish_event(
                event_type="password_changed",
                data={
                    "user_id": str(payload.user_id),
                    "revoked_sessions_count": revoked_count,
                },
                user_id=str(payload.user_id),
            )
        except Exception as e:
            logger.warning(f"Failed to publish password_changed event: {e}")

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=UpdatePasswordResponse(
                success=True,
                user_id=str(payload.user_id),
                revoked_sessions_count=revoked_count,
                message="Password updated successfully",
            ).model_dump(),
        )

    except NotFoundException:
        raise
    except Exception as e:
        logger.error(f"Failed to update password: {e}")
        raise BadRequestException(f"Failed to update password: {str(e)}")


@router.post(
    "/sessions/revoke-all",
    response_model=RevokeAllSessionsResponse,
    responses={
        200: {"description": "All sessions revoked successfully"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
    },
    status_code=status.HTTP_200_OK,
)
async def revoke_all_sessions(
    payload: RevokeAllSessionsRequest,
    _: None = Depends(verify_internal_api_key),
    token_service: TokenService = Depends(get_token_service),
) -> JSONResponse:
    try:
        revoked_count = await token_service.revoke_all_user_tokens(
            user_id=payload.user_id,
            except_session_id=payload.except_session_id,
            reason=payload.reason or "revoked_by_admin",
        )

        if payload.publish_event:
            try:
                await kafka_client.publish_event(
                    event_type="sessions_revoked",
                    data={
                        "user_id": str(payload.user_id),
                        "revoked_sessions_count": revoked_count,
                        "reason": payload.reason,
                    },
                    user_id=str(payload.user_id),
                )
            except Exception as e:
                logger.warning(f"Failed to publish sessions_revoked event: {e}")

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=RevokeAllSessionsResponse(
                success=True,
                user_id=str(payload.user_id),
                revoked_sessions_count=revoked_count,
                message=f"All sessions revoked successfully ({revoked_count} sessions)",
            ).model_dump(),
        )

    except Exception as e:
        logger.error(f"Failed to revoke sessions: {e}")
        raise BadRequestException(f"Failed to revoke sessions: {str(e)}")


@router.get(
    "/user/{user_id}/exists",
    response_model=UserExistsResponse,
    responses={
        200: {"description": "User existence check completed"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
    },
    status_code=status.HTTP_200_OK,
)
async def user_exists(
    user_id: UUID,
    _: None = Depends(verify_internal_api_key),
    repo: UserRepository = Depends(get_user_repository),
) -> JSONResponse:
    try:
        user = await repo.get_by_id(user_id)
        if user:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=UserExistsResponse(
                    user_id=str(user_id),
                    exists=True,
                    email=user.email,
                    phone=user.phone,
                    is_active=user.is_active,
                    is_email_verified=user.is_email_verified,
                ).model_dump(),
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=UserExistsResponse(
                    user_id=str(user_id),
                    exists=False,
                    is_active=None,
                    is_email_verified=None,
                ).model_dump(),
            )

    except Exception as e:
        logger.error(f"Failed to check user existence: {e}")
        raise BadRequestException(f"Failed to check user existence: {str(e)}")


@router.get(
    "/user/{user_id}/sessions/count",
    response_model=SessionsCountResponse,
    responses={
        200: {"description": "Sessions count retrieved"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
    },
    status_code=status.HTTP_200_OK,
)
async def sessions_count(
    user_id: UUID,
    _: None = Depends(verify_internal_api_key),
    token_service: TokenService = Depends(get_token_service),
) -> JSONResponse:
    try:
        count = await token_service.get_active_sessions_count(user_id)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=SessionsCountResponse(
                user_id=str(user_id),
                active_sessions_count=count,
            ).model_dump(),
        )

    except Exception as e:
        logger.error(f"Failed to get sessions count: {e}")
        raise BadRequestException(f"Failed to get sessions count: {str(e)}")