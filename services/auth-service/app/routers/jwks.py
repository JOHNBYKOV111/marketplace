"""
JWKS роутер для управления криптографическими ключами.

Обеспечивает:
- Публичный эндпоинт /.well-known/jwks.json для получения JWKS
- Кэширование в Redis с fail-open (при отказе Redis — прямое обращение к БД)
- Полный fail-open при отказе всех зависимостей (возврат пустого списка ключей с 200)
- Админские эндпоинты для управления ключами:
  - Список всех ключей
  - Список активных ключей
  - Ротация ключей
  - Активация/деактивация ключей
  - Очистка истекших ключей
  - Метрики

Связанные модули:
- app.services.jwk_service - бизнес-логика
- app.repositories.jwk_key_repository - CRUD операции
- app.schemas.jwks - Pydantic схемы
- app.core.redis_client - кэширование JWKS
"""

from typing import Optional
from fastapi import APIRouter, Depends, Request, status, HTTPException, Path
from fastapi.responses import JSONResponse

import redis.exceptions as redis_exc

from app.core.config import settings
from app.core.debug import LoggingRoute
from app.core.dependencies import get_current_admin, get_current_user
from app.core.exceptions import (
    BadRequestException,
    NotFoundException,
    ForbiddenException,
    ConflictException,
)
from app.core.logging import get_logger
from app.core.redis_client import redis_client
from app.models.user import User
from app.repositories.jwk_key_repository import JWKKeyRepository
from app.services.jwk_service import JWKService
from app.schemas.jwks import (
    JWKSResponse,
    JWKKeyResponse,
    JWKKeyListResponse,
    RotateKeysRequest,
    RotateKeysResponse,
    ActivateKeyResponse,
    DeactivateKeyResponse,
    CleanupExpiredResponse,
    JWKSMetricsResponse,
    JWKSErrorResponse,
)
from app.core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

logger = get_logger(__name__)
router = APIRouter(route_class=LoggingRoute, tags=["jwks"])


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

async def get_jwk_service(
    session: AsyncSession = Depends(get_db),
) -> JWKService:
    """Dependency для получения JWKService."""
    repository = JWKKeyRepository(session)
    return JWKService(repository)


def require_admin(user: User = Depends(get_current_admin)) -> User:
    """
    Проверка прав администратора.

    Используется для всех админских эндпоинтов.
    """
    if not user.is_superuser:
        raise ForbiddenException("Admin access required")
    return user


# ==================== ПУБЛИЧНЫЙ ЭНДПОИНТ ====================

@router.get(
    "/.well-known/jwks.json",
    response_model=JWKSResponse,
    summary="Получение JWKS",
    description="Возвращает публичные ключи в формате JWKS для верификации JWT токенов",
    responses={
        200: {"description": "Успешный ответ (включая fail-open с пустым списком)"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def get_jwks(
    request: Request,
    jwk_service: JWKService = Depends(get_jwk_service),
) -> JSONResponse:
    """
    Получение JWKS (JSON Web Key Set).

    Используется клиентами для верификации JWT подписей.
    При недоступности Redis работает напрямую с БД (fail-open).
    При полном отказе всех зависимостей возвращает пустой список ключей с 200.

    Flow:
    1. Проверяем force_refresh заголовок
    2. Пытаемся получить ключи из кэша Redis
    3. Если кэша нет или Redis недоступен — идём в БД
    4. Сохраняем результат в Redis (если доступен)
    5. При полном отказе — возвращаем пустой список ключей с 200

    Args:
        request: FastAPI Request
        jwk_service: Сервис JWK

    Returns:
        JSONResponse: JWKS данные
    """
    source = "cache"
    jwks_data = None

    try:
        # Проверяем необходимость принудительного обновления
        force_refresh = request.headers.get("X-Force-Refresh", "false").lower() == "true"

        if not force_refresh:
            # Пытаемся получить ключи из кэша Redis
            try:
                jwks_data = await redis_client.get_json("jwks_cache")
                if jwks_data:
                    logger.debug("JWKS returned from Redis cache")
                    return JSONResponse(
                        content=jwks_data,
                        status_code=status.HTTP_200_OK,
                        headers={
                            "Cache-Control": "public, max-age=3600",
                            "X-JWKS-Source": source,
                        },
                    )
            except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
                # Redis недоступен — логируем и идём в БД (fail-open)
                logger.warning(f"Redis unavailable for JWKS cache, falling back to database: {e}")
                source = "database"

        # Кэш пуст, отключён или произошёл сбой Redis — получаем ключи из БД
        jwks_data = await jwk_service.get_jwks(force_refresh=force_refresh)
        source = "database"

        # Пытаемся сохранить в кэш Redis для будущих запросов
        try:
            await redis_client.set_json("jwks_cache", jwks_data, ttl=3600)
            logger.debug("JWKS saved to Redis cache")
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            # Не удалось сохранить в кэш — ничего страшного, продолжаем
            logger.warning(f"Failed to cache JWKS in Redis: {e}")

        return JSONResponse(
            content=jwks_data,
            status_code=status.HTTP_200_OK,
            headers={
                "Cache-Control": "public, max-age=3600",
                "X-JWKS-Source": source,
            },
        )

    except Exception as e:
        # Полный отказ — fail-open: возвращаем пустой список ключей с 200
        logger.error(f"Failed to get JWKS, entering fail-open mode: {e}")

        headers = {
            "Cache-Control": "no-store",
            "X-JWKS-Source": "failed",
        }

        return JSONResponse(
            content={"keys": []},
            status_code=status.HTTP_200_OK,
            headers=headers,
        )


# ==================== АДМИНСКИЕ ЭНДПОИНТЫ ====================

@router.get(
    "/admin/jwks/keys",
    response_model=JWKKeyListResponse,
    summary="Список всех ключей",
    description="Возвращает список всех JWK ключей (только для администраторов)",
    responses={
        200: {"description": "Успешный ответ"},
        403: {"model": JWKSErrorResponse, "description": "Доступ запрещен"},
        401: {"model": JWKSErrorResponse, "description": "Не авторизован"},
    },
)
async def list_all_keys(
    admin: User = Depends(require_admin),
    jwk_service: JWKService = Depends(get_jwk_service),
) -> JSONResponse:
    """
    Получение списка всех ключей (админский эндпоинт).

    Args:
        admin: Текущий администратор
        jwk_service: Сервис JWK

    Returns:
        JSONResponse: Список ключей
    """
    try:
        keys = await jwk_service.get_all_keys()

        return JSONResponse(
            content={
                "items": [key.to_dict() for key in keys],
                "total": len(keys),
            },
            status_code=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Failed to list all keys: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve keys",
        )


@router.get(
    "/admin/jwks/keys/active",
    response_model=JWKKeyListResponse,
    summary="Список активных ключей",
    description="Возвращает список активных JWK ключей (только для администраторов)",
    responses={
        200: {"description": "Успешный ответ"},
        403: {"model": JWKSErrorResponse, "description": "Доступ запрещен"},
        401: {"model": JWKSErrorResponse, "description": "Не авторизован"},
    },
)
async def list_active_keys(
    admin: User = Depends(require_admin),
    jwk_service: JWKService = Depends(get_jwk_service),
) -> JSONResponse:
    """
    Получение списка активных ключей (админский эндпоинт).

    Args:
        admin: Текущий администратор
        jwk_service: Сервис JWK

    Returns:
        JSONResponse: Список активных ключей
    """
    try:
        keys = await jwk_service.get_active_keys()

        return JSONResponse(
            content={
                "items": [key.to_dict() for key in keys],
                "total": len(keys),
            },
            status_code=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Failed to list active keys: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve active keys",
        )


@router.post(
    "/admin/jwks/rotate",
    response_model=RotateKeysResponse,
    summary="Ротация ключей",
    description="Создает новый ключ и деактивирует старые (только для администраторов)",
    responses={
        200: {"description": "Успешная ротация"},
        400: {"model": JWKSErrorResponse, "description": "Неверный запрос"},
        403: {"model": JWKSErrorResponse, "description": "Доступ запрещен"},
        401: {"model": JWKSErrorResponse, "description": "Не авторизован"},
        409: {"model": JWKSErrorResponse, "description": "Конфликт"},
    },
)
async def rotate_keys(
    request: Request,
    rotate_data: RotateKeysRequest,
    admin: User = Depends(require_admin),
    jwk_service: JWKService = Depends(get_jwk_service),
) -> JSONResponse:
    """
    Ротация JWK ключей (админский эндпоинт).

    Args:
        request: FastAPI Request
        rotate_data: Данные для ротации
        admin: Текущий администратор
        jwk_service: Сервис JWK

    Returns:
        JSONResponse: Результат ротации

    Raises:
        BadRequestException: Если данные невалидны
        ConflictException: Если ключ уже существует
    """
    try:
        # Выполняем ротацию
        new_key, private_pem, public_pem = await jwk_service.rotate_keys(
            algorithm=rotate_data.algorithm,
            key_size=rotate_data.key_size,
            grace_period_hours=rotate_data.grace_period_hours,
            rotated_by=str(admin.id),
        )

        logger.info(f"Keys rotated by admin {admin.id}, new kid: {new_key.kid}")

        return JSONResponse(
            content={
                "success": True,
                "new_kid": new_key.kid,
                "expires_at": new_key.expires_at.isoformat() if new_key.expires_at else None,
                "message": f"Keys rotated successfully. New key: {new_key.kid}",
            },
            status_code=status.HTTP_200_OK,
        )

    except ConflictException as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Failed to rotate keys: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rotate keys",
        )


@router.post(
    "/admin/jwks/keys/{kid}/activate",
    response_model=ActivateKeyResponse,
    summary="Активация ключа",
    description="Активирует указанный JWK ключ (только для администраторов)",
    responses={
        200: {"description": "Успешная активация"},
        404: {"model": JWKSErrorResponse, "description": "Ключ не найден"},
        403: {"model": JWKSErrorResponse, "description": "Доступ запрещен"},
        401: {"model": JWKSErrorResponse, "description": "Не авторизован"},
    },
)
async def activate_key(
    kid: str = Path(..., max_length=64, description="Идентификатор JWK ключа"),
    admin: User = Depends(require_admin),
    jwk_service: JWKService = Depends(get_jwk_service),
) -> JSONResponse:
    """
    Активация JWK ключа (админский эндпоинт).

    Args:
        kid: Key ID (максимум 64 символа)
        admin: Текущий администратор
        jwk_service: Сервис JWK

    Returns:
        JSONResponse: Результат активации

    Raises:
        NotFoundException: Если ключ не найден
    """
    try:
        result = await jwk_service.activate_key(kid, activated_by=str(admin.id))

        if not result:
            raise NotFoundException(f"Key with kid {kid} not found")

        logger.info(f"Key {kid} activated by admin {admin.id}")

        return JSONResponse(
            content={
                "success": True,
                "kid": kid,
                "message": f"Key {kid} activated successfully",
            },
            status_code=status.HTTP_200_OK,
        )

    except NotFoundException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Failed to activate key {kid}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate key",
        )


@router.post(
    "/admin/jwks/keys/{kid}/deactivate",
    response_model=DeactivateKeyResponse,
    summary="Деактивация ключа",
    description="Деактивирует указанный JWK ключ (только для администраторов)",
    responses={
        200: {"description": "Успешная деактивация"},
        404: {"model": JWKSErrorResponse, "description": "Ключ не найден"},
        403: {"model": JWKSErrorResponse, "description": "Доступ запрещен"},
        401: {"model": JWKSErrorResponse, "description": "Не авторизован"},
        409: {"model": JWKSErrorResponse, "description": "Невозможно деактивировать единственный активный ключ"},
    },
)
async def deactivate_key(
    kid: str = Path(..., max_length=64, description="Идентификатор JWK ключа"),
    admin: User = Depends(require_admin),
    jwk_service: JWKService = Depends(get_jwk_service),
) -> JSONResponse:
    """
    Деактивация JWK ключа (админский эндпоинт).

    Args:
        kid: Key ID (максимум 64 символа)
        admin: Текущий администратор
        jwk_service: Сервис JWK

    Returns:
        JSONResponse: Результат деактивации

    Raises:
        NotFoundException: Если ключ не найден
    """
    try:
        result = await jwk_service.deactivate_key(kid)

        if not result:
            raise NotFoundException(f"Key with kid {kid} not found")

        logger.info(f"Key {kid} deactivated by admin {admin.id}")

        return JSONResponse(
            content={
                "success": True,
                "kid": kid,
                "message": f"Key {kid} deactivated successfully",
            },
            status_code=status.HTTP_200_OK,
        )

    except NotFoundException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Failed to deactivate key {kid}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate key",
        )


@router.delete(
    "/admin/jwks/keys/expired",
    response_model=CleanupExpiredResponse,
    summary="Очистка истекших ключей",
    description="Удаляет все истекшие JWK ключи (только для администраторов)",
    responses={
        200: {"description": "Успешная очистка"},
        403: {"model": JWKSErrorResponse, "description": "Доступ запрещен"},
        401: {"model": JWKSErrorResponse, "description": "Не авторизован"},
    },
)
async def cleanup_expired_keys(
    admin: User = Depends(require_admin),
    jwk_service: JWKService = Depends(get_jwk_service),
) -> JSONResponse:
    """
    Очистка истекших JWK ключей (админский эндпоинт).

    Args:
        admin: Текущий администратор
        jwk_service: Сервис JWK

    Returns:
        JSONResponse: Результат очистки
    """
    try:
        deleted_count = await jwk_service.cleanup_expired_keys()

        logger.info(f"Cleaned up {deleted_count} expired keys by admin {admin.id}")

        return JSONResponse(
            content={
                "success": True,
                "deleted_count": deleted_count,
                "message": f"Cleaned up {deleted_count} expired keys",
            },
            status_code=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Failed to cleanup expired keys: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cleanup expired keys",
        )


@router.get(
    "/admin/jwks/metrics",
    response_model=JWKSMetricsResponse,
    summary="Метрики JWKS",
    description="Возвращает метрики JWK ключей (только для администраторов)",
    responses={
        200: {"description": "Успешный ответ"},
        403: {"model": JWKSErrorResponse, "description": "Доступ запрещен"},
        401: {"model": JWKSErrorResponse, "description": "Не авторизован"},
    },
)
async def get_jwks_metrics(
    admin: User = Depends(require_admin),
    jwk_service: JWKService = Depends(get_jwk_service),
) -> JSONResponse:
    """
    Получение метрик JWK ключей (админский эндпоинт).

    Args:
        admin: Текущий администратор
        jwk_service: Сервис JWK

    Returns:
        JSONResponse: Метрики
    """
    try:
        metrics = await jwk_service.get_metrics_data()

        return JSONResponse(
            content=metrics,
            status_code=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Failed to get JWKS metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve JWKS metrics",
        )