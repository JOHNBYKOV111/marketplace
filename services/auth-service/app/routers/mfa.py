"""
MFA (Multi-Factor Authentication) роутер.

Обеспечивает:
- POST /mfa/totp/setup - генерация TOTP секрета
- POST /mfa/totp/verify - верификация и активация TOTP
- POST /mfa/totp/disable - отключение TOTP
- POST /mfa/sms/send - отправка SMS кода
- POST /mfa/sms/verify - верификация SMS и активация
- POST /mfa/email/send - отправка Email кода
- POST /mfa/email/verify - верификация Email и активация
- GET /mfa/backup-codes - получение резервных кодов
- POST /mfa/backup-codes/renew - регенерация кодов
- POST /mfa/verify - универсальная проверка 2FA при логине
- Rate limiting и идемпотентность
- Проверку авторизации через Gateway заголовки
- Обработку отказов Redis (fail open)

Совместимость с тестами:
- Все тесты из test_mfa_routes.py (18 тестов в 8 классах)
- test_redis_resilience.py: тесты отказоустойчивости Redis
- Моки: MFAService, redis_client, RateLimitService, qrcode.QRCode, set_refresh_token_cookie

Связанные модули:
- app.services.mfa_service - бизнес-логика MFA
- app.services.rate_limit_service - rate limiting
- app.schemas.mfa - Pydantic схемы
- app.core.redis_client - кэширование и идемпотентность
- app.core.dependencies - GatewayUser зависимость
"""

import base64
import io
from typing import Optional
from uuid import uuid4

import qrcode
import redis.exceptions as redis_exc
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    GatewayUser,
    get_current_user_from_gateway_headers,
)
from app.core.logging import get_logger
from app.core.redis_client import redis_client
from app.schemas.mfa import (
    BackupCodesResponse,
    BackupCodesRenewResponse,
    EmailSendResponse,
    EmailVerifyRequest,
    EmailVerifyResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
    MFAMethod,
    SMSVerifyRequest,
    SMSVerifyResponse,
    SMSSendResponse,
    TOTPDisableRequest,
    TOTPDisableResponse,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    TOTPVerifyResponse,
)
from app.services.mfa_service import MFAService
from app.services.rate_limit_service import RateLimitService

logger = get_logger(__name__)
router = APIRouter(prefix="/mfa", tags=["mfa"])


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

async def get_mfa_service() -> MFAService:
    """Dependency для получения MFAService."""
    return MFAService()


async def get_rate_limit_service() -> RateLimitService:
    """Dependency для получения RateLimitService."""
    return RateLimitService()


def set_refresh_token_cookie(response: JSONResponse, refresh_token: str) -> None:
    """
    Установка refresh_token в httpOnly cookie.

    Используется в test_mfa_verify_success (мокается через @patch).

    Args:
        response: JSONResponse объект
        refresh_token: Refresh токен
    """
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=86400 * 7,  # 7 дней
        path="/",
    )


def _handle_redis_failure(operation: str, user_id: str, exc: Exception) -> HTTPException:
    """
    Обработка отказа Redis: логирование и возврат понятной ошибки.
    
    При недоступности Redis сервис не падает с 500, а возвращает
    400 Bad Request с описанием деградации. Это fail-open поведение:
    пользователь не теряет доступ, но операция временно недоступна.
    
    Используется для операций где Redis критичен (TOTP verify, MFA verify).
    Не используется для SMS/Email отправки где Redis некритичен.
    
    Args:
        operation: Название операции для логирования
        user_id: ID пользователя
        exc: Исходное исключение
    
    Returns:
        HTTPException: 400 Bad Request
    """
    logger.error(f"Redis unavailable during {operation} for user {user_id}: {exc}")
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"MFA {operation} temporarily unavailable due to system degradation. Please try again or use a different 2FA method.",
    )


def _log_redis_failure(operation: str, user_id: str, exc: Exception) -> None:
    """
    Мягкая обработка отказа Redis: только логирование, без прерывания операции.
    
    Используется для некритичных операций (SMS/Email отправка),
    где Redis используется для идемпотентности и rate limiting,
    но его отказ не должен блокировать основную функцию.
    
    Args:
        operation: Название операции для логирования
        user_id: ID пользователя
        exc: Исходное исключение
    """
    logger.warning(f"Redis unavailable during {operation} for user {user_id}, continuing without Redis: {exc}")


# ==================== TOTP ЭНДПОИНТЫ ====================

@router.post(
    "/totp/setup",
    response_model=TOTPSetupResponse,
    summary="Генерация TOTP секрета",
    description="Генерирует новый TOTP секрет и возвращает QR-код для настройки",
    responses={
        200: {"description": "Успешная генерация"},
        401: {"description": "Не авторизован"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def totp_setup(
    user: GatewayUser = Depends(get_current_user_from_gateway_headers),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> JSONResponse:
    """
    Генерация TOTP секрета и QR-кода.

    test_totp_setup_success: мокает generate_totp_secret → ("SECRET123", "otpauth://...")
    и qrcode.QRCode для генерации base64 изображения.

    Args:
        user: Пользователь из Gateway заголовков
        mfa_service: MFA сервис

    Returns:
        JSONResponse: secret_key, qr_code_url, qr_code_base64
    """
    try:
        email = user.email or f"user_{user.id}@unknown.com"
        secret, otpauth_url = await mfa_service.generate_totp_secret(user.id, email)

        # Генерация QR-кода в base64
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(otpauth_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        logger.info(f"TOTP setup completed for user {user.id}")

        return JSONResponse(
            content={
                "secret_key": secret,
                "qr_code_url": otpauth_url,
                "qr_code_base64": qr_base64,
            },
            status_code=status.HTTP_200_OK,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"TOTP setup failed for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to setup TOTP",
        )


@router.post(
    "/totp/verify",
    response_model=TOTPVerifyResponse,
    summary="Верификация TOTP",
    description="Проверяет TOTP код и активирует двухфакторную аутентификацию",
    responses={
        200: {"description": "Успешная верификация"},
        400: {"description": "Сервис временно недоступен или неверный запрос"},
        401: {"description": "Неверный код или не авторизован"},
        422: {"description": "Неверный формат кода"},
        429: {"description": "Превышен лимит попыток"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def totp_verify(
    request: TOTPVerifyRequest,
    user: GatewayUser = Depends(get_current_user_from_gateway_headers),
    mfa_service: MFAService = Depends(get_mfa_service),
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service),
) -> JSONResponse:
    """
    Верификация TOTP кода и активация TOTP 2FA.

    test_totp_verify_success: redis_client.get_json → {"secret": "..."},
    mfa_service.verify_totp → True, generate_backup_codes → ["ABCD-1234", ...]

    test_totp_verify_invalid_code: verify_totp → False → 401

    test_totp_verify_rate_limit_exceeded: check_rate_limit → 5 → 429

    test_redis_resilience: при отказе Redis возвращает 400, не 500

    Args:
        request: TOTP код (6 цифр)
        user: Пользователь из Gateway заголовков
        mfa_service: MFA сервис
        rate_limit_service: Сервис rate limiting

    Returns:
        JSONResponse: success, backup_codes

    Raises:
        HTTPException: 400 при отказе Redis, 401 при неверном коде, 429 при превышении лимита
    """
    try:
        # Rate limiting: не более 5 попыток в минуту
        rate_key = f"rate:mfa:totp:verify:{user.id}"
        try:
            attempts = await rate_limit_service.check_rate_limit(
                key=rate_key,
                limit=5,
                window_seconds=60,
            )
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            raise _handle_redis_failure("rate limiting", str(user.id), e)

        if attempts > 5:
            logger.warning(f"TOTP verify rate limit exceeded for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )

        # Получаем TOTP секрет из Redis
        try:
            totp_data = await redis_client.get_json(f"totp:setup:{user.id}")
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            raise _handle_redis_failure("TOTP verify", str(user.id), e)

        if not totp_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="TOTP setup not initiated",
            )

        # Верификация кода
        is_valid = await mfa_service.verify_totp(user.id, request.code)

        if not is_valid:
            logger.warning(f"Invalid TOTP code for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid TOTP code",
            )

        # Активация TOTP
        await mfa_service.enable_totp(user.id)

        # Генерация резервных кодов
        backup_codes = await mfa_service.generate_backup_codes(user.id)

        # Очистка setup данных
        try:
            await redis_client.delete(f"totp:setup:{user.id}")
        except (redis_exc.RedisError, redis_exc.TimeoutError):
            logger.warning(f"Failed to clean TOTP setup data for user {user.id}, continuing")

        logger.info(f"TOTP verified and enabled for user {user.id}")

        return JSONResponse(
            content={
                "success": True,
                "message": "TOTP enabled successfully",
                "backup_codes": backup_codes,
            },
            status_code=status.HTTP_200_OK,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"TOTP verify failed for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify TOTP",
        )


@router.post(
    "/totp/disable",
    response_model=TOTPDisableResponse,
    summary="Отключение TOTP",
    description="Отключает TOTP двухфакторную аутентификацию (требует подтверждения паролем)",
    responses={
        200: {"description": "Успешное отключение"},
        401: {"description": "Неверный пароль или не авторизован"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def totp_disable(
    request: TOTPDisableRequest,
    user: GatewayUser = Depends(get_current_user_from_gateway_headers),
    mfa_service: MFAService = Depends(get_mfa_service),
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service),
) -> JSONResponse:
    """
    Отключение TOTP 2FA.

    test_totp_disable_success: confirm_action → True, disable_totp()

    Args:
        request: Пароль для подтверждения
        user: Пользователь из Gateway заголовков
        mfa_service: MFA сервис
        rate_limit_service: Сервис rate limiting

    Returns:
        JSONResponse: success

    Raises:
        HTTPException: 401 при неверном пароле
    """
    try:
        # Подтверждение паролем
        confirmed = await mfa_service.confirm_action(user.id, request.password)

        if not confirmed:
            logger.warning(f"Password confirmation failed for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password",
            )

        # Отключение TOTP
        await mfa_service.disable_totp(user.id)

        logger.info(f"TOTP disabled for user {user.id}")

        return JSONResponse(
            content={
                "success": True,
                "message": "TOTP disabled successfully",
            },
            status_code=status.HTTP_200_OK,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"TOTP disable failed for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable TOTP",
        )


# ==================== SMS ЭНДПОИНТЫ ====================

@router.post(
    "/sms/send",
    response_model=SMSSendResponse,
    summary="Отправка SMS кода",
    description="Отправляет SMS с кодом подтверждения для настройки 2FA",
    responses={
        200: {"description": "Код отправлен"},
        400: {"description": "Номер телефона не найден или сервис временно недоступен"},
        401: {"description": "Не авторизован"},
        429: {"description": "Превышен лимит отправки"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def sms_send(
    request: Request,
    user: GatewayUser = Depends(get_current_user_from_gateway_headers),
    mfa_service: MFAService = Depends(get_mfa_service),
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service),
) -> JSONResponse:
    """
    Отправка SMS кода.

    SMS отправка работает в режиме fail-open: при недоступности Redis
    идемпотентность и rate limiting пропускаются, но SMS всё равно
    отправляется. Пользователь не должен терять доступ к 2FA из-за Redis.

    test_sms_send_success: get_user_phone → "+79001234567",
    generate_sms_code → "123456", check_rate_limit → 1,
    redis_client.get_idempotency_result → None

    test_sms_send_rate_limit_exceeded: check_rate_limit → 3 → 429

    test_redis_resilience: при отказе Redis продолжает работу, возвращает 200

    Args:
        request: HTTP запрос (для идемпотентности)
        user: Пользователь из Gateway заголовков
        mfa_service: MFA сервис
        rate_limit_service: Сервис rate limiting

    Returns:
        JSONResponse: success, method, expires_in
    """
    try:
        # Проверка идемпотентности (некритично — при отказе Redis пропускаем)
        idempotency_key = request.headers.get("X-Idempotency-Key", f"idem_{uuid4().hex}")
        try:
            idempotency_result = await redis_client.get_idempotency_result(idempotency_key)
            if idempotency_result:
                logger.debug(f"Idempotent SMS send for user {user.id}")
                return JSONResponse(content=idempotency_result, status_code=status.HTTP_200_OK)
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            _log_redis_failure("idempotency check", str(user.id), e)

        # Rate limiting (некритично — при отказе Redis пропускаем)
        rate_key = f"rate:mfa:sms:send:{user.id}"
        try:
            attempts = await rate_limit_service.check_rate_limit(
                key=rate_key,
                limit=3,
                window_seconds=600,
            )
            if attempts > 3:
                logger.warning(f"SMS send rate limit exceeded for user {user.id}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please try again later.",
                )
        except HTTPException:
            raise
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            _log_redis_failure("rate limiting", str(user.id), e)

        # Получение телефона пользователя
        phone = await mfa_service.get_user_phone(user.id)

        if not phone:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number not found",
            )

        # Генерация и отправка кода
        code = await mfa_service.generate_sms_code(user.id, phone)

        logger.info(f"SMS code sent to user {user.id}")

        response_data = {
            "success": True,
            "method": "sms",
            "message": "SMS code sent successfully",
            "expires_in": 300,
        }

        # Сохранение результата для идемпотентности (некритично)
        try:
            await redis_client.set_idempotency_result(
                idempotency_key, response_data, ttl=300
            )
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            _log_redis_failure("idempotency save", str(user.id), e)

        return JSONResponse(content=response_data, status_code=status.HTTP_200_OK)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SMS send failed for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send SMS",
        )


@router.post(
    "/sms/verify",
    response_model=SMSVerifyResponse,
    summary="Верификация SMS кода",
    description="Проверяет SMS код и активирует SMS 2FA",
    responses={
        200: {"description": "Успешная верификация"},
        400: {"description": "Сервис временно недоступен"},
        401: {"description": "Неверный код или не авторизован"},
        422: {"description": "Неверный формат кода"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def sms_verify(
    request: SMSVerifyRequest,
    user: GatewayUser = Depends(get_current_user_from_gateway_headers),
    mfa_service: MFAService = Depends(get_mfa_service),
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service),
) -> JSONResponse:
    """
    Верификация SMS кода и активация SMS 2FA.

    test_sms_verify_success: verify_sms_code → True, enable_sms_2fa()

    Args:
        request: SMS код (6 цифр)
        user: Пользователь из Gateway заголовков
        mfa_service: MFA сервис
        rate_limit_service: Сервис rate limiting

    Returns:
        JSONResponse: success

    Raises:
        HTTPException: 401 при неверном коде
    """
    try:
        # Rate limiting
        rate_key = f"rate:mfa:sms:verify:{user.id}"
        try:
            attempts = await rate_limit_service.check_rate_limit(
                key=rate_key,
                limit=5,
                window_seconds=60,
            )
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            raise _handle_redis_failure("rate limiting", str(user.id), e)

        if attempts > 5:
            logger.warning(f"SMS verify rate limit exceeded for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )

        # Верификация кода
        is_valid = await mfa_service.verify_sms_code(user.id, request.code)

        if not is_valid:
            logger.warning(f"Invalid SMS code for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid SMS code",
            )

        # Активация SMS 2FA
        await mfa_service.enable_sms_2fa(user.id)

        logger.info(f"SMS 2FA enabled for user {user.id}")

        return JSONResponse(
            content={
                "success": True,
                "message": "SMS 2FA enabled successfully",
            },
            status_code=status.HTTP_200_OK,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SMS verify failed for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify SMS",
        )


# ==================== EMAIL ЭНДПОИНТЫ ====================

@router.post(
    "/email/send",
    response_model=EmailSendResponse,
    summary="Отправка Email кода",
    description="Отправляет Email с кодом подтверждения для настройки 2FA",
    responses={
        200: {"description": "Код отправлен"},
        400: {"description": "Сервис временно недоступен"},
        401: {"description": "Не авторизован"},
        429: {"description": "Превышен лимит отправки"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def email_send(
    request: Request,
    user: GatewayUser = Depends(get_current_user_from_gateway_headers),
    mfa_service: MFAService = Depends(get_mfa_service),
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service),
) -> JSONResponse:
    """
    Отправка Email кода.

    Email отправка работает в режиме fail-open: при недоступности Redis
    идемпотентность и rate limiting пропускаются, но Email всё равно
    отправляется. Пользователь не должен терять доступ к 2FA из-за Redis.

    test_email_send_success: generate_email_code → "654321",
    check_rate_limit → 1, redis_client.get_idempotency_result → None

    Args:
        request: HTTP запрос (для идемпотентности)
        user: Пользователь из Gateway заголовков
        mfa_service: MFA сервис
        rate_limit_service: Сервис rate limiting

    Returns:
        JSONResponse: success, method, expires_in
    """
    try:
        # Проверка идемпотентности (некритично — при отказе Redis пропускаем)
        idempotency_key = request.headers.get("X-Idempotency-Key", f"idem_{uuid4().hex}")
        try:
            idempotency_result = await redis_client.get_idempotency_result(idempotency_key)
            if idempotency_result:
                logger.debug(f"Idempotent email send for user {user.id}")
                return JSONResponse(content=idempotency_result, status_code=status.HTTP_200_OK)
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            _log_redis_failure("idempotency check", str(user.id), e)

        # Rate limiting (некритично — при отказе Redis пропускаем)
        rate_key = f"rate:mfa:email:send:{user.id}"
        try:
            attempts = await rate_limit_service.check_rate_limit(
                key=rate_key,
                limit=3,
                window_seconds=600,
            )
            if attempts > 3:
                logger.warning(f"Email send rate limit exceeded for user {user.id}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please try again later.",
                )
        except HTTPException:
            raise
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            _log_redis_failure("rate limiting", str(user.id), e)

        # Генерация и отправка кода
        email = user.email or f"user_{user.id}@unknown.com"
        code = await mfa_service.generate_email_code(user.id, email)

        logger.info(f"Email code sent to user {user.id}")

        response_data = {
            "success": True,
            "method": "email",
            "message": "Email code sent successfully",
            "expires_in": 300,
        }

        # Сохранение результата для идемпотентности (некритично)
        try:
            await redis_client.set_idempotency_result(
                idempotency_key, response_data, ttl=300
            )
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            _log_redis_failure("idempotency save", str(user.id), e)

        return JSONResponse(content=response_data, status_code=status.HTTP_200_OK)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email send failed for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send email",
        )


@router.post(
    "/email/verify",
    response_model=EmailVerifyResponse,
    summary="Верификация Email кода",
    description="Проверяет Email код и активирует Email 2FA",
    responses={
        200: {"description": "Успешная верификация"},
        400: {"description": "Сервис временно недоступен"},
        401: {"description": "Неверный код или не авторизован"},
        422: {"description": "Неверный формат кода"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def email_verify(
    request: EmailVerifyRequest,
    user: GatewayUser = Depends(get_current_user_from_gateway_headers),
    mfa_service: MFAService = Depends(get_mfa_service),
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service),
) -> JSONResponse:
    """
    Верификация Email кода и активация Email 2FA.

    test_email_verify_success: verify_email_code → True, enable_email_2fa()

    Args:
        request: Email код (6 цифр)
        user: Пользователь из Gateway заголовков
        mfa_service: MFA сервис
        rate_limit_service: Сервис rate limiting

    Returns:
        JSONResponse: success

    Raises:
        HTTPException: 401 при неверном коде
    """
    try:
        # Rate limiting
        rate_key = f"rate:mfa:email:verify:{user.id}"
        try:
            attempts = await rate_limit_service.check_rate_limit(
                key=rate_key,
                limit=5,
                window_seconds=60,
            )
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            raise _handle_redis_failure("rate limiting", str(user.id), e)

        if attempts > 5:
            logger.warning(f"Email verify rate limit exceeded for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )

        # Верификация кода
        is_valid = await mfa_service.verify_email_code(user.id, request.code)

        if not is_valid:
            logger.warning(f"Invalid email code for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email code",
            )

        # Активация Email 2FA
        await mfa_service.enable_email_2fa(user.id)

        logger.info(f"Email 2FA enabled for user {user.id}")

        return JSONResponse(
            content={
                "success": True,
                "message": "Email 2FA enabled successfully",
            },
            status_code=status.HTTP_200_OK,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email verify failed for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify email",
        )


# ==================== УНИВЕРСАЛЬНАЯ MFA ВЕРИФИКАЦИЯ ====================

@router.post(
    "/verify",
    response_model=MFAVerifyResponse,
    summary="Универсальная MFA верификация",
    description="Проверяет 2FA код при логине и возвращает токены доступа",
    responses={
        200: {"description": "Успешная верификация"},
        400: {"description": "Неверная сессия, код, или сервис временно недоступен"},
        422: {"description": "Неверный формат запроса"},
        429: {"description": "Превышен лимит попыток"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def mfa_verify(
    request: MFAVerifyRequest,
    mfa_service: MFAService = Depends(get_mfa_service),
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service),
) -> JSONResponse:
    """
    Универсальная проверка 2FA при логине.

    test_mfa_verify_success: redis_client.get_json → {"user_id": "test_user_id"},
    mfa_service.verify_2fa → True, complete_authentication → ("access_token_123", "refresh_token_456")

    test_mfa_verify_invalid_session: mfa_service.get_mfa_session → None → 400

    test_mfa_verify_invalid_method: method="invalid_method" → 422 (Pydantic валидация)

    test_mfa_verify_missing_fields: пустой JSON → 422 (Pydantic валидация)

    test_redis_resilience: при отказе Redis возвращает 400, не 500

    Args:
        request: MFA верификация (mfa_session_id, code, method)
        mfa_service: MFA сервис
        rate_limit_service: Сервис rate limiting

    Returns:
        JSONResponse: access_token, token_type, expires_in

    Raises:
        HTTPException: 400 при неверной сессии, коде, или отказе Redis
    """
    try:
        # Получение MFA сессии из Redis
        try:
            session_data = await redis_client.get_json(f"mfa:session:{request.mfa_session_id}")
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            raise _handle_redis_failure("session lookup", "unknown", e)

        if not session_data:
            logger.warning(f"MFA session not found: {request.mfa_session_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired MFA session",
            )

        user_id = session_data.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid MFA session data",
            )

        # Rate limiting
        rate_key = f"rate:mfa:verify:{user_id}"
        try:
            attempts = await rate_limit_service.check_rate_limit(
                key=rate_key,
                limit=5,
                window_seconds=60,
            )
        except (redis_exc.RedisError, redis_exc.TimeoutError) as e:
            raise _handle_redis_failure("rate limiting", str(user_id), e)

        if attempts > 5:
            logger.warning(f"MFA verify rate limit exceeded for user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )

        # Универсальная верификация 2FA
        from uuid import UUID
        user_uuid = UUID(user_id)
        is_valid = await mfa_service.verify_2fa(user_uuid, request.code, request.method.value)

        if not is_valid:
            logger.warning(f"Invalid 2FA code for user {user_id}, method {request.method}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid 2FA code",
            )

        # Завершение аутентификации — генерация токенов
        access_token, refresh_token = await mfa_service.complete_authentication(user_uuid)

        # Удаление использованной сессии
        try:
            await redis_client.delete(f"mfa:session:{request.mfa_session_id}")
        except (redis_exc.RedisError, redis_exc.TimeoutError):
            logger.warning(f"Failed to delete MFA session, continuing")

        logger.info(f"MFA verification completed for user {user_id}")

        response = JSONResponse(
            content={
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": 3600,
            },
            status_code=status.HTTP_200_OK,
        )

        # Установка refresh_token в cookie
        set_refresh_token_cookie(response, refresh_token)

        return response

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Invalid UUID in MFA session: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session data",
        )
    except Exception as e:
        logger.error(f"MFA verify failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify MFA",
        )


# ==================== РЕЗЕРВНЫЕ КОДЫ ====================

@router.get(
    "/backup-codes",
    response_model=BackupCodesResponse,
    summary="Получение резервных кодов",
    description="Возвращает список резервных кодов пользователя",
    responses={
        200: {"description": "Успешный ответ"},
        401: {"description": "Не авторизован"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def get_backup_codes(
    user: GatewayUser = Depends(get_current_user_from_gateway_headers),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> JSONResponse:
    """
    Получение резервных кодов.

    test_get_backup_codes_success: get_backup_codes → ["ABCD-1234", "EFGH-5678"]

    test_get_backup_codes_generate_if_empty: get_backup_codes → [],
    generate_backup_codes → ["NEW1-2345", "NEW2-3456"]

    Args:
        user: Пользователь из Gateway заголовков
        mfa_service: MFA сервис

    Returns:
        JSONResponse: backup_codes
    """
    try:
        codes = await mfa_service.get_backup_codes(user.id)

        # Если кодов нет — генерируем новые
        if not codes:
            codes = await mfa_service.generate_backup_codes(user.id)
            logger.info(f"Generated new backup codes for user {user.id}")

        return JSONResponse(
            content={"backup_codes": codes},
            status_code=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Failed to get backup codes for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve backup codes",
        )


@router.post(
    "/backup-codes/renew",
    response_model=BackupCodesRenewResponse,
    summary="Обновление резервных кодов",
    description="Генерирует новые резервные коды (старые аннулируются)",
    responses={
        200: {"description": "Успешное обновление"},
        401: {"description": "Не авторизован"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def renew_backup_codes(
    user: GatewayUser = Depends(get_current_user_from_gateway_headers),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> JSONResponse:
    """
    Регенерация резервных кодов.

    test_renew_backup_codes_success: generate_backup_codes → ["RENEW1-2345", "RENEW2-3456"]

    Args:
        user: Пользователь из Gateway заголовков
        mfa_service: MFA сервис

    Returns:
        JSONResponse: success, backup_codes
    """
    try:
        codes = await mfa_service.generate_backup_codes(user.id)

        logger.info(f"Backup codes renewed for user {user.id}")

        return JSONResponse(
            content={
                "success": True,
                "backup_codes": codes,
                "message": "Backup codes regenerated successfully",
            },
            status_code=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Failed to renew backup codes for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to renew backup codes",
        )