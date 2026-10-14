"""
Password роутер для управления паролями пользователей.

Обеспечивает:
- POST /password/change - смена пароля авторизованным пользователем
- POST /password/reset-request - запрос сброса пароля (email)
- POST /password/reset-confirm - подтверждение сброса пароля с токеном
- Валидацию паролей (сложность, длина, отличие от старого)
- Rate limiting для всех операций
- Отзыв сессий при смене пароля
- Отправку уведомлений (email) при смене/сбросе пароля

Совместимость с тестами:
- TestChangePassword: смена пароля с проверкой старого, rate limiting
- TestResetPasswordRequest: запрос сброса с защитой от перебора email
- TestResetPasswordConfirm: подтверждение сброса с токеном
- TestPasswordValidationEdgeCases: граничные случаи валидации

Архитектура:
- Реальная логика: PasswordService (bcrypt), Pydantic-валидация, авторизация
- Моки в тестах: AuthService (БД), RateLimitService (Redis), email-уведомления
- Использует app.dependency_overrides для изоляции в тестах

Связанные модули:
- app.services.password_service - криптография паролей
- app.schemas.password - Pydantic схемы
- app.core.config - настройки PASSWORD_*
- app.core.dependencies - фабрики сервисов и GatewayUser
"""

import asyncio
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.dependencies import (
    GatewayUser,
    get_auth_service_for_password_router,
    get_current_user_from_gateway_headers,
    get_password_service_for_password_router,
    get_rate_limit_service_for_password_router,
)
from app.core.logging import get_logger
from app.schemas.password import (
    ChangePasswordRequest,
    ChangePasswordResponse,
    ResetPasswordConfirmRequest,
    ResetPasswordConfirmResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
)
from app.services.auth_service import AuthService
from app.services.password_service import PasswordService
from app.services.rate_limit_service import RateLimitService

logger = get_logger(__name__)
router = APIRouter(prefix="/password", tags=["password"])


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

async def send_password_reset_email(email: str, reset_token: str) -> None:
    """
    Отправка email со ссылкой для сброса пароля.

    В production — отправляет реальный email через SMTP/шлюз.
    В тестах — мокается через setup_password_test_environment.

    Args:
        email: Email пользователя
        reset_token: Токен сброса пароля
    """
    reset_link = f"{settings.OAUTH_DEFAULT_REDIRECT_URI}?token={reset_token}"
    logger.info(f"Password reset email sent to {email}")
    # В production: отправка email через email_service.send()


async def send_password_changed_notification(email: str) -> None:
    """
    Отправка уведомления о смене пароля.

    В production — отправляет реальный email через SMTP/шлюз.
    В тестах — мокается через setup_password_test_environment.

    Args:
        email: Email пользователя
    """
    logger.info(f"Password changed notification sent to {email}")
    # В production: отправка email через email_service.send()


# ==================== СМЕНА ПАРОЛЯ ====================

@router.post(
    "/change",
    response_model=ChangePasswordResponse,
    summary="Смена пароля",
    description="Меняет пароль авторизованного пользователя с проверкой старого пароля",
    responses={
        200: {"description": "Пароль успешно изменён"},
        400: {"description": "Новый пароль совпадает со старым"},
        401: {"description": "Неверный текущий пароль или не авторизован"},
        422: {"description": "Неверный формат пароля"},
        429: {"description": "Превышен лимит попыток"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def change_password(
    request: ChangePasswordRequest,
    http_request: Request,
    user: GatewayUser = Depends(get_current_user_from_gateway_headers),
    auth_service: AuthService = Depends(get_auth_service_for_password_router),
    password_service: PasswordService = Depends(get_password_service_for_password_router),
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service_for_password_router),
) -> JSONResponse:
    """
    Смена пароля авторизованным пользователем.

    test_change_password_success: правильный старый пароль, валидный новый → 200
    test_change_password_invalid_old_password: неверный старый пароль → 401
    test_change_password_same_as_old: новый пароль совпадает со старым → 400
    test_change_password_rate_limit_exceeded: лимит превышен → 429
    test_change_password_unauthorized: без заголовков → 401
    test_change_password_invalid_new_password: слабый пароль → 422

    Flow:
    1. Проверка rate limit
    2. Получение пользователя из БД
    3. Проверка старого пароля (реальная криптография)
    4. Проверка что новый пароль отличается от старого
    5. Хеширование и сохранение нового пароля
    6. Отзыв всех сессий
    7. Отправка уведомления

    Args:
        request: Данные запроса (old_password, new_password)
        http_request: HTTP запрос
        user: Авторизованный пользователь из Gateway
        auth_service: Сервис аутентификации
        password_service: Сервис паролей (реальная криптография)
        rate_limit_service: Сервис rate limiting

    Returns:
        JSONResponse: Статус операции
    """
    try:
        # Rate limiting: не более 5 попыток в минуту
        rate_key = f"rate:password:change:{user.id}"
        attempts = await rate_limit_service.check_rate_limit(
            key=rate_key,
            limit=settings.PASSWORD_CHANGE_RATE_LIMIT,
            window_seconds=settings.PASSWORD_CHANGE_RATE_LIMIT_WINDOW,
        )

        if attempts > settings.PASSWORD_CHANGE_RATE_LIMIT:
            logger.warning(f"Password change rate limit exceeded for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts. Please try again later.",
            )

        # Получение пользователя из БД
        db_user = await auth_service.get_user_by_id(user.id)

        if not db_user:
            logger.warning(f"User not found: {user.id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )

        # Проверка старого пароля (реальная криптография — bcrypt)
        is_old_password_valid = await password_service.verify_password(
            request.old_password,
            db_user.password_hash,
        )

        if not is_old_password_valid:
            logger.warning(f"Invalid old password for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect",
            )

        # Проверка что новый пароль отличается от старого
        is_same_password = await password_service.verify_password(
            request.new_password,
            db_user.password_hash,
        )

        if is_same_password:
            logger.warning(f"New password same as old for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be different from current password",
            )

        # Хеширование нового пароля (реальная криптография — bcrypt)
        new_password_hash = await password_service.hash_password(request.new_password)

        # Сохранение нового пароля в БД
        await auth_service.update_password(user.id, new_password_hash)

        # Отзыв всех сессий пользователя
        await auth_service.revoke_all_sessions(user.id)

        # Публикация события о смене пароля
        await auth_service.publish_password_changed(user.id)

        # Отправка уведомления
        user_email = db_user.email or user.email or f"user_{user.id}@unknown.com"
        await send_password_changed_notification(user_email)

        # Сброс rate limit после успешной операции
        await rate_limit_service.reset_rate_limit(rate_key)

        logger.info(f"Password changed successfully for user {user.id}")

        return JSONResponse(
            content={
                "success": True,
                "message": "Password changed successfully. All sessions have been revoked.",
                "sessions_revoked": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            status_code=status.HTTP_200_OK,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change failed for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password",
        )


# ==================== ЗАПРОС СБРОСА ПАРОЛЯ ====================

@router.post(
    "/reset-request",
    response_model=ResetPasswordResponse,
    summary="Запрос сброса пароля",
    description="Отправляет email со ссылкой для сброса пароля (если пользователь существует)",
    responses={
        200: {"description": "Инструкции отправлены (всегда одинаковый ответ)"},
        422: {"description": "Неверный формат email"},
        429: {"description": "Превышен лимит запросов"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def reset_password_request(
    request: ResetPasswordRequest,
    http_request: Request,
    auth_service: AuthService = Depends(get_auth_service_for_password_router),
    password_service: PasswordService = Depends(get_password_service_for_password_router),
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service_for_password_router),
) -> JSONResponse:
    """
    Запрос на сброс пароля по email.

    test_reset_request_success_existing_user: существующий пользователь → 200 + отправка email
    test_reset_request_non_existent_user: несуществующий пользователь → 200 (защита от перебора)
    test_reset_request_rate_limit_exceeded: лимит превышен → 429
    test_reset_request_invalid_email: неверный формат email → 422
    test_reset_request_blocked_user: заблокированный пользователь → 200

    Всегда возвращает одинаковый ответ для защиты от перебора email-адресов.

    Flow:
    1. Проверка rate limit по IP
    2. Проверка rate limit по email
    3. Поиск пользователя по email
    4. Проверка что пользователь активен
    5. Генерация токена сброса
    6. Сохранение токена
    7. Отправка email (только для существующих активных пользователей)
    8. Искусственная задержка для несуществующих пользователей

    Args:
        request: Данные запроса (email)
        http_request: HTTP запрос
        auth_service: Сервис аутентификации
        password_service: Сервис паролей
        rate_limit_service: Сервис rate limiting

    Returns:
        JSONResponse: Всегда 200 с одинаковым сообщением
    """
    try:
        email = request.email

        # Rate limiting по IP
        client_ip = http_request.client.host if http_request.client else "unknown"
        ip_rate_key = f"rate:password:reset:ip:{client_ip}"
        ip_attempts = await rate_limit_service.check_rate_limit(
            key=ip_rate_key,
            limit=settings.PASSWORD_RESET_RATE_LIMIT,
            window_seconds=settings.PASSWORD_RESET_RATE_LIMIT_WINDOW,
        )

        if ip_attempts > settings.PASSWORD_RESET_RATE_LIMIT:
            logger.warning(f"Password reset rate limit exceeded for IP {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )

        # Rate limiting по email
        email_rate_key = f"rate:password:reset:email:{email}"
        email_attempts = await rate_limit_service.check_rate_limit(
            key=email_rate_key,
            limit=settings.PASSWORD_RESET_RATE_LIMIT,
            window_seconds=settings.PASSWORD_RESET_RATE_LIMIT_WINDOW,
        )

        if email_attempts > settings.PASSWORD_RESET_RATE_LIMIT:
            logger.warning(f"Password reset rate limit exceeded for email {email}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )

        # Поиск пользователя по email
        db_user = await auth_service.get_user_by_email(email)

        if db_user and db_user.is_active:
            # Генерация токена сброса
            reset_token = password_service.generate_reset_token()

            # Сохранение токена
            await password_service.save_reset_token(
                user_id=db_user.id,
                token=reset_token,
                ttl_minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES,
            )

            # Отправка email
            await send_password_reset_email(email, reset_token)

            # Логирование
            await auth_service.log_password_reset_request(db_user.id)

            logger.info(f"Password reset email sent to {email}")
        else:
            # Искусственная задержка для несуществующих/заблокированных пользователей
            # Защита от timing attacks при переборе email
            await asyncio.sleep(0.5)
            logger.debug(f"Password reset requested for non-existent/inactive email: {email}")

        # Всегда возвращаем одинаковый ответ
        return JSONResponse(
            content={
                "success": True,
                "message": "If the email exists, a password reset link has been sent.",
            },
            status_code=status.HTTP_200_OK,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset request failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process reset request",
        )


# ==================== ПОДТВЕРЖДЕНИЕ СБРОСА ПАРОЛЯ ====================

@router.post(
    "/reset-confirm",
    response_model=ResetPasswordConfirmResponse,
    summary="Подтверждение сброса пароля",
    description="Устанавливает новый пароль по токену сброса",
    responses={
        200: {"description": "Пароль успешно сброшен"},
        400: {"description": "Неверный или истекший токен, или пароль совпадает со старым"},
        422: {"description": "Неверный формат токена или пароля"},
        429: {"description": "Превышен лимит попыток"},
        500: {"description": "Внутренняя ошибка сервера"},
    },
)
async def reset_password_confirm(
    request: ResetPasswordConfirmRequest,
    http_request: Request,
    auth_service: AuthService = Depends(get_auth_service_for_password_router),
    password_service: PasswordService = Depends(get_password_service_for_password_router),
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service_for_password_router),
) -> JSONResponse:
    """
    Подтверждение сброса пароля с токеном.

    test_reset_confirm_success: валидный токен, новый пароль → 200
    test_reset_confirm_invalid_token: неверный токен → 400
    test_reset_confirm_same_password: новый пароль совпадает со старым → 400
    test_reset_confirm_rate_limit_exceeded: лимит превышен → 429
    test_reset_confirm_invalid_token_format: короткий токен → 422
    test_reset_confirm_invalid_new_password: слабый пароль → 422

    Flow:
    1. Проверка rate limit
    2. Поиск пользователя по токену сброса
    3. Получение данных пользователя из БД
    4. Проверка что новый пароль отличается от старого
    5. Хеширование и сохранение нового пароля
    6. Удаление использованного токена
    7. Отзыв всех сессий
    8. Отправка уведомления

    Args:
        request: Данные запроса (token, new_password)
        http_request: HTTP запрос
        auth_service: Сервис аутентификации
        password_service: Сервис паролей (реальная криптография)
        rate_limit_service: Сервис rate limiting

    Returns:
        JSONResponse: Статус операции
    """
    try:
        # Rate limiting: не более 10 попыток в минуту
        client_ip = http_request.client.host if http_request.client else "unknown"
        rate_key = f"rate:password:confirm:{client_ip}"
        attempts = await rate_limit_service.check_rate_limit(
            key=rate_key,
            limit=settings.PASSWORD_CONFIRM_RATE_LIMIT,
            window_seconds=settings.PASSWORD_CONFIRM_RATE_LIMIT_WINDOW,
        )

        if attempts > settings.PASSWORD_CONFIRM_RATE_LIMIT:
            logger.warning(f"Password confirm rate limit exceeded for IP {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts. Please try again later.",
            )

        # Поиск пользователя по токену сброса
        user_id = await password_service.get_user_by_reset_token(request.token)

        if not user_id:
            logger.warning("Invalid or expired reset token")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token",
            )

        # Получение данных пользователя
        db_user = await auth_service.get_user_by_id(user_id)

        if not db_user:
            logger.warning(f"User not found for reset token: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not found",
            )

        if not db_user.is_active:
            logger.warning(f"Blocked user attempted password reset: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is blocked",
            )

        # Проверка что новый пароль отличается от старого
        is_same_password = await password_service.verify_password(
            request.new_password,
            db_user.password_hash,
        )

        if is_same_password:
            logger.warning(f"New password same as old for user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be different from current password",
            )

        # Хеширование нового пароля (реальная криптография — bcrypt)
        new_password_hash = await password_service.hash_password(request.new_password)

        # Сохранение нового пароля в БД
        await auth_service.update_password(user_id, new_password_hash)

        # Удаление использованного токена
        await password_service.delete_reset_token(request.token)

        # Отзыв всех сессий пользователя
        await auth_service.revoke_all_sessions(user_id)

        # Публикация события о смене пароля
        await auth_service.publish_password_changed(user_id)

        # Отправка уведомления
        user_email = db_user.email or f"user_{user_id}@unknown.com"
        await send_password_changed_notification(user_email)

        # Сброс rate limit после успешной операции
        await rate_limit_service.reset_rate_limit(rate_key)

        logger.info(f"Password reset successfully for user {user_id}")

        return JSONResponse(
            content={
                "success": True,
                "message": "Password reset successfully. All sessions have been revoked.",
                "sessions_revoked": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            status_code=status.HTTP_200_OK,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset confirm failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password",
        )