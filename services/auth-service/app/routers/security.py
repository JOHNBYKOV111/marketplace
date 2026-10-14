"""
Роутер для управления безопасностью пользователя.

Обрабатывает:
- Настройку двухфакторной аутентификации (TOTP)
- Включение/отключение MFA
- Получение MFA статуса
- Генерацию резервных кодов
- Верификацию MFA
- Управление устройствами доверия
"""

from typing import Annotated, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import (
    get_current_user,
    get_user_security_settings_repository,
    get_user_security_service,
    get_audit_service,
)
from app.core.exceptions import UnauthorizedException, AppException, BadRequestException
from app.core.logging import get_logger
from app.core.rate_limit import RateLimiter
from app.core.security import generate_mfa_secret, generate_mfa_backup_codes
from app.models.user import User
from app.models.user_security_settings import UserSecuritySettings
from app.repositories.user_security_settings_repository import UserSecuritySettingsRepository
from app.schemas.security import (
    MFAStatusResponse,
    MFAEnableRequest,
    MFAEnableResponse,
    MFADisableRequest,
    MFADisableResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
    BackupCodesResponse,
    TrustedDeviceRequest,
    TrustedDeviceResponse,
    SecuritySettingsResponse,
    SecuritySettingsUpdateRequest,
    MFAChallengeResponse,
)
from app.services.audit_service import AuditService
from app.services.totp_service import TOTPService
from app.services.user_security_service import UserSecurityService

router = APIRouter(prefix="", tags=["security"])
logger = get_logger(__name__)

# Rate limiters
mfa_limiter = RateLimiter(limit=10, window=300)
backup_limiter = RateLimiter(limit=3, window=300)


@router.get(
    "/mfa/status",
    response_model=MFAStatusResponse,
    responses={
        200: {"description": "Статус MFA"},
        401: {"description": "Не авторизован"},
    },
)
async def get_mfa_status(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    settings_repo: Annotated[UserSecuritySettingsRepository, Depends(get_user_security_settings_repository)],
    security_service: Annotated[UserSecurityService, Depends(get_user_security_service)],
) -> MFAStatusResponse:
    """
    Получение статуса MFA пользователя.

    Args:
        request: HTTP запрос
        current_user: Текущий пользователь
        settings_repo: Репозиторий настроек безопасности
        security_service: Сервис безопасности

    Returns:
        MFAStatusResponse: Статус MFA
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        # Получение настроек
        settings = await settings_repo.get_by_user_id(current_user.id)

        if not settings:
            return MFAStatusResponse(
                totp_enabled=False,
                has_backup_codes=False,
                is_setup_complete=False,
            )

        # Проверка, завершена ли настройка
        is_setup_complete = settings.totp_enabled and settings.totp_secret is not None

        # Количество резервных кодов
        backup_codes_count = len(settings.totp_backup_codes) if settings.totp_backup_codes else 0

        return MFAStatusResponse(
            totp_enabled=settings.totp_enabled,
            has_backup_codes=backup_codes_count > 0,
            is_setup_complete=is_setup_complete,
            backup_codes_count=backup_codes_count,
            last_password_change=settings.last_password_change,
        )

    except Exception as e:
        logger.error(f"Failed to get MFA status for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get MFA status",
        )


@router.post(
    "/mfa/setup",
    response_model=MFAEnableResponse,
    responses={
        200: {"description": "MFA настроен"},
        400: {"description": "Ошибка настройки"},
        401: {"description": "Не авторизован"},
        409: {"description": "MFA уже включен"},
    },
)
async def setup_mfa(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    settings_repo: Annotated[UserSecuritySettingsRepository, Depends(get_user_security_settings_repository)],
    security_service: Annotated[UserSecurityService, Depends(get_user_security_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> MFAEnableResponse:
    """
    Настройка MFA (генерация секрета и QR кода).

    Args:
        request: HTTP запрос
        current_user: Текущий пользователь
        settings_repo: Репозиторий настроек безопасности
        security_service: Сервис безопасности
        audit_service: Сервис аудита

    Returns:
        MFAEnableResponse: Секретный ключ и QR URL
    """
    client_ip = request.client.host if request.client else "unknown"

    # Rate limiting
    if not await mfa_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many MFA setup attempts. Please try again later.",
        )

    try:
        # Проверка, не включен ли уже MFA
        settings = await settings_repo.get_by_user_id(current_user.id)

        if settings and settings.totp_enabled:
            raise AppException("MFA is already enabled", code="MFA_ALREADY_ENABLED", status_code=409)

        # Генерация секрета
        secret = generate_mfa_secret()
        totp_service = TOTPService()

        # Создание OTPAuth URL для QR кода
        otpauth_url = totp_service.get_otpauth_url(
            secret=secret,
            account_name=current_user.email,
            issuer="Marketplace",
        )

        # Сохранение секрета (но не включение MFA до верификации)
        if settings:
            await security_service.update_settings(
                current_user.id,
                totp_secret=secret,
                totp_enabled=False,
            )
        else:
            await security_service.create_settings(
                current_user.id,
                totp_secret=secret,
                totp_enabled=False,
            )

        await audit_service.log_mfa_setup_started(current_user.id, client_ip)

        logger.info(f"MFA setup started for user: {current_user.id}")

        return MFAEnableResponse(
            success=True,
            message="MFA setup initiated. Verify with TOTP code.",
            secret=secret,
            otpauth_url=otpauth_url,
        )

    except AppException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
        )

    except Exception as e:
        logger.error(f"Failed to setup MFA for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to setup MFA",
        )


@router.post(
    "/mfa/verify",
    response_model=MFAVerifyResponse,
    responses={
        200: {"description": "MFA верифицирован"},
        400: {"description": "Неверный код"},
        401: {"description": "Не авторизован"},
        422: {"description": "Ошибка валидации"},
    },
)
async def verify_mfa(
    request: Request,
    verify_data: MFAVerifyRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    settings_repo: Annotated[UserSecuritySettingsRepository, Depends(get_user_security_settings_repository)],
    security_service: Annotated[UserSecurityService, Depends(get_user_security_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> MFAVerifyResponse:
    """
    Верификация TOTP кода для включения MFA.

    Args:
        request: HTTP запрос
        verify_data: Данные верификации
        current_user: Текущий пользователь
        settings_repo: Репозиторий настроек безопасности
        security_service: Сервис безопасности
        audit_service: Сервис аудита

    Returns:
        MFAVerifyResponse: Статус верификации
    """
    client_ip = request.client.host if request.client else "unknown"

    # Rate limiting
    if not await mfa_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many verification attempts. Please try again later.",
        )

    try:
        # Получение настроек
        settings = await settings_repo.get_by_user_id(current_user.id)

        if not settings or not settings.totp_secret:
            raise AppException("MFA not configured", code="MFA_NOT_CONFIGURED", status_code=400)

        if settings.totp_enabled:
            raise AppException("MFA is already enabled", code="MFA_ALREADY_ENABLED", status_code=409)

        # Верификация кода
        totp_service = TOTPService()
        is_valid = totp_service.verify(settings.totp_secret, verify_data.totp_code)

        if not is_valid:
            await audit_service.log_mfa_verification_failed(current_user.id, client_ip)
            raise AppException("Invalid TOTP code", code="INVALID_TOTP_CODE", status_code=400)

        # Включение MFA
        await security_service.enable_mfa(current_user.id)

        # Генерация резервных кодов
        backup_codes = generate_mfa_backup_codes()
        await security_service.save_backup_codes(current_user.id, backup_codes)

        await audit_service.log_mfa_enabled(current_user.id, client_ip)

        logger.info(f"MFA verified and enabled for user: {current_user.id}")

        return MFAVerifyResponse(
            success=True,
            message="MFA verified and enabled successfully",
            backup_codes=backup_codes,
        )

    except AppException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
        )

    except Exception as e:
        logger.error(f"Failed to verify MFA for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify MFA",
        )


@router.post(
    "/mfa/disable",
    response_model=MFADisableResponse,
    responses={
        200: {"description": "MFA отключен"},
        400: {"description": "Неверный код"},
        401: {"description": "Не авторизован"},
        404: {"description": "MFA не настроен"},
    },
)
async def disable_mfa(
    request: Request,
    disable_data: MFADisableRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    settings_repo: Annotated[UserSecuritySettingsRepository, Depends(get_user_security_settings_repository)],
    security_service: Annotated[UserSecurityService, Depends(get_user_security_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> MFADisableResponse:
    """
    Отключение MFA.

    Args:
        request: HTTP запрос
        disable_data: Данные для отключения
        current_user: Текущий пользователь
        settings_repo: Репозиторий настроек безопасности
        security_service: Сервис безопасности
        audit_service: Сервис аудита

    Returns:
        MFADisableResponse: Статус операции
    """
    client_ip = request.client.host if request.client else "unknown"

    # Rate limiting
    if not await mfa_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Please try again later.",
        )

    try:
        # Получение настроек
        settings = await settings_repo.get_by_user_id(current_user.id)

        if not settings or not settings.totp_enabled:
            raise AppException("MFA is not enabled", code="MFA_NOT_ENABLED", status_code=404)

        # Верификация кода (если предоставлен)
        if disable_data.totp_code:
            totp_service = TOTPService()
            is_valid = totp_service.verify(settings.totp_secret, disable_data.totp_code)

            if not is_valid:
                await audit_service.log_mfa_disable_failed(current_user.id, client_ip, "INVALID_CODE")
                raise AppException("Invalid TOTP code", code="INVALID_TOTP_CODE", status_code=400)

        # Отключение MFA
        await security_service.disable_mfa(current_user.id)

        await audit_service.log_mfa_disabled(current_user.id, client_ip)

        logger.info(f"MFA disabled for user: {current_user.id}")

        return MFADisableResponse(
            success=True,
            message="MFA disabled successfully",
        )

    except AppException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
        )

    except Exception as e:
        logger.error(f"Failed to disable MFA for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable MFA",
        )


@router.post(
    "/mfa/backup-codes",
    response_model=BackupCodesResponse,
    responses={
        200: {"description": "Резервные коды сгенерированы"},
        401: {"description": "Не авторизован"},
        404: {"description": "MFA не настроен"},
    },
)
async def generate_backup_codes(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    settings_repo: Annotated[UserSecuritySettingsRepository, Depends(get_user_security_settings_repository)],
    security_service: Annotated[UserSecurityService, Depends(get_user_security_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> BackupCodesResponse:
    """
    Генерация новых резервных кодов для MFA.

    Args:
        request: HTTP запрос
        current_user: Текущий пользователь
        settings_repo: Репозиторий настроек безопасности
        security_service: Сервис безопасности
        audit_service: Сервис аудита

    Returns:
        BackupCodesResponse: Резервные коды
    """
    client_ip = request.client.host if request.client else "unknown"

    # Rate limiting
    if not await backup_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many backup code generation attempts. Please try again later.",
        )

    try:
        # Проверка, что MFA включен
        settings = await settings_repo.get_by_user_id(current_user.id)

        if not settings or not settings.totp_enabled:
            raise AppException("MFA is not enabled", code="MFA_NOT_ENABLED", status_code=404)

        # Генерация новых кодов
        backup_codes = generate_mfa_backup_codes()
        await security_service.save_backup_codes(current_user.id, backup_codes)

        await audit_service.log_backup_codes_generated(current_user.id, client_ip)

        logger.info(f"Backup codes generated for user: {current_user.id}")

        return BackupCodesResponse(
            backup_codes=backup_codes,
            message="Backup codes generated successfully. Store them securely.",
        )

    except AppException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
        )

    except Exception as e:
        logger.error(f"Failed to generate backup codes for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate backup codes",
        )


@router.get(
    "/settings",
    response_model=SecuritySettingsResponse,
    responses={
        200: {"description": "Настройки безопасности"},
        401: {"description": "Не авторизован"},
    },
)
async def get_security_settings(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    settings_repo: Annotated[UserSecuritySettingsRepository, Depends(get_user_security_settings_repository)],
) -> SecuritySettingsResponse:
    """
    Получение настроек безопасности пользователя.

    Args:
        request: HTTP запрос
        current_user: Текущий пользователь
        settings_repo: Репозиторий настроек безопасности

    Returns:
        SecuritySettingsResponse: Настройки безопасности
    """
    try:
        settings = await settings_repo.get_by_user_id(current_user.id)

        if not settings:
            # Возвращаем настройки по умолчанию
            return SecuritySettingsResponse(
                totp_enabled=False,
                totp_secret=None,
                has_backup_codes=False,
                last_password_change=None,
            )

        return SecuritySettingsResponse(
            totp_enabled=settings.totp_enabled,
            totp_secret=settings.totp_secret,
            has_backup_codes=bool(settings.totp_backup_codes),
            last_password_change=settings.last_password_change,
        )

    except Exception as e:
        logger.error(f"Failed to get security settings for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get security settings",
        )


@router.patch(
    "/settings",
    response_model=SecuritySettingsResponse,
    responses={
        200: {"description": "Настройки обновлены"},
        400: {"description": "Ошибка валидации"},
        401: {"description": "Не авторизован"},
    },
)
async def update_security_settings(
    request: Request,
    update_data: SecuritySettingsUpdateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    settings_repo: Annotated[UserSecuritySettingsRepository, Depends(get_user_security_settings_repository)],
    security_service: Annotated[UserSecurityService, Depends(get_user_security_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> SecuritySettingsResponse:
    """
    Обновление настроек безопасности.

    Args:
        request: HTTP запрос
        update_data: Данные для обновления
        current_user: Текущий пользователь
        settings_repo: Репозиторий настроек безопасности
        security_service: Сервис безопасности
        audit_service: Сервис аудита

    Returns:
        SecuritySettingsResponse: Обновленные настройки
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        # Обновление настроек
        update_dict = update_data.model_dump(exclude_unset=True)
        settings = await security_service.update_settings(current_user.id, **update_dict)

        if not settings:
            raise AppException("Failed to update security settings", code="SETTINGS_UPDATE_FAILED", status_code=400)

        await audit_service.log_security_settings_updated(current_user.id, client_ip, update_dict)

        logger.info(f"Security settings updated for user: {current_user.id}")

        return SecuritySettingsResponse(
            totp_enabled=settings.totp_enabled,
            totp_secret=settings.totp_secret,
            has_backup_codes=bool(settings.totp_backup_codes),
            last_password_change=settings.last_password_change,
        )

    except AppException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
        )

    except Exception as e:
        logger.error(f"Failed to update security settings for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update security settings",
        )


@router.post(
    "/mfa/challenge",
    response_model=MFAChallengeResponse,
    responses={
        200: {"description": "MFA запрос создан"},
        401: {"description": "Не авторизован"},
        404: {"description": "MFA не настроен"},
    },
)
async def create_mfa_challenge(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    settings_repo: Annotated[UserSecuritySettingsRepository, Depends(get_user_security_settings_repository)],
) -> MFAChallengeResponse:
    """
    Создание MFA запроса для верификации.

    Используется для подтверждения критических действий.

    Args:
        request: HTTP запрос
        current_user: Текущий пользователь
        settings_repo: Репозиторий настроек безопасности

    Returns:
        MFAChallengeResponse: Данные для верификации
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        # Проверка, что MFA включен
        settings = await settings_repo.get_by_user_id(current_user.id)

        if not settings or not settings.totp_enabled:
            raise AppException("MFA is not enabled", code="MFA_NOT_ENABLED", status_code=404)

        # Создание MFA запроса
        # TODO: Сохранять запрос в Redis с временем жизни
        challenge_id = generate_mfa_challenge_id()

        logger.info(f"MFA challenge created for user: {current_user.id}")

        return MFAChallengeResponse(
            challenge_id=challenge_id,
            expires_in=300,  # 5 минут
            message="Enter your TOTP code to complete the action",
        )

    except AppException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
        )

    except Exception as e:
        logger.error(f"Failed to create MFA challenge for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create MFA challenge",
        )


def generate_mfa_challenge_id() -> str:
    """Генерация ID MFA запроса."""
    import secrets
    return secrets.token_urlsafe(32)