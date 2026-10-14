"""
Кастомные исключения для приложения.

Обеспечивает:
- Иерархию исключений для разных слоев приложения
- Единый формат ошибок
- Контекст для логирования
- Коды ошибок для клиентов
- Трассировку для отладки
- Обработчики исключений для FastAPI
- Поддержку Gateway-зависимостей
- Структурированные HTTP-ответы
- Инфраструктурные ошибки (Redis, Cache, Rate Limit, Session)
"""

import json
import traceback
from typing import Any, Dict, Optional, List, Union, Type
from uuid import UUID

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class AppException(Exception):
    """
    Базовое исключение приложения.

    Все кастомные исключения наследуются от этого класса.
    """

    def __init__(
        self,
        message: str,
        code: str = "APP_ERROR",
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        """
        Инициализация исключения.

        Args:
            message: Сообщение об ошибке
            code: Код ошибки
            status_code: HTTP статус код
            details: Дополнительные детали
            user_id: ID пользователя (если известен)
            context: Контекст ошибки (для логирования)
            cause: Причина ошибки (исходное исключение)
        """
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}
        self.user_id = user_id
        self.context = context or {}
        self.cause = cause

        if user_id and "user_id" not in self.details:
            self.details["user_id"] = str(user_id)

        if cause:
            self.context["cause"] = str(cause)
            self.context["cause_type"] = cause.__class__.__name__

        super().__init__(message)

    def to_dict(self, include_internal: bool = False) -> Dict[str, Any]:
        """
        Преобразование исключения в словарь для ответа клиенту.

        Args:
            include_internal: Включать внутренние детали (для отладки)

        Returns:
            Dict[str, Any]: Словарь с информацией об ошибке
        """
        result = {
            "error": {
                "code": self.code,
                "message": self.message,
            }
        }

        if self.details and (include_internal or not self._is_internal_detail()):
            result["error"]["details"] = self.details

        if include_internal:
            result["internal"] = {
                "status_code": self.status_code,
                "user_id": str(self.user_id) if self.user_id else None,
                "context": self.context,
                "trace_id": self.context.get("trace_id"),
                "request_id": self.context.get("request_id"),
            }

        return result

    def _is_internal_detail(self) -> bool:
        """Проверка, являются ли детали внутренними."""
        internal_keys = {"stack", "trace", "sql", "query", "redis_key"}
        return any(key in self.details for key in internal_keys)

    def log(self, level: str = "error") -> None:
        """
        Логирование исключения.

        Args:
            level: Уровень логирования
        """
        log_func = getattr(logger, level, logger.error)
        log_func(
            f"Exception: {self.code} - {self.message}",
            extra={
                "exception": self.to_dict(include_internal=True),
                "user_id": str(self.user_id) if self.user_id else None,
                "status_code": self.status_code,
            },
        )


# ==================== КОНСТАНТЫ КОДОВ ОШИБОК ====================

class ErrorCodes:
    """Константы кодов ошибок."""
    
    # Общие ошибки
    APP_ERROR = "APP_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    BAD_REQUEST = "BAD_REQUEST"
    
    # Аутентификация/Авторизация
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_INVALID = "TOKEN_INVALID"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    MFA_REQUIRED = "MFA_REQUIRED"
    MFA_PENDING = "MFA_PENDING"
    MFA_VERIFICATION_FAILED = "MFA_VERIFICATION_FAILED"
    USER_BLOCKED = "USER_BLOCKED"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    
    # Gateway ошибки
    GATEWAY_AUTH_ERROR = "GATEWAY_AUTH_ERROR"
    MISSING_GATEWAY_HEADER = "MISSING_GATEWAY_HEADER"
    INVALID_GATEWAY_HEADER = "INVALID_GATEWAY_HEADER"
    GATEWAY_ROLE_REQUIRED = "GATEWAY_ROLE_REQUIRED"
    
    # Инфраструктурные ошибки
    REDIS_ERROR = "REDIS_ERROR"
    REDIS_CONNECTION_ERROR = "REDIS_CONNECTION_ERROR"
    REDIS_OPERATION_ERROR = "REDIS_OPERATION_ERROR"
    CACHE_ERROR = "CACHE_ERROR"
    SESSION_ERROR = "SESSION_ERROR"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    DATABASE_ERROR = "DATABASE_ERROR"
    DATABASE_CONNECTION_ERROR = "DATABASE_CONNECTION_ERROR"
    INTEGRITY_ERROR = "INTEGRITY_ERROR"
    ENCRYPTION_ERROR = "ENCRYPTION_ERROR"
    
    # Внешние сервисы
    EXTERNAL_SERVICE_ERROR = "EXTERNAL_SERVICE_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"


# ==================== СТРУКТУРИРОВАННЫЕ ОШИБКИ HTTP ====================

class HTTPException(AppException):
    """
    Базовое исключение для HTTP ошибок.
    
    Все HTTP-исключения наследуются от этого класса.
    """


class BadRequestException(HTTPException):
    """Ошибка 400 Bad Request."""

    def __init__(
        self,
        message: str = "Bad request",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.BAD_REQUEST,
            status_code=400,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


class UnauthorizedException(HTTPException):
    """Ошибка 401 Unauthorized."""

    def __init__(
        self,
        message: str = "Unauthorized",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        authenticate_header: str = "Bearer",
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.UNAUTHORIZED,
            status_code=401,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.authenticate_header = authenticate_header


class InvalidCredentialsException(UnauthorizedException):
    """Ошибка 401 Invalid Credentials."""

    def __init__(
        self,
        message: str = "Invalid credentials",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.INVALID_CREDENTIALS


class TokenExpiredException(UnauthorizedException):
    """Ошибка 401 Token Expired."""

    def __init__(
        self,
        message: str = "Token has expired",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.TOKEN_EXPIRED


class TokenInvalidException(UnauthorizedException):
    """Ошибка 401 Token Invalid."""

    def __init__(
        self,
        message: str = "Invalid token",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.TOKEN_INVALID


class TokenRevokedException(UnauthorizedException):
    """Ошибка 401 Token Revoked."""

    def __init__(
        self,
        message: str = "Token has been revoked",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.TOKEN_REVOKED


class MFARequiredException(UnauthorizedException):
    """Ошибка 401 MFA Required."""

    def __init__(
        self,
        message: str = "MFA verification required",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        mfa_session_id: Optional[str] = None,
        available_methods: Optional[List[str]] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.MFA_REQUIRED
        if mfa_session_id:
            self.details["mfa_session_id"] = mfa_session_id
        if available_methods:
            self.details["available_methods"] = available_methods


class MFAPendingException(UnauthorizedException):
    """Ошибка 401 MFA Pending."""

    def __init__(
        self,
        message: str = "MFA verification pending",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        mfa_session_id: Optional[str] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.MFA_PENDING
        if mfa_session_id:
            self.details["mfa_session_id"] = mfa_session_id


class MFAVerificationFailedException(UnauthorizedException):
    """Ошибка 401 MFA Verification Failed."""

    def __init__(
        self,
        message: str = "MFA verification failed",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.MFA_VERIFICATION_FAILED


class ForbiddenException(HTTPException):
    """Ошибка 403 Forbidden."""

    def __init__(
        self,
        message: str = "Forbidden",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.FORBIDDEN,
            status_code=403,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


class UserBlockedException(ForbiddenException):
    """Ошибка 403 User Blocked."""

    def __init__(
        self,
        message: str = "User is blocked",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        block_reason: Optional[str] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.USER_BLOCKED
        if block_reason:
            self.details["block_reason"] = block_reason


class NotFoundException(HTTPException):
    """Ошибка 404 Not Found."""

    def __init__(
        self,
        message: str = "Not found",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.NOT_FOUND,
            status_code=404,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        if resource_type:
            self.details["resource_type"] = resource_type
        if resource_id:
            self.details["resource_id"] = resource_id


class UserNotFoundException(NotFoundException):
    """Ошибка 404 User Not Found."""

    def __init__(
        self,
        message: str = "User not found",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
            resource_type="user",
            resource_id=str(user_id) if user_id else None,
        )
        self.code = ErrorCodes.USER_NOT_FOUND


class ConflictException(HTTPException):
    """Ошибка 409 Conflict."""

    def __init__(
        self,
        message: str = "Conflict",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.CONFLICT,
            status_code=409,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


class TooManyRequestsException(HTTPException):
    """Ошибка 429 Too Many Requests."""

    def __init__(
        self,
        message: str = "Too many requests",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        retry_after: int = 60,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.RATE_LIMIT_EXCEEDED,
            status_code=429,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.retry_after = retry_after
        self.details["retry_after"] = retry_after


class InternalServerErrorException(HTTPException):
    """Ошибка 500 Internal Server Error."""

    def __init__(
        self,
        message: str = "Internal server error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.INTERNAL_SERVER_ERROR,
            status_code=500,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


class ServiceUnavailableException(HTTPException):
    """Ошибка 503 Service Unavailable."""

    def __init__(
        self,
        message: str = "Service unavailable",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.SERVICE_UNAVAILABLE,
            status_code=503,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


# ==================== ОШИБКИ АУТЕНТИФИКАЦИИ/АВТОРИЗАЦИИ (ДЛЯ СОВМЕСТИМОСТИ) ====================

class AuthenticationError(UnauthorizedException):
    """Ошибка аутентификации (401)."""

    def __init__(
        self,
        message: str = "Authentication required",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.UNAUTHORIZED


class AuthorizationError(ForbiddenException):
    """Ошибка авторизации (403)."""

    def __init__(
        self,
        message: str = "Access denied",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.FORBIDDEN


class InvalidTokenError(UnauthorizedException):
    """Неверный или истекший токен (401)."""

    def __init__(
        self,
        message: str = "Invalid or expired token",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.TOKEN_INVALID


class TokenExpiredError(UnauthorizedException):
    """Истекший токен (401)."""

    def __init__(
        self,
        message: str = "Token has expired",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.TOKEN_EXPIRED


class TokenRevokedError(UnauthorizedException):
    """Отозванный токен (401)."""

    def __init__(
        self,
        message: str = "Token has been revoked",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.TOKEN_REVOKED


class UserNotFoundError(NotFoundException):
    """Пользователь не найден (404)."""

    def __init__(
        self,
        message: str = "User not found",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
            resource_type="user",
            resource_id=str(user_id) if user_id else None,
        )
        self.code = ErrorCodes.USER_NOT_FOUND


class MFARequiredError(UnauthorizedException):
    """Требуется MFA (401)."""

    def __init__(
        self,
        message: str = "MFA verification required",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        mfa_session_id: Optional[str] = None,
        available_methods: Optional[List[str]] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.MFA_REQUIRED
        if mfa_session_id:
            self.details["mfa_session_id"] = mfa_session_id
        if available_methods:
            self.details["available_methods"] = available_methods


# ==================== ИНФРАСТРУКТУРНЫЕ ОШИБКИ ====================

class RedisError(AppException):
    """Ошибка Redis (500)."""

    def __init__(
        self,
        message: str = "Redis error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.REDIS_ERROR,
            status_code=500,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


class RedisConnectionError(RedisError):
    """Ошибка подключения к Redis (500)."""

    def __init__(
        self,
        message: str = "Redis connection failed",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.REDIS_CONNECTION_ERROR


class RedisOperationError(RedisError):
    """Ошибка выполнения операции Redis (500)."""

    def __init__(
        self,
        operation: str,
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        msg = message or f"Redis operation failed: {operation}"
        super().__init__(
            message=msg,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.REDIS_OPERATION_ERROR
        self.operation = operation
        if details is None:
            self.details = {"operation": operation}
        else:
            self.details["operation"] = operation


class CacheError(AppException):
    """Ошибка кэширования (500)."""

    def __init__(
        self,
        message: str = "Cache error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.CACHE_ERROR,
            status_code=500,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


class SessionError(AppException):
    """Ошибка сессии (400)."""

    def __init__(
        self,
        message: str = "Session error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.SESSION_ERROR,
            status_code=400,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


class RateLimitError(AppException):
    """Ошибка rate limit (429)."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        retry_after: int = 60,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.RATE_LIMIT_EXCEEDED,
            status_code=429,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.retry_after = retry_after
        if retry_after:
            self.details["retry_after"] = retry_after


class DatabaseError(AppException):
    """Ошибка базы данных (500)."""

    def __init__(
        self,
        message: str = "Database error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.DATABASE_ERROR,
            status_code=500,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


class DatabaseConnectionError(DatabaseError):
    """Ошибка подключения к БД (500)."""

    def __init__(
        self,
        message: str = "Database connection failed",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.DATABASE_CONNECTION_ERROR


class IntegrityError(DatabaseError):
    """Ошибка целостности данных (409)."""

    def __init__(
        self,
        message: str = "Data integrity violation",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.INTEGRITY_ERROR
        self.status_code = 409


class EncryptionError(AppException):
    """Ошибка шифрования (500)."""

    def __init__(
        self,
        message: str = "Encryption error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.ENCRYPTION_ERROR,
            status_code=500,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


# ==================== ОШИБКИ GATEWAY ====================

class GatewayAuthenticationError(UnauthorizedException):
    """Ошибка аутентификации через Gateway (401)."""

    def __init__(
        self,
        message: str = "Gateway authentication failed",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.GATEWAY_AUTH_ERROR
        self.authenticate_header = "Gateway"


class MissingGatewayHeaderError(GatewayAuthenticationError):
    """Отсутствует обязательный заголовок Gateway (401)."""

    def __init__(
        self,
        header_name: str,
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        msg = message or f"Missing required gateway header: {header_name}"
        super().__init__(
            message=msg,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.MISSING_GATEWAY_HEADER
        self.header_name = header_name
        if details is None:
            self.details = {"header_name": header_name}
        else:
            self.details["header_name"] = header_name


class InvalidGatewayHeaderError(GatewayAuthenticationError):
    """Невалидный заголовок Gateway (401)."""

    def __init__(
        self,
        header_name: str,
        reason: str = "invalid format",
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        msg = message or f"Invalid gateway header {header_name}: {reason}"
        super().__init__(
            message=msg,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.INVALID_GATEWAY_HEADER
        self.header_name = header_name
        if details is None:
            self.details = {"header_name": header_name, "reason": reason}
        else:
            self.details["header_name"] = header_name
            self.details["reason"] = reason


class GatewayRoleRequiredError(ForbiddenException):
    """Требуется роль Gateway (403)."""

    def __init__(
        self,
        required_roles: List[str],
        user_roles: List[str],
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        msg = message or f"Required roles: {', '.join(required_roles)}"
        super().__init__(
            message=msg,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.GATEWAY_ROLE_REQUIRED
        self.required_roles = required_roles
        self.user_roles = user_roles
        if details is None:
            self.details = {
                "required_roles": required_roles,
                "user_roles": user_roles,
            }
        else:
            self.details["required_roles"] = required_roles
            self.details["user_roles"] = user_roles


# ==================== ОШИБКИ БЕЗОПАСНОСТИ ====================

class SecurityError(AppException):
    """Ошибка безопасности (403)."""

    def __init__(
        self,
        message: str = "Security violation",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code="SECURITY_ERROR",
            status_code=403,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


# ==================== ОШИБКИ ВАЛИДАЦИИ ====================

class ValidationError(AppException):
    """Ошибка валидации (422)."""

    def __init__(
        self,
        message: str = "Validation error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        errors: Optional[List[Dict[str, Any]]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.VALIDATION_ERROR,
            status_code=422,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        if errors:
            self.details["errors"] = errors


class PasswordValidationError(ValidationError):
    """Ошибка валидации пароля (422)."""

    def __init__(
        self,
        message: str = "Password validation failed",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        errors: Optional[List[Dict[str, Any]]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            errors=errors,
            cause=cause,
        )
        self.code = "PASSWORD_VALIDATION_ERROR"


# ==================== ВНЕШНИЕ СЕРВИСЫ ====================

class ExternalServiceError(AppException):
    """Ошибка внешнего сервиса (502)."""

    def __init__(
        self,
        message: str = "External service error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        service_name: Optional[str] = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCodes.EXTERNAL_SERVICE_ERROR,
            status_code=502,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        if service_name:
            self.details["service_name"] = service_name


class TimeoutError(ExternalServiceError):
    """Таймаут операции (504)."""

    def __init__(
        self,
        message: str = "Operation timeout",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        operation: Optional[str] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = ErrorCodes.TIMEOUT
        self.status_code = 504
        if operation:
            self.details["operation"] = operation


class EmailServiceError(ExternalServiceError):
    """Ошибка сервиса email (502)."""

    def __init__(
        self,
        message: str = "Email service error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
            service_name="email",
        )
        self.code = "EMAIL_SERVICE_ERROR"


class SMSServiceError(ExternalServiceError):
    """Ошибка SMS сервиса (502)."""

    def __init__(
        self,
        message: str = "SMS service error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
            service_name="sms",
        )
        self.code = "SMS_SERVICE_ERROR"


# ==================== ОШИБКИ MFA ====================

class MFAError(AppException):
    """Ошибка MFA (400)."""

    def __init__(
        self,
        message: str = "MFA error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code="MFA_ERROR",
            status_code=400,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


class MFAAlreadyEnabledError(MFAError):
    """MFA уже включен (409)."""

    def __init__(
        self,
        message: str = "MFA is already enabled",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = "MFA_ALREADY_ENABLED"
        self.status_code = 409


class MFANotEnabledError(MFAError):
    """MFA не включен (404)."""

    def __init__(
        self,
        message: str = "MFA is not enabled",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = "MFA_NOT_ENABLED"
        self.status_code = 404


# ==================== ОШИБКИ ТОКЕНОВ (REFRESH) ====================

class RefreshTokenError(AppException):
    """Ошибка refresh токена (401)."""

    def __init__(
        self,
        message: str = "Refresh token error",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            code="REFRESH_TOKEN_ERROR",
            status_code=401,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )


class RefreshTokenNotFoundError(RefreshTokenError):
    """Refresh токен не найден (401)."""

    def __init__(
        self,
        message: str = "Refresh token not found",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = "REFRESH_TOKEN_NOT_FOUND"


class RefreshTokenRevokedError(RefreshTokenError):
    """Refresh токен отозван (401)."""

    def __init__(
        self,
        message: str = "Refresh token has been revoked",
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            message=message,
            details=details,
            user_id=user_id,
            context=context,
            cause=cause,
        )
        self.code = "REFRESH_TOKEN_REVOKED"


# ==================== УТИЛИТЫ ====================

def create_error_response(
    request: Request,
    status_code: int,
    error_code: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
    retry_after: Optional[int] = None,
) -> JSONResponse:
    """
    Создание JSON-ответа с ошибкой.

    Args:
        request: HTTP запрос
        status_code: HTTP статус код
        error_code: Код ошибки
        message: Сообщение об ошибке
        details: Дополнительные детали
        retry_after: Время ожидания для Retry-After заголовка

    Returns:
        JSONResponse: Ответ с ошибкой
    """
    response_data = {
        "error": {
            "code": error_code,
            "message": message,
        }
    }

    if details:
        response_data["error"]["details"] = details

    trace_id = getattr(request.state, "trace_id", None)
    request_id = getattr(request.state, "request_id", None)

    if trace_id:
        response_data["trace_id"] = trace_id
    if request_id:
        response_data["request_id"] = request_id

    headers = {}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)

    return JSONResponse(
        status_code=status_code,
        content=response_data,
        headers=headers,
    )


async def app_exception_handler(
    request: Request,
    exc: AppException,
) -> JSONResponse:
    """
    Обработчик кастомных исключений приложения.

    Args:
        request: HTTP запрос
        exc: Исключение AppException

    Returns:
        JSONResponse: Ответ с ошибкой
    """
    exc.log()
    return create_error_response(
        request=request,
        status_code=exc.status_code,
        error_code=exc.code,
        message=exc.message,
        details=exc.details if exc.details else None,
        retry_after=getattr(exc, "retry_after", None),
    )


async def http_exception_handler(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:
    """
    Обработчик Starlette HTTPException.

    Args:
        request: HTTP запрос
        exc: Starlette HTTPException

    Returns:
        JSONResponse: Ответ с ошибкой
    """
    # Для 401 всегда маскируем детали
    if exc.status_code == 401:
        message = "Unauthorized"
    else:
        message = str(exc.detail) if exc.detail else "An error occurred"

    error_code_map = {
        400: ErrorCodes.BAD_REQUEST,
        401: ErrorCodes.UNAUTHORIZED,
        403: ErrorCodes.FORBIDDEN,
        404: ErrorCodes.NOT_FOUND,
        409: ErrorCodes.CONFLICT,
        422: ErrorCodes.VALIDATION_ERROR,
        429: ErrorCodes.RATE_LIMIT_EXCEEDED,
        500: ErrorCodes.INTERNAL_SERVER_ERROR,
        503: ErrorCodes.SERVICE_UNAVAILABLE,
    }

    error_code = error_code_map.get(exc.status_code, "HTTP_ERROR")

    return create_error_response(
        request=request,
        status_code=exc.status_code,
        error_code=error_code,
        message=message,
    )


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """
    Обработчик Pydantic валидационных ошибок (422).

    Args:
        request: HTTP запрос
        exc: RequestValidationError

    Returns:
        JSONResponse: Ответ с ошибкой
    """
    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"],
        })

    return create_error_response(
        request=request,
        status_code=422,
        error_code=ErrorCodes.VALIDATION_ERROR,
        message="Request validation failed",
        details={"errors": errors},
    )


async def generic_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """
    Обработчик непредвиденных исключений (500).

    Args:
        request: HTTP запрос
        exc: Исключение

    Returns:
        JSONResponse: Ответ с ошибкой
    """
    logger.error(
        f"Unhandled exception: {exc}",
        extra={
            "exception": str(exc),
            "traceback": traceback.format_exc(),
            "path": request.url.path,
            "method": request.method,
        },
    )

    if settings.DEBUG:
        message = str(exc) if str(exc) else "Unknown error"
        error_code = exc.__class__.__name__
    else:
        message = "Internal server error"
        error_code = ErrorCodes.INTERNAL_SERVER_ERROR

    return create_error_response(
        request=request,
        status_code=500,
        error_code=error_code,
        message=message,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """
    Регистрация всех хендлеров исключений в FastAPI приложении.

    Args:
        app: FastAPI приложение
    """
    app.add_exception_handler(AppException, app_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)


# ==================== HELPER ФУНКЦИИ ДЛЯ RAISE ====================

def raise_bad_request(
    message: str = "Bad request",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise BadRequestException(message, details)


def raise_unauthorized(
    message: str = "Unauthorized",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise UnauthorizedException(message, details)


def raise_invalid_credentials(
    message: str = "Invalid credentials",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise InvalidCredentialsException(message, details)


def raise_forbidden(
    message: str = "Forbidden",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise ForbiddenException(message, details)


def raise_not_found(
    message: str = "Not found",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise NotFoundException(message, details)


def raise_user_not_found(
    user_id: UUID,
    message: str = "User not found",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise UserNotFoundError(message, details, user_id=user_id)


def raise_user_blocked(
    message: str = "User is blocked",
    details: Optional[Dict[str, Any]] = None,
    block_reason: Optional[str] = None,
) -> None:
    raise UserBlockedException(message, details, block_reason=block_reason)


def raise_conflict(
    message: str = "Conflict",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise ConflictException(message, details)


def raise_rate_limit(
    message: str = "Too many requests",
    details: Optional[Dict[str, Any]] = None,
    retry_after: int = 60,
) -> None:
    raise TooManyRequestsException(message, details, retry_after=retry_after)


def raise_internal_server_error(
    message: str = "Internal server error",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise InternalServerErrorException(message, details)


def raise_service_unavailable(
    message: str = "Service unavailable",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise ServiceUnavailableException(message, details)


def raise_redis_error(
    message: str = "Redis error",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise RedisError(message, details)


def raise_cache_error(
    message: str = "Cache error",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise CacheError(message, details)


def raise_session_error(
    message: str = "Session error",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise SessionError(message, details)


def raise_security_error(
    message: str = "Security violation",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise SecurityError(message, details)


def raise_invalid_token(
    message: str = "Invalid or expired token",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise InvalidTokenError(message, details)


def raise_token_expired(
    message: str = "Token has expired",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise TokenExpiredError(message, details)


def raise_token_revoked(
    message: str = "Token has been revoked",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise TokenRevokedError(message, details)


def raise_authentication_error(
    message: str = "Authentication required",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise AuthenticationError(message, details)


def raise_authorization_error(
    message: str = "Access denied",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise AuthorizationError(message, details)


def raise_mfa_required_error(
    message: str = "MFA verification required",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise MFARequiredError(message, details)


def raise_refresh_token_error(
    message: str = "Refresh token error",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise RefreshTokenError(message, details)


# ==================== ЭКСПОРТЫ ====================

__all__ = [
    "AppException",
    "HTTPException",
    "BadRequestException",
    "UnauthorizedException",
    "InvalidCredentialsException",
    "TokenExpiredException",
    "TokenInvalidException",
    "TokenRevokedException",
    "MFARequiredException",
    "MFAPendingException",
    "MFAVerificationFailedException",
    "ForbiddenException",
    "UserBlockedException",
    "NotFoundException",
    "UserNotFoundException",
    "ConflictException",
    "TooManyRequestsException",
    "InternalServerErrorException",
    "ServiceUnavailableException",
    "AuthenticationError",
    "AuthorizationError",
    "InvalidTokenError",
    "TokenExpiredError",
    "TokenRevokedError",
    "UserNotFoundError",
    "MFARequiredError",
    "RedisError",
    "RedisConnectionError",
    "RedisOperationError",
    "CacheError",
    "SessionError",
    "RateLimitError",
    "DatabaseError",
    "DatabaseConnectionError",
    "IntegrityError",
    "EncryptionError",
    "SecurityError",
    "GatewayAuthenticationError",
    "MissingGatewayHeaderError",
    "InvalidGatewayHeaderError",
    "GatewayRoleRequiredError",
    "ValidationError",
    "PasswordValidationError",
    "ExternalServiceError",
    "TimeoutError",
    "EmailServiceError",
    "SMSServiceError",
    "MFAError",
    "MFAAlreadyEnabledError",
    "MFANotEnabledError",
    "RefreshTokenError",
    "RefreshTokenNotFoundError",
    "RefreshTokenRevokedError",
    "ErrorCodes",
    "create_error_response",
    "app_exception_handler",
    "http_exception_handler",
    "validation_exception_handler",
    "generic_exception_handler",
    "register_exception_handlers",
    "raise_bad_request",
    "raise_unauthorized",
    "raise_invalid_credentials",
    "raise_forbidden",
    "raise_not_found",
    "raise_user_not_found",
    "raise_user_blocked",
    "raise_conflict",
    "raise_rate_limit",
    "raise_internal_server_error",
    "raise_service_unavailable",
    "raise_redis_error",
    "raise_cache_error",
    "raise_session_error",
    "raise_security_error",
    "raise_invalid_token",
    "raise_token_expired",
    "raise_token_revoked",
    "raise_authentication_error",
    "raise_authorization_error",
    "raise_mfa_required_error",
    "raise_refresh_token_error",
]