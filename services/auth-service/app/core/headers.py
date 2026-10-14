"""
Заголовки Gateway для межсервисного взаимодействия.

Содержит константы заголовков, которые передаются от Gateway
к микросервисам для идентификации пользователя и его прав.

Стандартизирует имена заголовков для всего проекта:
- Единое место для всех gateway-заголовков
- Типизированные константы для IDE и автодополнения
- Документация по каждому заголовку
- Легкое изменение без разброса по всему коду
- Валидация и парсинг заголовков
- Безопасное извлечение с типами
"""

from enum import Enum
from typing import Final, Optional, List, Dict, Any, Union
from uuid import UUID
import re
from fastapi import Request, HTTPException, status

from app.core.logging import get_logger

logger = get_logger(__name__)


class GatewayHeaders(str, Enum):
    """
    Заголовки, передаваемые от Gateway к микросервисам.
    
    Все заголовки начинаются с префикса X-User- для единообразия
    и легкой идентификации в логах и трейсинге.
    
    Пример использования:
        headers = {
            GatewayHeaders.USER_ID: "123e4567-e89b-12d3-a456-426614174000",
            GatewayHeaders.USER_ROLES: "admin,user",
        }
    """
    
    # === ОСНОВНЫЕ ЗАГОЛОВКИ ПОЛЬЗОВАТЕЛЯ ===
    
    # ID пользователя в формате UUID
    # Передается от Gateway после аутентификации
    # Обязательный заголовок для авторизованных запросов
    USER_ID: Final[str] = "X-User-Id"
    
    # Роли пользователя через запятую (admin,user,moderator)
    # Передается от Gateway на основе прав пользователя
    # Опциональный заголовок (если нет - пользователь без ролей)
    USER_ROLES: Final[str] = "X-User-Roles"
    
    # Email пользователя (опционально)
    # Используется для логирования и аудита
    USER_EMAIL: Final[str] = "X-User-Email"
    
    # Имя пользователя (опционально)
    # Используется для логирования и персонализации
    USER_NAME: Final[str] = "X-User-Name"
    
    # Идентификатор сессии (опционально)
    # Используется для отслеживания сессии пользователя
    SESSION_ID: Final[str] = "X-Session-Id"
    
    # Аватар пользователя (опционально)
    USER_AVATAR: Final[str] = "X-User-Avatar"
    
    # === ЗАГОЛОВКИ ДЛЯ ТРЕЙСИНГА ===
    
    # Request ID для трейсинга (пробрасывается от Gateway)
    # Сквозной идентификатор для всех сервисов
    REQUEST_ID: Final[str] = "X-Request-Id"
    
    # Trace ID для распределенного трейсинга
    TRACE_ID: Final[str] = "X-Trace-Id"
    
    # Span ID для распределенного трейсинга
    SPAN_ID: Final[str] = "X-Span-Id"
    
    # Parent Span ID для распределенного трейсинга
    PARENT_SPAN_ID: Final[str] = "X-Parent-Span-Id"
    
    # === ЗАГОЛОВКИ КЛИЕНТА ===
    
    # Тип клиента (web, mobile, api, admin)
    CLIENT_TYPE: Final[str] = "X-Client-Type"
    
    # Версия клиента (1.0.0, 2.1.3)
    CLIENT_VERSION: Final[str] = "X-Client-Version"
    
    # Клиентский IP (пробрасывается от Gateway)
    CLIENT_IP: Final[str] = "X-Client-IP"
    
    # User-Agent клиента
    CLIENT_USER_AGENT: Final[str] = "X-Client-User-Agent"
    
    # Язык клиента (ru, en, etc.)
    CLIENT_LANGUAGE: Final[str] = "X-Client-Language"
    
    # Часовой пояс клиента (UTC+3, etc.)
    CLIENT_TIMEZONE: Final[str] = "X-Client-Timezone"
    
    # === ЗАГОЛОВКИ БЕЗОПАСНОСТИ ===
    
    # JWT токен (передается для валидации)
    AUTHORIZATION: Final[str] = "Authorization"
    
    # API ключ (для сервис-ту-сервис)
    API_KEY: Final[str] = "X-API-Key"
    
    # Подпись запроса (для верификации)
    REQUEST_SIGNATURE: Final[str] = "X-Request-Signature"
    
    # Timestamp запроса (для защиты от replay)
    REQUEST_TIMESTAMP: Final[str] = "X-Request-Timestamp"
    
    # === ЗАГОЛОВКИ ДЛЯ АУДИТА ===
    
    # IP адрес пользователя (для аудита)
    USER_IP: Final[str] = "X-User-IP"
    
    # User-Agent пользователя (для аудита)
    USER_AGENT: Final[str] = "X-User-Agent"
    
    # Источник запроса (web, mobile, api)
    REQUEST_SOURCE: Final[str] = "X-Request-Source"
    
    # === ЗАГОЛОВКИ ДЛЯ ЭКСПЕРИМЕНТОВ ===
    
    # AB-тестирование (экспериментальная группа)
    EXPERIMENT_GROUP: Final[str] = "X-Experiment-Group"
    
    # Feature flags (включенные фичи)
    FEATURE_FLAGS: Final[str] = "X-Feature-Flags"
    
    @classmethod
    def get_required_headers(cls) -> List[str]:
        """
        Возвращает список обязательных заголовков для авторизованных запросов.
        
        Returns:
            List[str]: Список обязательных заголовков
        """
        return [
            cls.USER_ID,
        ]
    
    @classmethod
    def get_optional_headers(cls) -> List[str]:
        """
        Возвращает список опциональных заголовков.
        
        Returns:
            List[str]: Список опциональных заголовков
        """
        return [
            cls.USER_ROLES,
            cls.USER_EMAIL,
            cls.USER_NAME,
            cls.SESSION_ID,
            cls.USER_AVATAR,
            cls.REQUEST_ID,
            cls.TRACE_ID,
            cls.SPAN_ID,
            cls.PARENT_SPAN_ID,
            cls.CLIENT_TYPE,
            cls.CLIENT_VERSION,
            cls.CLIENT_IP,
            cls.CLIENT_USER_AGENT,
            cls.CLIENT_LANGUAGE,
            cls.CLIENT_TIMEZONE,
            cls.USER_IP,
            cls.USER_AGENT,
            cls.REQUEST_SOURCE,
            cls.EXPERIMENT_GROUP,
            cls.FEATURE_FLAGS,
        ]
    
    @classmethod
    def get_security_headers(cls) -> List[str]:
        """
        Возвращает список заголовков безопасности.
        
        Returns:
            List[str]: Список заголовков безопасности
        """
        return [
            cls.AUTHORIZATION,
            cls.API_KEY,
            cls.REQUEST_SIGNATURE,
            cls.REQUEST_TIMESTAMP,
        ]
    
    @classmethod
    def get_tracing_headers(cls) -> List[str]:
        """
        Возвращает список заголовков для трейсинга.
        
        Returns:
            List[str]: Список заголовков трейсинга
        """
        return [
            cls.REQUEST_ID,
            cls.TRACE_ID,
            cls.SPAN_ID,
            cls.PARENT_SPAN_ID,
        ]
    
    @classmethod
    def get_client_headers(cls) -> List[str]:
        """
        Возвращает список заголовков клиента.
        
        Returns:
            List[str]: Список заголовков клиента
        """
        return [
            cls.CLIENT_TYPE,
            cls.CLIENT_VERSION,
            cls.CLIENT_IP,
            cls.CLIENT_USER_AGENT,
            cls.CLIENT_LANGUAGE,
            cls.CLIENT_TIMEZONE,
        ]
    
    @classmethod
    def get_user_headers(cls) -> List[str]:
        """
        Возвращает список заголовков пользователя.
        
        Returns:
            List[str]: Список заголовков пользователя
        """
        return [
            cls.USER_ID,
            cls.USER_ROLES,
            cls.USER_EMAIL,
            cls.USER_NAME,
            cls.SESSION_ID,
            cls.USER_AVATAR,
        ]
    
    @classmethod
    def get_all_headers(cls) -> List[str]:
        """
        Возвращает список всех заголовков.
        
        Returns:
            List[str]: Список всех заголовков
        """
        return [header.value for header in cls]
    
    def __str__(self) -> str:
        """Строковое представление заголовка."""
        return self.value


# ==================== ПАРСЕРЫ И ВАЛИДАТОРЫ ====================

class HeaderParser:
    """
    Парсер и валидатор заголовков Gateway.
    
    Предоставляет методы для безопасного извлечения и валидации
    заголовков из HTTP запроса.
    """
    
    # Регулярное выражение для UUID
    UUID_PATTERN = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    
    # Допустимые типы клиентов
    VALID_CLIENT_TYPES = {"web", "mobile", "api", "admin", "cli", "test"}
    
    # Допустимые языки
    VALID_LANGUAGES = {"ru", "en", "de", "fr", "es", "zh", "ja", "ko"}
    
    @classmethod
    def get_user_id(cls, request: Request) -> Optional[UUID]:
        """
        Извлечение и валидация User ID из заголовка.
        
        Args:
            request: FastAPI Request
            
        Returns:
            Optional[UUID]: User ID или None если заголовок отсутствует
            
        Raises:
            HTTPException: Если UUID невалидный
        """
        user_id = request.headers.get(GatewayHeaders.USER_ID)
        if not user_id:
            return None
        
        # Валидация UUID
        if not cls.UUID_PATTERN.match(user_id):
            logger.warning(f"Invalid UUID format for user_id: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid user_id format. Expected UUID."
            )
        
        return UUID(user_id)
    
    @classmethod
    def get_user_roles(cls, request: Request) -> List[str]:
        """
        Извлечение и парсинг ролей пользователя.
        
        Args:
            request: FastAPI Request
            
        Returns:
            List[str]: Список ролей
        """
        roles = request.headers.get(GatewayHeaders.USER_ROLES)
        if not roles:
            return []
        
        # Парсинг ролей (разделители: запятая, точка с запятой, пробел)
        roles_list = re.split(r'[,;\s]+', roles)
        return [role.strip() for role in roles_list if role.strip()]
    
    @classmethod
    def get_request_id(cls, request: Request) -> Optional[str]:
        """
        Извлечение Request ID.
        
        Args:
            request: FastAPI Request
            
        Returns:
            Optional[str]: Request ID или None
        """
        request_id = request.headers.get(GatewayHeaders.REQUEST_ID)
        if request_id:
            return request_id.strip()
        
        # Генерируем новый Request ID если отсутствует
        import uuid
        return str(uuid.uuid4())
    
    @classmethod
    def get_trace_id(cls, request: Request) -> Optional[str]:
        """
        Извлечение Trace ID.
        
        Args:
            request: FastAPI Request
            
        Returns:
            Optional[str]: Trace ID или None
        """
        trace_id = request.headers.get(GatewayHeaders.TRACE_ID)
        if trace_id:
            return trace_id.strip()
        return None
    
    @classmethod
    def get_span_id(cls, request: Request) -> Optional[str]:
        """
        Извлечение Span ID.
        
        Args:
            request: FastAPI Request
            
        Returns:
            Optional[str]: Span ID или None
        """
        span_id = request.headers.get(GatewayHeaders.SPAN_ID)
        if span_id:
            return span_id.strip()
        return None
    
    @classmethod
    def get_client_type(cls, request: Request) -> str:
        """
        Извлечение и валидация типа клиента.
        
        Args:
            request: FastAPI Request
            
        Returns:
            str: Тип клиента (по умолчанию "web")
        """
        client_type = request.headers.get(GatewayHeaders.CLIENT_TYPE, "web")
        client_type = client_type.lower().strip()
        
        if client_type not in cls.VALID_CLIENT_TYPES:
            logger.warning(f"Unknown client type: {client_type}, using 'web'")
            return "web"
        
        return client_type
    
    @classmethod
    def get_client_language(cls, request: Request) -> str:
        """
        Извлечение языка клиента.
        
        Args:
            request: FastAPI Request
            
        Returns:
            str: Язык клиента (по умолчанию "en")
        """
        language = request.headers.get(GatewayHeaders.CLIENT_LANGUAGE, "en")
        language = language.lower().strip()
        
        if language not in cls.VALID_LANGUAGES:
            return "en"
        
        return language
    
    @classmethod
    def get_feature_flags(cls, request: Request) -> Dict[str, bool]:
        """
        Извлечение feature flags.
        
        Args:
            request: FastAPI Request
            
        Returns:
            Dict[str, bool]: Словарь feature flags
        """
        flags_str = request.headers.get(GatewayHeaders.FEATURE_FLAGS)
        if not flags_str:
            return {}
        
        flags = {}
        for item in flags_str.split(','):
            if '=' in item:
                key, value = item.split('=', 1)
                flags[key.strip()] = value.strip().lower() == 'true'
            else:
                flags[item.strip()] = True
        
        return flags
    
    @classmethod
    def get_all_user_info(cls, request: Request) -> Dict[str, Any]:
        """
        Получение всей информации о пользователе из заголовков.
        
        Args:
            request: FastAPI Request
            
        Returns:
            Dict[str, Any]: Информация о пользователе
        """
        return {
            "user_id": cls.get_user_id(request),
            "roles": cls.get_user_roles(request),
            "email": request.headers.get(GatewayHeaders.USER_EMAIL),
            "name": request.headers.get(GatewayHeaders.USER_NAME),
            "session_id": request.headers.get(GatewayHeaders.SESSION_ID),
            "avatar": request.headers.get(GatewayHeaders.USER_AVATAR),
            "client_type": cls.get_client_type(request),
            "client_version": request.headers.get(GatewayHeaders.CLIENT_VERSION),
            "client_ip": request.headers.get(GatewayHeaders.CLIENT_IP),
            "language": cls.get_client_language(request),
            "timezone": request.headers.get(GatewayHeaders.CLIENT_TIMEZONE),
            "experiment_group": request.headers.get(GatewayHeaders.EXPERIMENT_GROUP),
            "feature_flags": cls.get_feature_flags(request),
        }


# ==================== ДЕПРЕКЕЙТЕД (для обратной совместимости) ====================

# Для обратной совместимости и удобства импорта
USER_ID: Final[str] = GatewayHeaders.USER_ID.value
USER_ROLES: Final[str] = GatewayHeaders.USER_ROLES.value
USER_EMAIL: Final[str] = GatewayHeaders.USER_EMAIL.value
USER_NAME: Final[str] = GatewayHeaders.USER_NAME.value
SESSION_ID: Final[str] = GatewayHeaders.SESSION_ID.value
REQUEST_ID: Final[str] = GatewayHeaders.REQUEST_ID.value
TRACE_ID: Final[str] = GatewayHeaders.TRACE_ID.value
CLIENT_TYPE: Final[str] = GatewayHeaders.CLIENT_TYPE.value
CLIENT_VERSION: Final[str] = GatewayHeaders.CLIENT_VERSION.value


# ==================== MIDDLEWARE ДЛЯ ЗАГОЛОВКОВ ====================

class HeadersMiddleware:
    """
    Middleware для обработки заголовков Gateway.
    
    Выполняет:
    - Извлечение и валидацию заголовков
    - Добавление информации в request.state
    - Генерацию request_id если отсутствует
    """
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope, receive)
        
        # Извлечение и валидация заголовков
        user_id = HeaderParser.get_user_id(request)
        if user_id:
            request.state.user_id = user_id
        
        request.state.user_roles = HeaderParser.get_user_roles(request)
        request.state.request_id = HeaderParser.get_request_id(request)
        request.state.trace_id = HeaderParser.get_trace_id(request)
        request.state.span_id = HeaderParser.get_span_id(request)
        request.state.client_type = HeaderParser.get_client_type(request)
        request.state.client_language = HeaderParser.get_client_language(request)
        request.state.feature_flags = HeaderParser.get_feature_flags(request)
        request.state.user_info = HeaderParser.get_all_user_info(request)
        
        # Логирование заголовков (без чувствительных данных)
        logger.debug(
            "Headers processed",
            extra={
                "user_id": str(user_id) if user_id else None,
                "roles": request.state.user_roles,
                "client_type": request.state.client_type,
                "feature_flags": request.state.feature_flags,
            }
        )
        
        await self.app(scope, receive, send)


# ==================== ЗАВИСИМОСТИ FASTAPI ====================

async def get_current_user_id(request: Request) -> UUID:
    """
    FastAPI зависимость для получения User ID из заголовков.
    
    Args:
        request: FastAPI Request
        
    Returns:
        UUID: ID пользователя
        
    Raises:
        HTTPException: Если заголовок отсутствует или невалидный
    """
    user_id = HeaderParser.get_user_id(request)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User ID not found in headers",
        )
    return user_id


async def get_current_user_roles(request: Request) -> List[str]:
    """
    FastAPI зависимость для получения ролей пользователя.
    
    Args:
        request: FastAPI Request
        
    Returns:
        List[str]: Список ролей пользователя
    """
    return HeaderParser.get_user_roles(request)


async def get_request_metadata(request: Request) -> Dict[str, Any]:
    """
    FastAPI зависимость для получения метаданных запроса.
    
    Args:
        request: FastAPI Request
        
    Returns:
        Dict[str, Any]: Метаданные запроса
    """
    return {
        "request_id": HeaderParser.get_request_id(request),
        "trace_id": HeaderParser.get_trace_id(request),
        "client_type": HeaderParser.get_client_type(request),
        "client_ip": request.headers.get(GatewayHeaders.CLIENT_IP),
        "user_agent": request.headers.get(GatewayHeaders.USER_AGENT),
        "language": HeaderParser.get_client_language(request),
    }


def require_roles(required_roles: List[str]):
    """
    Декоратор для проверки ролей пользователя.
    
    Args:
        required_roles: Список требуемых ролей
        
    Returns:
        Callable: Декоратор
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request not found"
                )
            
            user_roles = HeaderParser.get_user_roles(request)
            
            # Проверка наличия хотя бы одной требуемой роли
            if not any(role in user_roles for role in required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required roles: {', '.join(required_roles)}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


__all__ = [
    "GatewayHeaders",
    "HeaderParser",
    "HeadersMiddleware",
    "get_current_user_id",
    "get_current_user_roles",
    "get_request_metadata",
    "require_roles",
    # Constants
    "USER_ID",
    "USER_ROLES",
    "USER_EMAIL",
    "USER_NAME",
    "SESSION_ID",
    "REQUEST_ID",
    "TRACE_ID",
    "CLIENT_TYPE",
    "CLIENT_VERSION",
]