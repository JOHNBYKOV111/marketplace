"""
Настройка логирования для всего приложения.

Обеспечивает:
- Единую конфигурацию логгеров
- Структурированное логирование в JSON (для продакшена)
- Логирование в stdout (для контейнеров)
- Разные уровни логирования для разных окружений
- Контекстную информацию (request_id, user_id, trace_id)
- Фильтрацию чувствительных данных
- Интеграцию с системой мониторинга
"""

import json
import logging
import sys
import re
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union, List, Callable
from uuid import UUID
from functools import wraps
import asyncio
import traceback

from app.core.config import settings


# Контекстные переменные для логирования
trace_id_var: ContextVar[Optional[str]] = ContextVar("trace_id", default=None)
span_id_var: ContextVar[Optional[str]] = ContextVar("span_id", default=None)
user_id_var: ContextVar[Optional[Union[UUID, str]]] = ContextVar("user_id", default=None)
correlation_id_var: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


class PIIDataMasker:
    """Маскировщик персональных данных в логах."""

    SENSITIVE_KEYS = {
        "password", "password_hash", "current_password", "new_password",
        "token", "refresh_token", "access_token", "api_key", "api_secret",
        "secret", "private_key", "totp_secret", "totp_code",
        "credit_card", "cvv", "pan", "card_number",
        "authorization", "cookie", "set-cookie",
        "code", "verification_code", "otp",
        "session_id", "jwt", "refresh_token",
        "client_token", "accessor", "role_id", "secret_id",
        "vault_token", "vault_role_id", "vault_secret_id",
        "jwt_private_key", "pepper", "encryption_key",
    }

    @classmethod
    def mask_message(cls, message: str) -> str:
        """
        Маскирование PII в сообщении.

        Args:
            message: Исходное сообщение

        Returns:
            str: Сообщение с замаскированными данными
        """
        if not settings.LOG_PII_MASKING_ENABLED:
            return message

        masked = message

        # Маскирование email
        masked = re.sub(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "[EMAIL_MASKED]",
            masked
        )

        # Маскирование телефона
        masked = re.sub(
            r'\+?[0-9]{10,15}',
            "[PHONE_MASKED]",
            masked
        )

        # Маскирование IP
        masked = re.sub(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            "[IP_MASKED]",
            masked
        )

        # Маскирование пароля
        masked = re.sub(
            r'(password["\']?\s*[:=]\s*["\']?)([^"\'\,\s]+)(["\']?)',
            r'\1[MASKED]\3',
            masked,
            flags=re.IGNORECASE
        )

        # Маскирование токена - заменяем Authorization: Bearer <token> на token=[MASKED]
        masked = re.sub(
            r'(Authorization["\']?\s*[:=]\s*["\']?Bearer\s+)([A-Za-z0-9\-_\.]+)',
            r'token=[MASKED]',
            masked,
            flags=re.IGNORECASE
        )
        # Маскировка token: <token> на token=[MASKED]
        masked = re.sub(
            r'(token["\']?\s*[:=]\s*["\']?)([^"\'\,\s]+)(["\']?)',
            r'\1[MASKED]\3',
            masked,
            flags=re.IGNORECASE
        )

        # Маскирование OTP - заменяем OTP code: <цифры> на code=[MASKED]
        masked = re.sub(
            r'(otp|code|verification_code["\']?\s*[:=]\s*["\']?)(\d{4,8})(["\']?)',
            r'\1[MASKED]\3',
            masked,
            flags=re.IGNORECASE
        )

        return masked

    @classmethod
    def mask_data(cls, key: str, value: Any) -> Any:
        """
        Маскирование данных по ключу.

        Args:
            key: Ключ
            value: Значение

        Returns:
            Any: Замаскированное значение
        """
        if not settings.LOG_PII_MASKING_ENABLED:
            return value

        if key.lower() in cls.SENSITIVE_KEYS:
            return "***MASKED***"

        if isinstance(value, str) and len(value) > 500:
            return value[:500] + "...[TRUNCATED]"

        return value


class JSONFormatter(logging.Formatter):
    """
    Форматтер для структурированного JSON-логирования.
    """

    def __init__(self):
        super().__init__()
        self.service_name = settings.SERVICE_NAME
        self.environment = settings.ENVIRONMENT

    def format(self, record: logging.LogRecord) -> str:
        """
        Форматирование записи лога в JSON.

        Args:
            record: Запись лога

        Returns:
            str: JSON строка
        """
        log_data = {
            "timestamp": datetime.fromtimestamp(
                record.created,
                tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": PIIDataMasker.mask_message(record.getMessage()),
            "service": self.service_name,
            "environment": self.environment,
        }

        if record.pathname:
            log_data["file"] = record.pathname
            log_data["filename"] = record.filename
        if record.lineno:
            log_data["line"] = record.lineno
        if record.funcName:
            log_data["function"] = record.funcName

        # Контекстные переменные
        trace_id = trace_id_var.get()
        if trace_id:
            log_data["trace_id"] = trace_id

        span_id = span_id_var.get()
        if span_id:
            log_data["span_id"] = span_id

        user_id = user_id_var.get()
        if user_id:
            log_data["user_id"] = str(user_id)

        correlation_id = correlation_id_var.get()
        if correlation_id:
            log_data["correlation_id"] = correlation_id

        request_id = request_id_var.get()
        if request_id:
            log_data["request_id"] = request_id

        # Исключение
        if record.exc_info:
            if record.exc_info is True:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                if exc_type and exc_value:
                    log_data["exception"] = {
                        "type": exc_type.__name__,
                        "message": str(exc_value),
                        "traceback": "".join(traceback.format_tb(exc_traceback)) if exc_traceback else "",
                    }
            elif isinstance(record.exc_info, tuple) and len(record.exc_info) == 3:
                exc_type, exc_value, exc_traceback = record.exc_info
                if exc_type and exc_value:
                    log_data["exception"] = {
                        "type": exc_type.__name__ if hasattr(exc_type, "__name__") else str(exc_type),
                        "message": str(exc_value),
                        "traceback": self.formatException(record.exc_info),
                    }

        # Дополнительные поля
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            for key, value in record.extra.items():
                log_data[key] = PIIDataMasker.mask_data(key, value)

        return json.dumps(log_data, default=str, ensure_ascii=False)


class TraceContextFilter(logging.Filter):
    """Фильтр для добавления контекста трассировки."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Добавление контекстных данных в запись."""
        trace_id = trace_id_var.get()
        if trace_id:
            record.trace_id = trace_id

        span_id = span_id_var.get()
        if span_id:
            record.span_id = span_id

        user_id = user_id_var.get()
        if user_id:
            record.user_id = str(user_id)

        correlation_id = correlation_id_var.get()
        if correlation_id:
            record.correlation_id = correlation_id

        request_id = request_id_var.get()
        if request_id:
            record.request_id = request_id

        record.service = settings.SERVICE_NAME
        return True


class SensitiveDataFilter(logging.Filter):
    """Фильтр для маскировки чувствительных данных."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Маскировка чувствительных данных."""
        if settings.LOG_PII_MASKING_ENABLED:
            record.msg = PIIDataMasker.mask_message(record.msg)
        return True


class HealthCheckFilter(logging.Filter):
    """Фильтр для подавления health check логов."""

    HEALTH_CHECK_PATTERNS = (
        "/health",
        "/healthz",
        "/ping",
        "/metrics",
        "/ready",
        "/live",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        """Фильтрация health check логов."""
        msg = record.getMessage().lower()
        return not any(pattern in msg for pattern in self.HEALTH_CHECK_PATTERNS)


class ConsoleHandler(logging.StreamHandler):
    """Хендлер для консольного вывода с цветами."""

    COLORS = {
        "DEBUG": "\033[36m",    # Cyan
        "INFO": "\033[32m",     # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",    # Red
        "CRITICAL": "\033[41m", # Red background
        "RESET": "\033[0m",
    }

    def __init__(self, use_colors: bool = True):
        super().__init__(sys.stdout)
        self.use_colors = use_colors and settings.is_development
        self.setFormatter(self._create_formatter())

    def _create_formatter(self):
        """Создание форматтера для консоли."""
        if self.use_colors:
            return logging.Formatter(
                "%(asctime)s %(color)s[%(levelname)s]%(reset)s %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        return logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:
        """Форматирование записи с цветами."""
        if self.use_colors:
            record.color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
            record.reset = self.COLORS["RESET"]
        return super().format(record)


class AsyncBufferedHandler(logging.Handler):
    """
    Асинхронный буферизированный хендлер для отправки логов в OpenSearch.
    """

    def __init__(self, buffer_size: int = 100, flush_interval: float = 5.0):
        """
        Инициализация хендлера.

        Args:
            buffer_size: Размер буфера для накопления логов
            flush_interval: Интервал сброса в секундах
        """
        super().__init__()
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        self._buffer: List[Dict] = []
        self._lock = asyncio.Lock()
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Запуск фоновой задачи для периодического сброса."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        """Остановка фоновой задачи."""
        self._running = False
        if self._task:
            await self._task
            self._task = None
        await self.flush()

    def emit(self, record: logging.LogRecord) -> None:
        """
        Добавление записи в буфер.

        Args:
            record: Запись лога
        """
        try:
            log_entry = {
                "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "service": settings.SERVICE_NAME,
                "environment": settings.ENVIRONMENT,
            }

            if hasattr(record, "extra"):
                log_entry["extra"] = record.extra

            asyncio.create_task(self._add_to_buffer(log_entry))
        except Exception:
            self.handleError(record)

    async def _add_to_buffer(self, log_entry: Dict) -> None:
        """Добавление записи в буфер с блокировкой."""
        async with self._lock:
            self._buffer.append(log_entry)
            if len(self._buffer) >= self.buffer_size:
                await self.flush()

    async def flush(self) -> None:
        """Сброс буфера."""
        async with self._lock:
            if not self._buffer:
                return
            batch = self._buffer.copy()
            self._buffer.clear()

        try:
            await self._send_to_opensearch(batch)
        except Exception as e:
            logging.error(f"Failed to send logs to OpenSearch: {e}")

    async def _send_to_opensearch(self, batch: List[Dict]) -> None:
        """
        Отправка логов в OpenSearch.

        Args:
            batch: Пакет логов
        """
        # TODO: Реализовать отправку в OpenSearch
        # Пока просто логируем в stdout
        print(f"Sending {len(batch)} logs to OpenSearch")

    async def _flush_loop(self) -> None:
        """Фоновый цикл для периодического сброса."""
        while self._running:
            await asyncio.sleep(self.flush_interval)
            if self._buffer:
                await self.flush()


def set_trace_context(
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    user_id: Optional[Union[UUID, str]] = None,
    correlation_id: Optional[str] = None,
    request_id: Optional[str] = None,
) -> None:
    """
    Установка контекста трассировки.

    Args:
        trace_id: ID трассировки
        span_id: ID спана
        user_id: ID пользователя
        correlation_id: ID корреляции
        request_id: ID запроса
    """
    if trace_id is not None:
        trace_id_var.set(trace_id)
    if span_id is not None:
        span_id_var.set(span_id)
    if user_id is not None:
        user_id_var.set(user_id)
    if correlation_id is not None:
        correlation_id_var.set(correlation_id)
    if request_id is not None:
        request_id_var.set(request_id)


def get_trace_context() -> Dict[str, Optional[str]]:
    """
    Получение текущего контекста трассировки.

    Returns:
        Dict[str, Optional[str]]: Контекстные переменные
    """
    return {
        "trace_id": trace_id_var.get(),
        "span_id": span_id_var.get(),
        "user_id": str(user_id_var.get()) if user_id_var.get() else None,
        "correlation_id": correlation_id_var.get(),
        "request_id": request_id_var.get(),
    }


def clear_trace_context() -> None:
    """Очистка контекста трассировки."""
    trace_id_var.set(None)
    span_id_var.set(None)
    user_id_var.set(None)
    correlation_id_var.set(None)
    request_id_var.set(None)


class LogContext:
    """
    Контекстный менеджер для установки контекстных переменных логирования.
    """

    def __init__(
        self,
        request_id: Optional[str] = None,
        user_id: Optional[Union[UUID, str]] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ):
        self.request_id = request_id
        self.user_id = user_id
        self.trace_id = trace_id
        self.span_id = span_id
        self.correlation_id = correlation_id
        self._old_values = {}

    def __enter__(self):
        if self.request_id is not None:
            self._old_values["request_id"] = request_id_var.set(self.request_id)
        if self.user_id is not None:
            self._old_values["user_id"] = user_id_var.set(self.user_id)
        if self.trace_id is not None:
            self._old_values["trace_id"] = trace_id_var.set(self.trace_id)
        if self.span_id is not None:
            self._old_values["span_id"] = span_id_var.set(self.span_id)
        if self.correlation_id is not None:
            self._old_values["correlation_id"] = correlation_id_var.set(self.correlation_id)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if "request_id" in self._old_values:
            request_id_var.reset(self._old_values["request_id"])
        if "user_id" in self._old_values:
            user_id_var.reset(self._old_values["user_id"])
        if "trace_id" in self._old_values:
            trace_id_var.reset(self._old_values["trace_id"])
        if "span_id" in self._old_values:
            span_id_var.reset(self._old_values["span_id"])
        if "correlation_id" in self._old_values:
            correlation_id_var.reset(self._old_values["correlation_id"])

    async def __aenter__(self):
        self.__enter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.__exit__(exc_type, exc_val, exc_tb)


def log_execution(logger: logging.Logger, level: str = "INFO"):
    """
    Декоратор для логирования выполнения функции.

    Args:
        logger: Логгер
        level: Уровень логирования
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = datetime.now()
            logger.log(
                getattr(logging, level.upper()),
                f"Starting {func.__name__}"
            )
            try:
                result = await func(*args, **kwargs)
                duration = (datetime.now() - start).total_seconds() * 1000
                logger.log(
                    getattr(logging, level.upper()),
                    f"Completed {func.__name__} in {duration:.2f}ms"
                )
                return result
            except Exception as e:
                duration = (datetime.now() - start).total_seconds() * 1000
                logger.error(
                    f"Failed {func.__name__} after {duration:.2f}ms: {e}",
                    exc_info=True
                )
                raise

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = datetime.now()
            logger.log(
                getattr(logging, level.upper()),
                f"Starting {func.__name__}"
            )
            try:
                result = func(*args, **kwargs)
                duration = (datetime.now() - start).total_seconds() * 1000
                logger.log(
                    getattr(logging, level.upper()),
                    f"Completed {func.__name__} in {duration:.2f}ms"
                )
                return result
            except Exception as e:
                duration = (datetime.now() - start).total_seconds() * 1000
                logger.error(
                    f"Failed {func.__name__} after {duration:.2f}ms: {e}",
                    exc_info=True
                )
                raise

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


class LoggerMixin:
    """Миксин для добавления логгера в класс."""

    @property
    def logger(self) -> logging.Logger:
        """Получение логгера для класса."""
        return get_logger(self.__class__.__name__)


def get_logger(name: str) -> logging.Logger:
    """
    Получение логгера по имени.

    Args:
        name: Имя логгера

    Returns:
        logging.Logger: Логгер
    """
    return logging.getLogger(name)


async def setup_logging() -> None:
    """
    Настройка логирования приложения.
    """
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(log_level)

    console_handler = ConsoleHandler(use_colors=True)
    console_handler.setLevel(log_level)

    console_handler.addFilter(TraceContextFilter())
    console_handler.addFilter(SensitiveDataFilter())
    console_handler.addFilter(HealthCheckFilter())

    root_logger.addHandler(console_handler)

    # Настройка уровней для сторонних библиотек
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("aioredis").setLevel(logging.WARNING)

    get_logger(__name__).info(
        f"Logging configured",
        extra={
            "level": settings.LOG_LEVEL,
            "format": settings.LOG_FORMAT,
            "environment": settings.ENVIRONMENT,
        }
    )


async def shutdown_logging() -> None:
    """Остановка логирования."""
    logging.shutdown()
    logger = get_logger(__name__)
    logger.info("Logging shutdown complete")


__all__ = [
    "setup_logging",
    "shutdown_logging",
    "get_logger",
    "LoggerMixin",
    "log_execution",
    "set_trace_context",
    "get_trace_context",
    "clear_trace_context",
    "LogContext",
    "JSONFormatter",
    "ConsoleHandler",
    "TraceContextFilter",
    "SensitiveDataFilter",
    "HealthCheckFilter",
    "PIIDataMasker",
    "AsyncBufferedHandler",
]