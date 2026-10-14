"""
Инфраструктурный пакет инструментов трассировки, логирования и профилирования приложения.
Предоставляет единую точку доступа (Фасад) ко всем компонентам наблюдения (Observability).
"""

from app.core.debug.context import (
    ensure_trace_id,
    generate_trace_id,
    get_trace_id,
    reset_trace_id,
    set_trace_id,
)
from app.core.debug.db_logger import setup_db_logging
from app.core.debug.decorators import timer, trace
from app.core.debug.logging_config import get_logger, setup_logging
from app.core.debug.middleware import AsgiLoggingMiddleware
from app.core.debug.routing import LoggingRoute

# Автоматическая инициализация изолированного логгера для нужд самого пакета
logger = get_logger(__name__)

__all__ = [
    # Инструменты управления асинхронным контекстом (trace_id)
    "set_trace_id",
    "get_trace_id",
    "reset_trace_id",
    "generate_trace_id",
    "ensure_trace_id",
    
    # Декларативные декораторы профилирования и сбора locals()
    "trace",
    "timer",
    
    # Фабрика логгеров и центральный конфигуратор
    "logger",
    "get_logger",
    "setup_logging",
    
    # Событийный мониторинг базы данных (SQLAlchemy)
    "setup_db_logging",
    
    # Компоненты перехвата и логирования HTTP-трафика FastAPI / ASGI
    "LoggingRoute",
    "AsgiLoggingMiddleware",
]
