"""
Инфраструктурный модуль логирования уровня персистентности (SQLAlchemy).
Реализует механизм Slow Query Log через низкоуровневые события ядра ORM.
"""

import logging
import time
from typing import Any, Optional

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.debug.context import get_trace_id

# Логгер слоя взаимодействия с базами данных
_logger = logging.getLogger("app.db")


def _clean_sql(statement: str) -> str:
    """Нормализует многострочный SQL, преобразуя его в однострочную структуру."""
    if not statement:
        return ""
    return " ".join(statement.split())


def setup_db_logging(
    engine: Engine | AsyncEngine,
    slow_query_threshold_ms: float = 200.0
) -> None:
    """
    Интегрирует перехватчики событий выполнения команд в движок SQLAlchemy.
    
    Совместим как с классическим Engine, так и с асинхронным AsyncEngine.
    
    Args:
        engine: Движок SQLAlchemy (sync/async).
        slow_query_threshold_ms: Порог классификации медленного запроса в миллисекундах.
    """
    # Безопасно извлекаем синхронный исполнитель, если передан асинхронный контекст драйвера
    target_engine = engine.sync_engine if isinstance(engine, AsyncEngine) else engine

    @event.listens_for(target_engine, "before_cursor_execute")
    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        """Регистрирует таймстемп строго до передачи управления СУБД."""
        context._query_start_time = time.perf_counter()

    @event.listens_for(target_engine, "after_cursor_execute")
    def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        """Обрабатывает метрики успешно завершенной транзакции."""
        _process_query_metrics(
            statement, parameters, context,
            status="success",
            threshold_ms=slow_query_threshold_ms
        )

    @event.listens_for(target_engine, "handle_error")
    def handle_error(exception_context):
        """Перехватывает аварийные завершения SQL на уровне курсора."""
        context = exception_context.execution_context
        if context and hasattr(context, "_query_start_time"):
            _process_query_metrics(
                statement=exception_context.statement,
                parameters=exception_context.parameters,
                context=context,
                status="error",
                exc=exception_context.original_exception,
                threshold_ms=slow_query_threshold_ms
            )


def _process_query_metrics(
    statement: str,
    parameters: Any,
    context: Any,
    status: str,
    threshold_ms: float,
    exc: Exception = None
) -> None:
    """
    Анализирует длительность выполнения SQL-запроса и выполняет запись.
    
    Args:
        statement: SQL-запрос
        parameters: Параметры запроса
        context: Контекст выполнения
        status: Статус выполнения ('success' или 'error')
        threshold_ms: Порог медленного запроса в миллисекундах
        exc: Исключение при ошибке
    """
    if not hasattr(context, "_query_start_time"):
        return

    duration_ms_round = round((time.perf_counter() - context._query_start_time) * 1000, 2)
    clean_statement = _clean_sql(statement)
    trace_id = get_trace_id()

    # Сценарий А: Запрос завершился критическим сбоем на стороне СУБД
    if status == "error":
        _logger.error(
            f"SQL Execution Failed: {clean_statement[:60]}...",
            extra={
                "event": "sql_error",
                "sql": clean_statement,
                "parameters": str(parameters),
                "duration_ms": duration_ms_round,
                "error_type": type(exc).__name__ if exc else "UnknownSqlError",
                "trace_id": trace_id
            }
        )
        return

    # Сценарий Б: Включен атомарный DEBUG режим логирования (фиксируем абсолютно все транзакции)
    if _logger.isEnabledFor(logging.DEBUG):
        _logger.debug(
            f"SQL Query ({status})",
            extra={
                "event": "sql_query",
                "sql": clean_statement,
                "parameters": str(parameters),
                "duration_ms": duration_ms_round,
                "trace_id": trace_id
            }
        )
    # Сценарий В: Обычный режим (INFO), но зафиксировано превышение лимита (Slow Query Incident)
    elif duration_ms_round > threshold_ms:
        _logger.warning(
            f"Slow SQL Query detected [{duration_ms_round}ms]",
            extra={
                "event": "slow_query",
                "sql": clean_statement,
                "parameters": str(parameters),
                "duration_ms": duration_ms_round,
                "trace_id": trace_id
            }
        )