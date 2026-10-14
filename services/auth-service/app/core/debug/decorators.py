"""
Модуль инфраструктурных декораторов автоматической трассировки и профилирования.
Обеспечивает сбор контекста выполнения и локальных переменных при возникновении сбоев.
"""

import functools
import inspect
import sys
import time
import logging
from typing import Any, Callable, TypeVar, cast

from app.core.debug.context import get_trace_id

F = TypeVar('F', bound=Callable[..., Any])
_logger = logging.getLogger(__name__)


def _clean_args(*args: Any) -> tuple:
    """Очищает позиционные аргументы от ссылок на экземпляры или классы."""
    if args:
        first_arg = args[0]
        if hasattr(first_arg, "__dict__") or isinstance(first_arg, type):
            return args[1:]
    return args


def trace(level: int = logging.DEBUG) -> Callable[[F], F]:
    """
    Декоратор автоматического контроля жизненного цикла методов.
    Снимает показания локальных переменных из стека при фиксации исключений.
    """
    def decorator(func: F) -> F:
        is_async = inspect.iscoroutinefunction(func)
        func_name = func.__qualname__
        module_name = func.__module__

        def _get_base_extra(duration_ms: float = 0.0) -> dict:
            extra = {
                "function": func_name,
                "log_module": module_name,
                "trace_id": get_trace_id(),
            }
            if duration_ms > 0:
                extra["duration_ms"] = round(duration_ms, 2)
            return extra

        def _extract_crash_context(exc_traceback) -> dict:
            """Рекурсивно спускается к точке возникновения ошибки для сбора locals."""
            local_vars = {}
            tb = exc_traceback
            while tb and tb.tb_next:
                tb = tb.tb_next
            if tb and tb.tb_frame:
                for k, v in tb.tb_frame.f_locals.items():
                    if k not in ["self", "cls"] and not k.startswith("__"):
                        if isinstance(v, (dict, list, int, float, bool, type(None))):
                            local_vars[k] = v
                        else:
                            local_vars[k] = str(v)
            return local_vars

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            if not _logger.isEnabledFor(level):
                return await func(*args, **kwargs)

            start_time = time.perf_counter()
            extra = _get_base_extra()
            extra.update({"event": "method_call", "log_args": _clean_args(*args), "log_kwargs": kwargs})
            _logger.log(level, f"→ {func_name}", extra=extra)

            try:
                result = await func(*args, **kwargs)
                duration_ms = (time.perf_counter() - start_time) * 1000
                extra_success = _get_base_extra(duration_ms)
                extra_success["event"] = "method_return"
                _logger.log(level, f"← {func_name}", extra=extra_success)
                return result
            except Exception as e:
                duration_ms = (time.perf_counter() - start_time) * 1000
                _, _, exc_tb = sys.exc_info()
                extra_error = _get_base_extra(duration_ms)
                extra_error.update({
                    "event": "method_error",
                    "log_args": _clean_args(*args),
                    "log_kwargs": kwargs,
                    "local_variables": _extract_crash_context(exc_tb)
                })
                _logger.exception(f"❌ {func_name} failed", extra=extra_error)
                raise e

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            if not _logger.isEnabledFor(level):
                return func(*args, **kwargs)

            start_time = time.perf_counter()
            extra = _get_base_extra()
            extra.update({"event": "method_call", "log_args": _clean_args(*args), "log_kwargs": kwargs})
            _logger.log(level, f"→ {func_name}", extra=extra)

            try:
                result = func(*args, **kwargs)
                duration_ms = (time.perf_counter() - start_time) * 1000
                extra_success = _get_base_extra(duration_ms)
                extra_success["event"] = "method_return"
                _logger.log(level, f"← {func_name}", extra=extra_success)
                return result
            except Exception as e:
                duration_ms = (time.perf_counter() - start_time) * 1000
                _, _, exc_tb = sys.exc_info()
                extra_error = _get_base_extra(duration_ms)
                extra_error.update({
                    "event": "method_error",
                    "log_args": _clean_args(*args),
                    "log_kwargs": kwargs,
                    "local_variables": _extract_crash_context(exc_tb)
                })
                _logger.exception(f"❌ {func_name} failed", extra=extra_error)
                raise e

        return cast(F, async_wrapper if is_async else sync_wrapper)
    return decorator


class timer:
    """
    Высокоточный контекстный менеджер и декоратор профилирования времени выполнения.
    Безопасен для многопоточных сред и асинхронных задач под высокой нагрузкой.
    """
    def __init__(self, block_name: str = "code_block", level: int = logging.DEBUG):
        self.block_name = block_name
        self.level = level
        self._start_time: float = 0.0

    def __enter__(self) -> "timer":
        self._start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        duration_ms = (time.perf_counter() - self._start_time) * 1000
        status = "success" if exc_type is None else "error"
        _logger.log(
            self.level,
            f"⏱ {self.block_name} completed" if exc_type is None else f"⏱ {self.block_name} failed",
            extra={
                "event": "execution_time",
                "function": self.block_name,
                "duration_ms": round(duration_ms, 2),
                "status": status,
                "trace_id": get_trace_id(),
            }
        )

    def __call__(self, func: F) -> F:
        is_async = inspect.iscoroutinefunction(func)
        block_name = func.__qualname__

        @functools.wraps(func)
        async def async_inner(*args: Any, **kwargs: Any) -> Any:
            self.block_name = block_name
            with self:
                return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_inner(*args: Any, **kwargs: Any) -> Any:
            self.block_name = block_name
            with self:
                return func(*args, **kwargs)

        return cast(F, async_inner if is_async else sync_inner)