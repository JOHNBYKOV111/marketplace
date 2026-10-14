"""
Модуль изоляции контекста выполнения корутины.
Обеспечивает сквозное хранение и управление trace_id в асинхронных задачах asyncio.
"""

import secrets
from contextvars import ContextVar, Token

# Изолированный контейнер trace_id, жестко привязанный к текущей ветке asyncio Task
_trace_id_ctx: ContextVar[str] = ContextVar("trace_id", default="no-trace-id")


def set_trace_id(trace_id: str) -> Token:
    """
    Устанавливает идентификатор трассировки для текущей корутины.

    Args:
        trace_id: Строка с уникальным идентификатором запроса.

    Returns:
        Token: Системный токен состояния, обязательный для последующего сброса контекста.
    """
    return _trace_id_ctx.set(trace_id)


def get_trace_id() -> str:
    """
    Возвращает актуальный идентификатор трассировки из контекста корутины.

    Returns:
        str: Текущий trace_id или дефолтное значение 'no-trace-id', если контекст не инициализирован.
    """
    return _trace_id_ctx.get()


def reset_trace_id(token: Token) -> None:
    """
    Безопасно восстанавливает состояние контекста до момента вызова set_trace_id.
    
    Предотвращает перекрестное загрязнение логов при переиспользовании воркеров сервера.
    Используется строго в блоках finally инфраструктурных слоев (ASGI-мидлвари, APIRoute).

    Args:
        token: Токен, полученный при вызове функции set_trace_id.
    """
    _trace_id_ctx.reset(token)


def generate_trace_id() -> str:
    """
    Генерирует криптографически стойкий алфавитно-цифровой идентификатор трассировки.

    Использует модуль secrets вместо uuid для обеспечения максимальной производительности
    и исключения риска коллизий коротких хэшей в WSL и продакшене.

    Returns:
        str: Строка формата trace_a1b2c3d4e5f67890 (16 символов hex).
    """
    return f"trace_{secrets.token_hex(8)}"


def ensure_trace_id(trace_id: str | None = None) -> str:
    """
    Гарантирует возврат валидного идентификатора трассировки.

    Если входной trace_id передан (например, получен из HTTP-заголовков Nginx/Gateway),
    он очищается и возвращается. В противном случае генерируется новый.
    Функция не мутирует контекст корутины самостоятельно, соблюдая чистоту побочных эффектов.

    Args:
        trace_id: Внешний идентификатор трассировки или None.

    Returns:
        str: Валидный идентификатор трассировки.
    """
    if trace_id and isinstance(trace_id, str):
        return trace_id.strip()
    return generate_trace_id()
