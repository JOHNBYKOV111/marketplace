"""
Модуль централизованной настройки структурированного логирования.
Обеспечивает форматирование логов в JSON для production-окружения
и генерацию цветных отчетов с анализом стека для среды тестирования.
"""

import json
import logging
import sys
import traceback
import uuid  # ДОБАВЛЕНО
from datetime import datetime, timezone
from typing import Any, Dict

from app.core.debug.context import get_trace_id

# Атрибуты стандарта LogRecord, исключаемые из пользовательского extra-контекста
_STANDARD_FIELDS = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "module", "msecs",
    "message", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName", "trace_id"
}

# Маркер выполнения внутри среды автоматического тестирования pytest
_IS_TESTING = "pytest" in sys.modules

# Управляющие ANSI-последовательности для WSL-совместимых эмуляторов терминалов
_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_CYAN = "\033[36m"


class UUIDEncoder(json.JSONEncoder):  # ДОБАВЛЕНО
    """Кастомный JSON-кодировщик для поддержки UUID."""
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return str(obj)
        return super().default(obj)


class TraceIdFilter(logging.Filter):
    """
    Фильтр для автоматического обогащения записей логов.
    Инжектирует актуальный trace_id из контекста выполнения корутины.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        record.trace_id = get_trace_id()
        return True


class PiiMaskingProcessor:
    """
    Процессор для рекурсивного поиска и маскирования конфиденциальных данных.
    Предотвращает запись токенов и учетных данных в хранилища логов.
    """
    SECRET_KEYS = {
        "password", "token", "secret", "card", "authorization", 
        "api_key", "refresh_token", "access_token", "credit_card", "secret_key"
    }

    @classmethod
    def mask(cls, value: Any, depth: int = 0) -> Any:
        """Рекурсивно сканирует структуры данных с ограничением по глубине вложенности."""
        if depth > 5:
            return "***"
        
        if isinstance(value, dict):
            return {
                k: "***" if k.lower() in cls.SECRET_KEYS else cls.mask(v, depth + 1)
                for k, v in value.items()
            }
        elif isinstance(value, list):
            return [cls.mask(v, depth + 1) for v in value]
        elif isinstance(value, str) and len(value) > 500:
            return value[:500] + "..."
        return value


class JsonFormatter(logging.Formatter):
    """
    Двухрежимный форматтер вывода.
    Формирует single-line JSON для агрегаторов или расширенный CLI-рапорт для TDD.
    """
    def format(self, record: logging.LogRecord) -> str:
        # Сбор и изоляция всех динамических extra-полей, переданных разработчиком
        extra_fields = {}
        for key, value in record.__dict__.items():
            if key not in _STANDARD_FIELDS:
                extra_fields[key] = PiiMaskingProcessor.mask(value)

        # Режим дебага для WSL-терминала при выполнении тестов
        if _IS_TESTING:
            if record.levelno >= logging.ERROR:
                exc_type, exc_value, exc_tb = record.exc_info if record.exc_info else (None, None, None)
                
                report = [
                    "\n" + f"{_RED}{_BOLD}=" * 80,
                    f"🚨 КРИТИЧЕСКИЙ СБОЙ ЛОГИКИ В ПРИЛОЖЕНИИ",
                    f"   Компонент : {_CYAN}{record.name}.{record.funcName}{_RED}",
                    f"   Суть      : {record.getMessage()}",
                    f"=" * 80 + _RESET
                ]

                if "args" in extra_fields or "kwargs" in extra_fields:
                    report.append(f"{_GREEN}{_BOLD}📦 ВХОДНЫЕ ДАННЫЕ МЕТОДА:{_RESET}")
                    report.append(f"   • args   : {extra_fields.get('args')}")
                    report.append(f"   • kwargs : {extra_fields.get('kwargs')}")
                    report.append(f"{_GREEN}━" * 60 + _RESET)

                if "local_variables" in extra_fields and extra_fields["local_variables"]:
                    report.append(f"{_YELLOW}{_BOLD}🔍 СОСТОЯНИЕ ПЕРЕМЕННЫХ В МОМЕНТ КРЭША (Locals):{_RESET}")
                    for var_name, var_val in extra_fields["local_variables"].items():
                        report.append(f"   • {_CYAN}{var_name:<15}{_RESET} = {_YELLOW}{var_val}{_RESET}")
                    report.append(f"{_YELLOW}━" * 60 + _RESET)

                if exc_tb:
                    report.append(f"{_BLUE}{_BOLD}📍 ТОЧНЫЕ КООРДИНАТЫ ОШИБКИ:{_RESET}")
                    tb_list = traceback.extract_tb(exc_tb)
                    project_frames = [f for f in tb_list if "app" in f.filename]
                    
                    for i, frame in enumerate(project_frames, 1):
                        report.append(f"   [{i}] Файл   : {_BLUE}{frame.filename}{_RESET}")
                        report.append(f"       Строка : {_CYAN}{frame.lineno}{_RESET} в функции '{_CYAN}{frame.name}{_RESET}'")
                        report.append(f"       Код    : {_BOLD}{frame.line}{_RESET}")
                    report.append(f"{_BLUE}━" * 60 + _RESET)

                if exc_type:
                    report.append(f"{_RED}{_BOLD}❌ ТИП ОШИБКИ : {exc_type.__name__}")
                    report.append(f"📝 ПРИЧИНА   : {exc_value}{_RESET}")
                
                report.append(f"{_RED}{_BOLD}=" * 80 + f"{_RESET}\n")
                return "\n".join(report)

            # ИСПРАВЛЕНО: _RESET вместо RESET
            icon = f"{_BLUE}🔹{_RESET}" if record.levelno == logging.DEBUG else f"{_GREEN}🟢{_RESET}"
            return f"{icon} {_CYAN}{record.name}{_RESET} -> {record.getMessage()}"

        # Режим продакшена (валидный однострочный JSON с микросекундной точностью)
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        log_entry: Dict[str, Any] = {
            "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname,
            "module": record.name,
            "function": record.funcName,
            "line": record.lineno,
            "trace_id": getattr(record, "trace_id", "no-trace-id"),
            "message": record.getMessage(),
        }
        if extra_fields:
            log_entry["extra"] = extra_fields
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
            
        # ИСПРАВЛЕНО: добавлен cls=UUIDEncoder
        return json.dumps(log_entry, ensure_ascii=False, cls=UUIDEncoder)


def setup_logging(level: str = "INFO") -> None:
    """
    Выполняет инициализацию корневого логгера и конфигурирует потоки вывода.
    Подавляет избыточные логи внешних библиотек.
    """
    logging.root.handlers.clear()
    
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.root.setLevel(log_level)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(JsonFormatter())
    console_handler.addFilter(TraceIdFilter())
    
    logging.root.addHandler(console_handler)
    
    # Принудительное ограничение уровня логирования для минимизации шума зависимостей
    quiet_loggers = [
        "sqlalchemy.engine", "sqlalchemy.pool", "sqlalchemy.orm",
        "httpx", "httpcore", "aiokafka", "redis", "uvicorn.access"
    ]
    for logger_name in quiet_loggers:
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Фабричный метод получения именованного логгера для модулей."""
    return logging.getLogger(name)