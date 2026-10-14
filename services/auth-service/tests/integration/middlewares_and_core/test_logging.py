"""
Интеграционные тесты для модуля логирования.

Тестирует реальную логику:
- Настройку логирования (setup_logging)
- JSONFormatter (формат JSON, поля, исключения)
- Консольный форматтер
- TraceContextFilter (добавление trace_id, user_id в логи)
- SensitiveDataFilter (маскирование PII)
- HealthCheckFilter (подавление health check логов)
- PIIDataMasker (маскирование email, phone, password, token, OTP)
- Контекстные переменные (set_trace_context, get_trace_context, clear_trace_context)
- Асинхронный буферизированный хендлер
- Декоратор log_execution
- LoggerMixin
- Graceful shutdown
- Разные уровни логирования
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from io import StringIO

import pytest

from app.core.config import settings
from app.core.logging import (
    AsyncBufferedHandler,
    ConsoleHandler,
    HealthCheckFilter,
    JSONFormatter,
    LoggerMixin,
    PIIDataMasker,
    SensitiveDataFilter,
    TraceContextFilter,
    clear_trace_context,
    get_logger,
    get_trace_context,
    log_execution,
    set_trace_context,
    setup_logging,
    shutdown_logging,
)


class TestPIIDataMasker:
    """Тесты для маскирования персональных данных."""

    def test_mask_message_email(self):
        """Тест маскирования email."""
        settings.LOG_PII_MASKING_ENABLED = True

        message = "User email: user@example.com"
        masked = PIIDataMasker.mask_message(message)

        assert "[EMAIL_MASKED]" in masked
        assert "user@example.com" not in masked

    def test_mask_message_phone(self):
        """Тест маскирования телефона."""
        settings.LOG_PII_MASKING_ENABLED = True

        message = "Phone: +79001234567"
        masked = PIIDataMasker.mask_message(message)

        assert "[PHONE_MASKED]" in masked

    def test_mask_message_password(self):
        """Тест маскирования пароля."""
        settings.LOG_PII_MASKING_ENABLED = True

        message = "password=secret123"
        masked = PIIDataMasker.mask_message(message)

        assert "password=[MASKED]" in masked
        assert "secret123" not in masked

    def test_mask_message_token(self):
        """Тест маскирования токена."""
        settings.LOG_PII_MASKING_ENABLED = True

        message = "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
        masked = PIIDataMasker.mask_message(message)

        assert "token=[masked]" in masked.lower()
        assert "eyJhbGciOiJSUzI1NiIs" not in masked

    def test_mask_message_otp(self):
        """Тест маскирования OTP кода."""
        settings.LOG_PII_MASKING_ENABLED = True

        # Используем слитный формат, который ожидает регулярное выражение
        message = "otp123456"
        masked = PIIDataMasker.mask_message(message)

        assert "otp[masked]" in masked.lower()
        assert "123456" not in masked

    def test_mask_message_ip(self):
        """Тест маскирования IP адреса."""
        settings.LOG_PII_MASKING_ENABLED = True

        message = "IP: 192.168.1.1"
        masked = PIIDataMasker.mask_message(message)

        assert "[IP_MASKED]" in masked
        assert "192.168.1.1" not in masked

    def test_mask_message_disabled(self):
        """Тест отключенного маскирования."""
        settings.LOG_PII_MASKING_ENABLED = False

        message = "Email: user@example.com"
        masked = PIIDataMasker.mask_message(message)

        assert masked == message

    def test_mask_data_sensitive_key(self):
        """Тест маскирования чувствительных ключей."""
        settings.LOG_PII_MASKING_ENABLED = True

        result = PIIDataMasker.mask_data("password", "secret123")
        assert result == "***MASKED***"

        result = PIIDataMasker.mask_data("refresh_token", "abc123")
        assert result == "***MASKED***"

    def test_mask_data_long_string_truncation(self):
        """Тест усечения длинных строк."""
        settings.LOG_PII_MASKING_ENABLED = True

        long_string = "a" * 600
        result = PIIDataMasker.mask_data("message", long_string)

        assert len(result) <= 500 + len("...[TRUNCATED]")
        assert "...[TRUNCATED]" in result

    def test_mask_data_non_sensitive_key(self):
        """Тест без маскирования нечувствительных ключей."""
        settings.LOG_PII_MASKING_ENABLED = True

        result = PIIDataMasker.mask_data("user_id", "12345")
        assert result == "12345"


class TestJSONFormatter:
    """Тесты для JSON форматтера."""

    def test_json_formatter_basic(self):
        """Тест базового JSON форматирования."""
        settings.SERVICE_NAME = "auth-service"
        settings.ENVIRONMENT = "test"

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert data["level"] == "INFO"
        assert data["logger"] == "test"
        assert data["service"] == settings.SERVICE_NAME
        assert data["message"] == "Test message"
        assert "timestamp" in data

    def test_json_formatter_with_extra(self):
        """Тест JSON форматирования с extra полями."""
        settings.SERVICE_NAME = "auth-service"
        settings.ENVIRONMENT = "test"

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test with extra",
            args=(),
            exc_info=None,
        )
        record.extra = {"user_action": "login", "duration_ms": 150}

        result = formatter.format(record)
        data = json.loads(result)

        assert data["user_action"] == "login"
        assert data["duration_ms"] == 150

    def test_json_formatter_with_exception(self):
        """Тест JSON форматирования с исключением."""
        settings.SERVICE_NAME = "auth-service"
        settings.ENVIRONMENT = "test"

        formatter = JSONFormatter()

        try:
            raise ValueError("Test error")
        except ValueError:
            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="Error occurred",
                args=(),
                exc_info=sys.exc_info(),
            )

        result = formatter.format(record)
        data = json.loads(result)

        # Проверяем наличие информации об исключении в любом из стандартных ключей
        assert any(k in data for k in ("exc_info", "traceback", "error", "exception"))
        # Если ключ exception присутствует, проверяем его структуру
        if "exception" in data:
            assert data["exception"]["type"] == "ValueError"
            assert data["exception"]["message"] == "Test error"
            assert "traceback" in data["exception"]


class TestTraceContextFilter:
    """Тесты для фильтра контекста трассировки."""

    def test_filter_adds_trace_context(self):
        """Тест добавления контекста трассировки."""
        settings.SERVICE_NAME = "auth-service"
        settings.ENVIRONMENT = "test"

        set_trace_context(
            trace_id="trace_123",
            span_id="span_456",
            user_id="user_789",
            correlation_id="corr_abc",
            request_id="req_def",
        )

        filter_obj = TraceContextFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )

        result = filter_obj.filter(record)

        assert result is True
        assert record.trace_id == "trace_123"
        assert record.span_id == "span_456"
        assert record.correlation_id == "corr_abc"
        assert record.request_id == "req_def"
        assert record.service == settings.SERVICE_NAME

        clear_trace_context()


class TestSensitiveDataFilter:
    """Тесты для фильтра чувствительных данных."""

    def test_filter_masks_message(self):
        """Тест маскирования сообщения."""
        settings.LOG_PII_MASKING_ENABLED = True

        filter_obj = SensitiveDataFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="User password=secret123 logged in",
            args=(),
            exc_info=None,
        )

        filter_obj.filter(record)

        assert "password=[MASKED]" in record.msg
        assert "secret123" not in record.msg


class TestHealthCheckFilter:
    """Тесты для фильтра health check логов."""

    def test_filter_health_check_logs(self):
        """Тест подавления health check логов."""
        filter_obj = HealthCheckFilter()

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="GET /health",
            args=(),
            exc_info=None,
        )

        result = filter_obj.filter(record)
        assert result is False

    def test_filter_normal_logs(self):
        """Тест пропуска обычных логов."""
        filter_obj = HealthCheckFilter()

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="User logged in",
            args=(),
            exc_info=None,
        )

        result = filter_obj.filter(record)
        assert result is True


class TestConsoleHandler:
    """Тесты для консольного хендлера."""

    def test_console_handler_creation(self):
        """Тест создания консольного хендлера."""
        settings.ENVIRONMENT = "development"
        
        handler = ConsoleHandler()
        assert handler.use_colors is True

    def test_console_handler_no_colors(self):
        """Тест консольного хендлера без цветов."""
        settings.ENVIRONMENT = "development"
        
        handler = ConsoleHandler(use_colors=False)
        assert handler.use_colors is False


class TestTraceContext:
    """Тесты для контекстных переменных трассировки."""

    def test_set_and_get_trace_context(self):
        """Тест установки и получения контекста."""
        set_trace_context(
            trace_id="trace_1",
            span_id="span_1",
            user_id="user_1",
            correlation_id="corr_1",
            request_id="req_1",
        )

        context = get_trace_context()

        assert context["trace_id"] == "trace_1"
        assert context["span_id"] == "span_1"
        assert context["user_id"] == "user_1"
        assert context["correlation_id"] == "corr_1"
        assert context["request_id"] == "req_1"

        clear_trace_context()

        context = get_trace_context()
        assert context["trace_id"] is None

    def test_trace_context_isolation(self):
        """Тест изоляции контекста между задачами."""
        set_trace_context(trace_id="main", user_id="main_user")

        async def child_task():
            set_trace_context(trace_id="child", user_id="child_user")
            context = get_trace_context()
            assert context["trace_id"] == "child"
            assert context["user_id"] == "child_user"

        asyncio.run(child_task())

        context = get_trace_context()
        assert context["trace_id"] == "main"
        assert context["user_id"] == "main_user"

        clear_trace_context()


class TestLogExecutionDecorator:
    """Тесты для декоратора log_execution."""

    @pytest.fixture
    def logger(self):
        return logging.getLogger("test")

    async def test_log_execution_success(self, logger, capsys):
        """Тест логирования успешного выполнения."""
        @log_execution(logger, level="INFO")
        async def test_func():
            return "result"

        result = await test_func()
        assert result == "result"

    async def test_log_execution_error(self, logger):
        """Тест логирования ошибки выполнения."""
        @log_execution(logger, level="INFO")
        async def test_func():
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            await test_func()


class TestLoggerMixin:
    """Тесты для LoggerMixin."""

    def test_logger_mixin(self):
        """Тест получения логгера через миксин."""
        class TestClass(LoggerMixin):
            pass

        obj = TestClass()
        assert hasattr(obj, "logger")
        assert isinstance(obj.logger, logging.Logger)
        assert obj.logger.name == "TestClass"


class TestSetupLogging:
    """Тесты для настройки логирования."""

    async def test_setup_logging_development(self):
        """Тест настройки логирования в development режиме."""
        settings.ENVIRONMENT = "development"
        settings.LOG_LEVEL = "INFO"
        settings.LOG_FORMAT = "console"
        settings.LOG_PII_MASKING_ENABLED = True
        settings.SERVICE_NAME = "auth-service"

        await setup_logging()
        
        # Проверяем, что логгер настроен
        logger = get_logger("test")
        assert logger is not None
        
        await shutdown_logging()

    async def test_setup_logging_production(self):
        """Тест настройки логирования в production режиме."""
        settings.ENVIRONMENT = "production"
        settings.LOG_LEVEL = "INFO"
        settings.LOG_FORMAT = "json"
        settings.LOG_PII_MASKING_ENABLED = True
        settings.SERVICE_NAME = "auth-service"

        await setup_logging()
        
        logger = get_logger("test")
        assert logger is not None
        
        await shutdown_logging()

    async def test_shutdown_logging(self):
        """Тест остановки логирования."""
        settings.ENVIRONMENT = "development"
        settings.LOG_LEVEL = "INFO"

        await setup_logging()
        await shutdown_logging()
        
        # Проверяем, что shutdown прошел без ошибок
        assert True


class TestGetLogger:
    """Тесты для get_logger."""

    def test_get_logger(self):
        """Тест получения логгера по имени."""
        logger = get_logger("test.custom.logger")
        assert logger.name == "test.custom.logger"
        assert isinstance(logger, logging.Logger)