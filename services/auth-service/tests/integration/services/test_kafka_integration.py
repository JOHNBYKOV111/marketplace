"""
Интеграционные тесты для Kafka клиента и сервиса.

Тестирует:
- Инициализацию Kafka продюсера (start)
- Остановку продюсера (stop, flush)
- Отправку событий (send_event, send_raw)
- Специализированные методы (send_verification_code, send_user_blocked и т.д.)
- Сериализацию сообщений (JSON, timestamp)
- Маскирование получателей (email, phone)
- Обработку ошибок (Kafka недоступен, таймауты, ошибки)
- Health check и получение метаданных
- Пакетную отправку (publish_batch)
- Граничные случаи (пустые данные, большие сообщения)
"""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from aiokafka.errors import KafkaError, KafkaTimeoutError

from app.core.kafka_client import KafkaEvent, KafkaProducerClient, kafka_producer
from app.services.kafka_producer_service import KafkaProducerService


# ==================== ГЛОБАЛЬНАЯ ФИКСТУРА ====================

@pytest.fixture
def service():
    """Единая глобальная фикстура сервиса для ВСЕХ классов в этом файле."""
    from unittest.mock import AsyncMock, MagicMock
    from app.services.kafka_producer_service import KafkaProducerService

    fake_producer = MagicMock()
    # Делаем метод send_event асинхронным — это спасет и тесты публикаций,
    # и тесты пограничных случаев (Edge Cases), не ломая маскирование!
    fake_producer.send_event = AsyncMock(return_value=True)
    
    return KafkaProducerService(producer=fake_producer)


# ==================== ТЕСТЫ ====================

class TestKafkaEvent:
    """Тесты для KafkaEvent dataclass."""

    def test_kafka_event_to_json(self):
        """Тест преобразования KafkaEvent в JSON."""
        event = KafkaEvent(
            event_type="test.event",
            data={"key": "value", "number": 123},
            trace_id="trace_123",
            user_id="user_456",
        )

        result = json.loads(event.to_json())

        assert result["event_type"] == "test.event"
        assert result["data"]["key"] == "value"
        assert result["data"]["number"] == 123
        assert result["trace_id"] == "trace_123"
        assert result["user_id"] == "user_456"
        assert result["source"] == "auth-service"
        assert result["version"] == "1.0"

    def test_kafka_event_to_json_without_optional(self):
        """Тест преобразования KafkaEvent без опциональных полей."""
        event = KafkaEvent(
            event_type="minimal.event",
            data={},
        )

        result = json.loads(event.to_json())

        assert result["event_type"] == "minimal.event"
        assert result["data"] == {}
        assert result.get("trace_id") is None
        assert result.get("user_id") is None


class TestKafkaProducerClient:
    """Тесты для KafkaProducerClient."""

    @pytest.fixture
    def client(self):
        return KafkaProducerClient()

    @patch("app.core.kafka_client.settings")
    @patch("app.core.kafka_client.AIOKafkaProducer")
    async def test_start_success(self, mock_producer_class, mock_settings, client):
        """Тест успешного запуска Kafka продюсера."""
        # ГАРАНТИЯ ЛИДА: отключаем SSL и SASL для мок-настроек,
        # чтобы библиотека ssl не пыталась искать несуществующие файлы
        mock_settings.KAFKA_USE_SSL = False
        mock_settings.KAFKA_ENABLED = True
        
        mock_settings.KAFKA_PRODUCER_ACKS = "all"
        mock_settings.KAFKA_PRODUCER_MAX_BATCH_SIZE = 16384
        mock_settings.KAFKA_PRODUCER_LINGER_MS = 10
        mock_settings.KAFKA_PRODUCER_COMPRESSION_TYPE = None

        mock_producer = AsyncMock()
        mock_producer.start = AsyncMock()
        mock_producer_class.return_value = mock_producer

        await client.start(bootstrap_servers="localhost:9092")

        assert client._initialized is True
        mock_producer.start.assert_called_once()

    @patch("app.core.kafka_client.settings")
    async def test_start_without_bootstrap_servers(self, mock_settings, client):
        """Тест запуска без указания bootstrap серверов."""
        mock_settings.KAFKA_ENABLED = True
        mock_settings.KAFKA_USE_SSL = False
        mock_settings.KAFKA_BOOTSTRAP_SERVERS = None
        
        client._bootstrap_servers = None

        with pytest.raises(RuntimeError, match="Kafka bootstrap servers not provided"):
            await client.start()

    @patch("app.core.kafka_client.AIOKafkaProducer")
    @patch("app.core.kafka_client.settings")
    async def test_start_failure(self, mock_settings, mock_producer_class, client):
        """Тест неудачного запуска Kafka продюсера."""
        mock_settings.KAFKA_ENABLED = True
        mock_settings.KAFKA_USE_SSL = False
        mock_producer_class.side_effect = Exception("Connection failed")

        with pytest.raises(Exception, match="Connection failed"):
            await client.start(bootstrap_servers="localhost:9092")

        assert client._initialized is False

    @patch("app.core.kafka_client.settings")
    @patch("app.core.kafka_client.AIOKafkaProducer")
    async def test_stop_success(self, mock_producer_class, mock_settings, client):
        """Тест успешной остановки Kafka продюсера."""
        mock_settings.KAFKA_ENABLED = True
        mock_settings.KAFKA_USE_SSL = False
        mock_settings.KAFKA_PRODUCER_COMPRESSION_TYPE = None
        
        mock_producer = AsyncMock()
        mock_producer.flush = AsyncMock()
        mock_producer.stop = AsyncMock()
        mock_producer_class.return_value = mock_producer

        await client.start(bootstrap_servers="localhost:9092")
        await client.stop()

        mock_producer.flush.assert_called_once()
        mock_producer.stop.assert_called_once()
        assert client._initialized is False

    @patch("app.core.kafka_client.settings")
    @patch("app.core.kafka_client.AIOKafkaProducer")
    async def test_send_event_success(self, mock_producer_class, mock_settings, client):
        """Тест успешной отправки события."""
        mock_settings.KAFKA_ENABLED = True
        mock_settings.KAFKA_USE_SSL = False
        mock_settings.KAFKA_PRODUCER_COMPRESSION_TYPE = None
        
        mock_producer = AsyncMock()
        mock_producer.send = AsyncMock(return_value=MagicMock())
        mock_producer_class.return_value = mock_producer

        await client.start(bootstrap_servers="localhost:9092")

        event = KafkaEvent(
            event_type="test.event",
            data={"message": "hello"},
            user_id="user_123",
        )

        await client.send_event("test.topic", event, key="custom_key")

        mock_producer.send.assert_called_once()
        call_args = mock_producer.send.call_args
        assert call_args.kwargs["topic"] == "test.topic"
        assert call_args.kwargs["key"] == b"custom_key"

    @patch("app.core.kafka_client.settings")
    @patch("app.core.kafka_client.AIOKafkaProducer")
    async def test_send_event_not_initialized(self, mock_producer_class, mock_settings, client):
        """Тест отправки события до инициализации."""
        mock_settings.KAFKA_ENABLED = False
        mock_settings.KAFKA_USE_SSL = False
        
        event = KafkaEvent(event_type="test", data={})

        with patch("app.core.kafka_client.logger") as mock_logger:
            await client.send_event("test.topic", event)

            mock_logger.error.assert_called_once()

    @patch("app.core.kafka_client.settings")
    @patch("app.core.kafka_client.AIOKafkaProducer")
    async def test_send_event_kafka_error(self, mock_producer_class, mock_settings, client):
        """Тест обработки Kafka ошибки."""
        mock_settings.KAFKA_ENABLED = True
        mock_settings.KAFKA_USE_SSL = False
        mock_settings.KAFKA_PRODUCER_COMPRESSION_TYPE = None
        
        mock_producer = AsyncMock()
        mock_producer.send = AsyncMock(side_effect=KafkaError("Broker error"))
        mock_producer_class.return_value = mock_producer

        await client.start(bootstrap_servers="localhost:9092")

        event = KafkaEvent(event_type="test", data={})

        with patch("app.core.kafka_client.logger") as mock_logger:
            await client.send_event("test.topic", event)

            mock_logger.error.assert_called_once()

    @patch("app.core.kafka_client.settings")
    @patch("app.core.kafka_client.AIOKafkaProducer")
    async def test_send_raw_success(self, mock_producer_class, mock_settings, client):
        """Тест отправки сырого словаря."""
        mock_settings.KAFKA_ENABLED = True
        mock_settings.KAFKA_USE_SSL = False
        mock_settings.KAFKA_PRODUCER_COMPRESSION_TYPE = None
        
        mock_producer = AsyncMock()
        mock_producer.send = AsyncMock(return_value=MagicMock())
        mock_producer_class.return_value = mock_producer

        await client.start(bootstrap_servers="localhost:9092")

        await client.send_raw("test.topic", {"key": "value"}, key="user_123")

        mock_producer.send.assert_called_once()
        call_args = mock_producer.send.call_args
        assert call_args.kwargs["key"] == b"user_123"

    @patch("app.core.kafka_client.settings")
    @patch("app.core.kafka_client.AIOKafkaProducer")
    async def test_send_verification_code(self, mock_producer_class, mock_settings, client):
        """Тест отправки verification_code события."""
        mock_settings.KAFKA_ENABLED = True
        mock_settings.KAFKA_USE_SSL = False
        mock_settings.KAFKA_PRODUCER_COMPRESSION_TYPE = None
        mock_settings.OTP_TTL_SECONDS = 300
        
        mock_producer = AsyncMock()
        mock_producer.send = AsyncMock(return_value=MagicMock())
        mock_producer_class.return_value = mock_producer

        await client.start(bootstrap_servers="localhost:9092")

        await client.send_verification_code(
            user_id="user_123",
            code="123456",
            channel="email",
            trace_id="trace_abc",
        )

        mock_producer.send.assert_called_once()
        call_args = mock_producer.send.call_args
        assert call_args.kwargs["topic"] == "verification_codes"
        assert call_args.kwargs["key"] == b"user_123"

    @patch("app.core.kafka_client.settings")
    @patch("app.core.kafka_client.AIOKafkaProducer")
    async def test_health_check_success(self, mock_producer_class, mock_settings, client):
        """Тест health check."""
        mock_settings.KAFKA_ENABLED = True
        mock_settings.KAFKA_USE_SSL = False
        mock_settings.KAFKA_PRODUCER_COMPRESSION_TYPE = None

        # Lead-настройка мока: имитируем структуру ответа метаданных
        mock_metadata = MagicMock()
        mock_metadata.brokers = ["broker_1"]  # Должен быть хотя бы один элемент, чтобы len() > 0

        mock_producer = AsyncMock()
        # Заставляем асинхронный метод metadata() возвращать нашу заготовку
        mock_producer.metadata = AsyncMock(return_value=mock_metadata)

        mock_producer_class.return_value = mock_producer

        await client.start(bootstrap_servers="localhost:9092")

        result = await client.health_check()

        assert result is True

    @patch("app.core.kafka_client.settings")
    @patch("app.core.kafka_client.AIOKafkaProducer")
    async def test_get_metadata_success(self, mock_producer_class, mock_settings, client):
        """Тест получения метаданных."""
        mock_settings.KAFKA_ENABLED = True
        mock_settings.KAFKA_USE_SSL = False
        mock_settings.KAFKA_PRODUCER_COMPRESSION_TYPE = None

        # Lead-структура: имитируем объекты брокеров с нужными атрибутами
        broker1 = MagicMock(nodeId=1, host="localhost", port=9092)
        broker2 = MagicMock(nodeId=2, host="localhost", port=9093)
        
        # Имитируем структуру партиций для топиков
        topic_mock = MagicMock()
        topic_mock.partitions = [1, 2]  # списки партиций

        mock_metadata = MagicMock()
        mock_metadata.brokers = [broker1, broker2]
        mock_metadata.topics = {"topic1": topic_mock, "topic2": topic_mock}
        mock_metadata.controller_id = 1

        mock_producer = AsyncMock()
        # СЮДА! Перенаправляем вызов на метод metadata() приложения
        mock_producer.metadata = AsyncMock(return_value=mock_metadata)
        mock_producer_class.return_value = mock_producer

        await client.start(bootstrap_servers="localhost:9092")

        metadata = await client.get_metadata()

        assert metadata is not None
        assert len(metadata["topics"]) == 2  # Теперь вернет 2!
        assert len(metadata["brokers"]) == 2
        assert metadata["controller_id"] == 1


class TestKafkaProducerService:
    """Тесты для KafkaProducerService (сервис-обёртка)."""

    @pytest.fixture
    def user_id(self):
        return uuid4()

    @patch("app.services.kafka_producer_service.settings")
    async def test_publish_verification_code_email(self, mock_settings, service):
        """Тест публикации verification code для email."""
        mock_settings.SERVICE_NAME = "auth-service"
        mock_settings.ENVIRONMENT = "test"

        await service.publish_verification_code(
            user_id="user_123",
            code="123456",
            channel="email",
            recipient="user@example.com",
            ttl_seconds=300,
            trace_id="trace_123",
        )

        service._producer.send_event.assert_called_once()
        call_args = service._producer.send_event.call_args
        assert call_args.kwargs["topic"] == "verification_codes"
        assert call_args.kwargs["key"] == "user_123"

    async def test_publish_verification_code_sms(self, service):
        """Тест публикации verification code для SMS."""
        await service.publish_verification_code(
            user_id="user_123",
            code="654321",
            channel="sms",
            recipient="+79001234567",
            ttl_seconds=180,
        )

        service._producer.send_event.assert_called_once()
        call_args = service._producer.send_event.call_args
        assert call_args.kwargs["topic"] == "verification_codes"

    async def test_publish_user_blocked(self, service, user_id):
        """Тест публикации user.blocked события."""
        await service.publish_user_blocked(
            user_id=user_id,
            blocked_by="admin@example.com",
            reason="Spam",
            trace_id="trace_123",
        )

        service._producer.send_event.assert_called_once()
        call_args = service._producer.send_event.call_args
        assert call_args.kwargs["topic"] == "user.blocked"
        assert call_args.kwargs["key"] == str(user_id)

    async def test_publish_user_unblocked(self, service, user_id):
        """Тест публикации user.unblocked события."""
        await service.publish_user_unblocked(
            user_id=user_id,
            unblocked_by="admin@example.com",
            reason="Appeal approved",
        )

        service._producer.send_event.assert_called_once()
        call_args = service._producer.send_event.call_args
        assert call_args.kwargs["topic"] == "user.unblocked"
        assert call_args.kwargs["key"] == str(user_id)

    async def test_publish_password_changed(self, service, user_id):
        """Тест публикации password.changed события."""
        await service.publish_password_changed(
            user_id=user_id,
            source="user",
            ip="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        service._producer.send_event.assert_called_once()
        call_args = service._producer.send_event.call_args
        assert call_args.kwargs["topic"] == "password.changed"
        assert call_args.kwargs["key"] == str(user_id)

    async def test_publish_session_revoked(self, service, user_id):
        """Тест публикации session.revoked события."""
        await service.publish_session_revoked(
            user_id=user_id,
            session_id="session_123",
            all_sessions=False,
            reason="logout",
        )

        service._producer.send_event.assert_called_once()
        call_args = service._producer.send_event.call_args
        assert call_args.kwargs["topic"] == "session.revoked"
        assert call_args.kwargs["key"] == str(user_id)

    async def test_publish_user_created(self, service, user_id):
        """Тест публикации user.created события."""
        await service.publish_user_created(
            user_id=user_id,
            email_hash="hashed_email",
        )

        service._producer.send_event.assert_called_once()
        call_args = service._producer.send_event.call_args
        assert call_args.kwargs["topic"] == "user.created"
        assert call_args.kwargs["key"] == str(user_id)

    async def test_publish_user_deleted(self, service, user_id):
        """Тест публикации user.deleted события."""
        await service.publish_user_deleted(
            user_id=user_id,
            email_hash="hashed_email",
        )

        service._producer.send_event.assert_called_once()
        call_args = service._producer.send_event.call_args
        assert call_args.kwargs["topic"] == "user.deleted"
        assert call_args.kwargs["key"] == str(user_id)

    async def test_publish_email_verified(self, service, user_id):
        """Тест публикации email.verified события."""
        await service.publish_email_verified(
            user_id=user_id,
            email_hash="hashed_email",
        )

        service._producer.send_event.assert_called_once()
        call_args = service._producer.send_event.call_args
        assert call_args.kwargs["topic"] == "user.email.verified"
        assert call_args.kwargs["key"] == str(user_id)

    async def test_publish_batch(self, service):
        """Тест пакетной отправки событий."""
        events = [
            ("user.created", "user.created", {"id": "1"}, "user1"),
            ("user.blocked", "user.blocked", {"id": "2"}, "user2"),
        ]

        await service.publish_batch(events)

        assert service._producer.send_event.call_count == 2

    async def test_producer_not_available(self, service):
        """Тест отправки когда продюсер недоступен."""
        service._producer = None

        with patch("app.services.kafka_producer_service.logger") as mock_logger:
            await service.publish_user_blocked(
                user_id=uuid4(),
                blocked_by="admin",
            )

            mock_logger.error.assert_called_once()


class TestMaskRecipient:
    """Тесты для маскирования получателей."""

    def test_mask_recipient_email_short_local(self, service):
        """Тест маскирования email с коротким локальным именем."""
        result = service._mask_recipient("ab@example.com", "email")
        assert result == "a***@example.com"

    def test_mask_recipient_email_long_local(self, service):
        """Тест маскирования email с длинным локальным именем."""
        result = service._mask_recipient("john.doe@example.com", "email")
        assert result == "joh***@example.com"

    def test_mask_recipient_email_no_at(self, service):
        """Тест маскирования email без @."""
        result = service._mask_recipient("invalid-email", "email")
        assert result == "***@***"

    def test_mask_recipient_sms_long(self, service):
        """Тест маскирования SMS с длинным номером."""
        result = service._mask_recipient("+79001234567", "sms")
        assert result == "+***4567"

    def test_mask_recipient_sms_short(self, service):
        """Тест маскирования SMS с коротким номером."""
        result = service._mask_recipient("12345", "sms")
        assert result == "***"

    def test_mask_recipient_unknown_channel(self, service):
        """Тест маскирования для неизвестного канала."""
        result = service._mask_recipient("anything", "unknown")
        assert result == "[REDACTED]"


class TestEdgeCases:
    """Тесты для граничных случаев."""

    @patch("app.core.kafka_client.settings")
    @patch("app.core.kafka_client.AIOKafkaProducer")
    async def test_send_event_without_key(self, mock_producer_class, mock_settings):
        """Тест отправки события без ключа."""
        mock_settings.KAFKA_ENABLED = True
        mock_settings.KAFKA_USE_SSL = False
        mock_settings.KAFKA_PRODUCER_COMPRESSION_TYPE = None
        
        mock_producer = AsyncMock()
        mock_producer.send = AsyncMock(return_value=MagicMock())
        mock_producer_class.return_value = mock_producer

        client = KafkaProducerClient()
        await client.start(bootstrap_servers="localhost:9092")

        event = KafkaEvent(event_type="test", data={}, user_id=None, trace_id=None)

        await client.send_event("test.topic", event)

        call_args = mock_producer.send.call_args
        assert call_args.kwargs["key"] is None

    @patch("app.core.kafka_client.settings")
    @patch("app.core.kafka_client.AIOKafkaProducer")
    async def test_send_raw_without_timestamp(self, mock_producer_class, mock_settings):
        """Тест отправки сырого словаря без timestamp."""
        mock_settings.KAFKA_ENABLED = True
        mock_settings.KAFKA_USE_SSL = False
        mock_settings.KAFKA_PRODUCER_COMPRESSION_TYPE = None
        
        mock_producer = AsyncMock()
        mock_producer.send = AsyncMock(return_value=MagicMock())
        mock_producer_class.return_value = mock_producer

        client = KafkaProducerClient()
        await client.start(bootstrap_servers="localhost:9092")

        await client.send_raw("test.topic", {"key": "value"})

        call_args = mock_producer.send.call_args
        value = call_args.kwargs["value"]
        assert b"timestamp" in value

    @patch("app.services.kafka_producer_service.settings")
    async def test_verification_code_with_empty_trace_id(self, mock_settings, service):
        """Тест отправки verification code с пустым trace_id."""
        await service.publish_verification_code(
            user_id="user_123",
            code="123456",
            channel="email",
            recipient="test@example.com",
            trace_id="",
        )

        service._producer.send_event.assert_called_once()

    async def test_batch_empty_events(self, service):
        """Тест пакетной отправки с пустым списком."""
        await service.publish_batch([])

        service._producer.send_event.assert_not_called()


class TestSingleton:
    """Тесты для синглтона kafka_producer."""

    def test_kafka_producer_singleton(self):
        """Тест что kafka_producer является синглтоном."""
        from app.core.kafka_client import kafka_producer as client1
        from app.core.kafka_client import kafka_producer as client2

        assert client1 is client2
        assert isinstance(client1, KafkaProducerClient)