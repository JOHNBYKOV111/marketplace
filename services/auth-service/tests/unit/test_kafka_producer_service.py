"""
Unit tests for KafkaProducerService.

Tests cover:
- Service initialization with producer
- publish_verification_code (with recipient masking for email/sms)
- _mask_recipient (email and SMS masking logic)
- publish_user_blocked / publish_user_unblocked
- publish_password_changed
- publish_session_revoked
- publish_user_created / publish_user_deleted
- publish_email_verified
- publish_batch (bulk publishing)
- Edge cases (producer not available, empty data)
- All methods return bool from producer.send_event
"""

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from app.services.kafka_producer_service import KafkaProducerService


class TestKafkaProducerServiceInit:
    """Tests for service initialization."""

    def test_init_with_producer(self):
        """Test service initialization with custom producer."""
        mock_producer = AsyncMock()
        service = KafkaProducerService(mock_producer)
        assert service._producer == mock_producer

    @patch("app.core.kafka_client.kafka_producer")
    def test_init_defaults_to_global_producer(self, mock_global):
        """Test service uses global producer when none provided."""
        service = KafkaProducerService()
        assert service._producer == mock_global

    @patch("app.services.kafka_producer_service.settings")
    def test_init_reads_service_name_and_env(self, mock_settings):
        """Test service reads config from settings."""
        mock_settings.APP_NAME = "test-auth"
        mock_settings.ENVIRONMENT = "staging"
        service = KafkaProducerService(AsyncMock())
        assert service._service_name == "test-auth"
        assert service._environment == "staging"


class TestMaskRecipient:
    """Tests for _mask_recipient method."""

    @pytest.fixture
    def service(self):
        return KafkaProducerService(AsyncMock())

    def test_mask_email_short_local(self, service):
        """Test email masking with short local part (<=2 chars)."""
        result = service._mask_recipient("ab@example.com", "email")
        assert result == "a***@example.com"

    def test_mask_email_long_local(self, service):
        """Test email masking with long local part (>2 chars)."""
        result = service._mask_recipient("john.doe@example.com", "email")
        assert result == "joh***@example.com"

    def test_mask_email_no_at(self, service):
        """Test email masking when no @ symbol."""
        result = service._mask_recipient("invalid-email", "email")
        assert result == "***@***"

    def test_mask_sms_long(self, service):
        """Test SMS masking with number >= 7 chars."""
        result = service._mask_recipient("+1234567890", "sms")
        assert result == "+***7890"

    def test_mask_sms_short(self, service):
        """Test SMS masking with short number (<7 chars)."""
        result = service._mask_recipient("12345", "sms")
        assert result == "***"

    def test_mask_empty(self, service):
        """Test masking empty string."""
        result = service._mask_recipient("", "email")
        assert result == "[EMPTY]"

    def test_mask_unknown_channel(self, service):
        """Test masking for unknown channel."""
        result = service._mask_recipient("anything", "unknown")
        assert result == "[REDACTED]"


class TestPublishVerificationCode:
    """Tests for publish_verification_code method."""

    @pytest.fixture
    def mock_producer(self):
        producer = AsyncMock()
        producer.send_event = AsyncMock(return_value=True)
        return producer

    @pytest.fixture
    def service(self, mock_producer):
        return KafkaProducerService(mock_producer)

    async def test_publish_email_code(self, service, mock_producer):
        """Test publishing verification code for email."""
        result = await service.publish_verification_code(
            user_id="user_123",
            code="123456",
            channel="email",
            recipient="john.doe@example.com",
            ttl_seconds=300,
            trace_id="trace_abc",
        )

        assert result is True
        mock_producer.send_event.assert_called_once()
        call_kwargs = mock_producer.send_event.call_args[1]

        assert call_kwargs["topic"] == "verification_codes"
        assert call_kwargs["key"] == "user_123"
        assert call_kwargs["event"].event_type == "verification_code"
        assert call_kwargs["event"].data["code"] == "123456"
        assert call_kwargs["event"].data["channel"] == "email"
        assert call_kwargs["event"].data["recipient"] == "john.doe@example.com"
        assert call_kwargs["event"].data["ttl_seconds"] == 300

    async def test_publish_sms_code(self, service, mock_producer):
        """Test publishing verification code for SMS."""
        result = await service.publish_verification_code(
            user_id="user_456",
            code="654321",
            channel="sms",
            recipient="+1234567890",
        )

        assert result is True
        call_kwargs = mock_producer.send_event.call_args[1]
        assert call_kwargs["event"].data["channel"] == "sms"
        assert call_kwargs["event"].data["recipient"] == "+1234567890"

    async def test_publish_when_producer_is_none(self, service):
        """Test returns False when producer is None."""
        service._producer = None
        result = await service.publish_verification_code(
            user_id="user", code="123", channel="email", recipient="test@test.com"
        )
        assert result is False


class TestPublishUserBlocked:
    """Tests for publish_user_blocked method."""

    @pytest.fixture
    def mock_producer(self):
        producer = AsyncMock()
        producer.send_event = AsyncMock(return_value=True)
        return producer

    @pytest.fixture
    def service(self, mock_producer):
        return KafkaProducerService(mock_producer)

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_publish_user_blocked(self, service, mock_producer, user_id):
        """Test publishing user blocked event."""
        result = await service.publish_user_blocked(
            user_id=user_id,
            blocked_by="admin@example.com",
            reason="Spam",
            trace_id="trace_123",
        )

        assert result is True
        mock_producer.send_event.assert_called_once()
        call_kwargs = mock_producer.send_event.call_args[1]

        assert call_kwargs["topic"] == "user.blocked"
        assert call_kwargs["event"].event_type == "user.blocked"
        assert call_kwargs["event"].data["user_id"] == str(user_id)
        assert call_kwargs["event"].data["blocked_by"] == "admin@example.com"
        assert call_kwargs["event"].data["reason"] == "Spam"

    async def test_publish_user_blocked_no_reason(self, service, user_id):
        """Test publishing user blocked without reason."""
        result = await service.publish_user_blocked(
            user_id=user_id,
            blocked_by="system",
        )
        assert result is True

    async def test_publish_user_blocked_producer_none(self, service, user_id):
        """Test returns False when producer is None."""
        service._producer = None
        result = await service.publish_user_blocked(
            user_id=user_id,
            blocked_by="admin",
        )
        assert result is False


class TestPublishUserUnblocked:
    """Tests for publish_user_unblocked method."""

    @pytest.fixture
    def mock_producer(self):
        producer = AsyncMock()
        producer.send_event = AsyncMock(return_value=True)
        return producer

    @pytest.fixture
    def service(self, mock_producer):
        return KafkaProducerService(mock_producer)

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_publish_user_unblocked(self, service, mock_producer, user_id):
        """Test publishing user unblocked event."""
        result = await service.publish_user_unblocked(
            user_id=user_id,
            unblocked_by="admin@example.com",
            reason="Appeal approved",
            trace_id="trace_456",
        )

        assert result is True
        call_kwargs = mock_producer.send_event.call_args[1]

        assert call_kwargs["topic"] == "user.unblocked"
        assert call_kwargs["event"].event_type == "user.unblocked"
        assert call_kwargs["event"].data["user_id"] == str(user_id)
        assert call_kwargs["event"].data["unblocked_by"] == "admin@example.com"
        assert call_kwargs["event"].data["reason"] == "Appeal approved"


class TestPublishPasswordChanged:
    """Tests for publish_password_changed method."""

    @pytest.fixture
    def mock_producer(self):
        producer = AsyncMock()
        producer.send_event = AsyncMock(return_value=True)
        return producer

    @pytest.fixture
    def service(self, mock_producer):
        return KafkaProducerService(mock_producer)

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_publish_password_changed_full(self, service, mock_producer, user_id):
        """Test publishing password changed with all fields."""
        result = await service.publish_password_changed(
            user_id=user_id,
            source="user",
            ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            trace_id="trace_pwd",
        )

        assert result is True
        call_kwargs = mock_producer.send_event.call_args[1]

        assert call_kwargs["topic"] == "password.changed"
        assert call_kwargs["event"].event_type == "password.changed"
        assert call_kwargs["event"].data["user_id"] == str(user_id)
        assert call_kwargs["event"].data["source"] == "user"
        assert call_kwargs["event"].data["ip"] == "192.168.1.1"

    async def test_publish_password_changed_default_source(self, service, mock_producer, user_id):
        """Test publishing password changed with default source."""
        await service.publish_password_changed(user_id=user_id)
        call_kwargs = mock_producer.send_event.call_args[1]
        assert call_kwargs["event"].data["source"] == "user"


class TestPublishSessionRevoked:
    """Tests for publish_session_revoked method."""

    @pytest.fixture
    def mock_producer(self):
        producer = AsyncMock()
        producer.send_event = AsyncMock(return_value=True)
        return producer

    @pytest.fixture
    def service(self, mock_producer):
        return KafkaProducerService(mock_producer)

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_publish_session_revoked_single(self, service, mock_producer, user_id):
        """Test publishing single session revocation."""
        await service.publish_session_revoked(
            user_id=user_id,
            session_id="session_123",
            all_sessions=False,
            reason="logout",
            trace_id="trace_revoke",
        )

        call_kwargs = mock_producer.send_event.call_args[1]
        assert call_kwargs["topic"] == "session.revoked"
        assert call_kwargs["event"].data["session_id"] == "session_123"
        assert call_kwargs["event"].data["all_sessions"] is False

    async def test_publish_session_revoked_all(self, service, mock_producer, user_id):
        """Test publishing all sessions revocation."""
        await service.publish_session_revoked(
            user_id=user_id,
            all_sessions=True,
            reason="password_change",
        )

        call_kwargs = mock_producer.send_event.call_args[1]
        assert call_kwargs["event"].data["all_sessions"] is True
        assert call_kwargs["event"].data["session_id"] is None


class TestPublishUserCreated:
    """Tests for publish_user_created method."""

    @pytest.fixture
    def mock_producer(self):
        producer = AsyncMock()
        producer.send_event = AsyncMock(return_value=True)
        return producer

    @pytest.fixture
    def service(self, mock_producer):
        return KafkaProducerService(mock_producer)

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_publish_user_created(self, service, mock_producer, user_id):
        """Test publishing user created event."""
        await service.publish_user_created(
            user_id=user_id,
            email_hash="hashed_email_123",
            trace_id="trace_create",
        )

        call_kwargs = mock_producer.send_event.call_args[1]
        assert call_kwargs["topic"] == "user.created"
        assert call_kwargs["event"].event_type == "user.created"
        assert call_kwargs["event"].data["email_hash"] == "hashed_email_123"


class TestPublishUserDeleted:
    """Tests for publish_user_deleted method."""

    @pytest.fixture
    def mock_producer(self):
        producer = AsyncMock()
        producer.send_event = AsyncMock(return_value=True)
        return producer

    @pytest.fixture
    def service(self, mock_producer):
        return KafkaProducerService(mock_producer)

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_publish_user_deleted(self, service, mock_producer, user_id):
        """Test publishing user deleted event."""
        await service.publish_user_deleted(
            user_id=user_id,
            email_hash="hashed_email_456",
            trace_id="trace_delete",
        )

        call_kwargs = mock_producer.send_event.call_args[1]
        assert call_kwargs["topic"] == "user.deleted"
        assert call_kwargs["event"].event_type == "user.deleted"
        assert call_kwargs["event"].data["email_hash"] == "hashed_email_456"


class TestPublishEmailVerified:
    """Tests for publish_email_verified method."""

    @pytest.fixture
    def mock_producer(self):
        producer = AsyncMock()
        producer.send_event = AsyncMock(return_value=True)
        return producer

    @pytest.fixture
    def service(self, mock_producer):
        return KafkaProducerService(mock_producer)

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_publish_email_verified(self, service, mock_producer, user_id):
        """Test publishing email verified event."""
        await service.publish_email_verified(
            user_id=user_id,
            email_hash="verified_email_hash",
            trace_id="trace_verify",
        )

        call_kwargs = mock_producer.send_event.call_args[1]
        assert call_kwargs["topic"] == "user.email.verified"
        assert call_kwargs["event"].event_type == "user.email.verified"
        assert call_kwargs["event"].data["email_hash"] == "verified_email_hash"


class TestPublishBatch:
    """Tests for publish_batch method."""

    @pytest.fixture
    def mock_producer(self):
        producer = AsyncMock()
        producer.send_event = AsyncMock(return_value=True)
        return producer

    @pytest.fixture
    def service(self, mock_producer):
        return KafkaProducerService(mock_producer)

    async def test_publish_batch(self, service, mock_producer):
        """Test batch publishing of multiple events."""
        events = [
            ("user.created", "user.created", {"id": "1"}, "user1"),
            ("user.blocked", "user.blocked", {"id": "2"}, "user2"),
            ("password.changed", "password.changed", {"id": "3"}, "user3"),
        ]

        count = await service.publish_batch(events)

        assert count == 3
        assert mock_producer.send_event.call_count == 3

    async def test_publish_batch_empty(self, service, mock_producer):
        """Test batch publishing with empty list."""
        count = await service.publish_batch([])
        assert count == 0
        mock_producer.send_event.assert_not_called()

    async def test_publish_batch_producer_none(self, service):
        """Test returns 0 when producer is None."""
        service._producer = None
        count = await service.publish_batch([("topic", "event", {}, "key")])
        assert count == 0


class TestEdgeCases:
    """Tests for edge cases."""

    @pytest.fixture
    def mock_producer(self):
        producer = AsyncMock()
        producer.send_event = AsyncMock(return_value=True)
        return producer

    @pytest.fixture
    def service(self, mock_producer):
        return KafkaProducerService(mock_producer)

    async def test_all_methods_return_bool_from_producer(self, service, mock_producer):
        """Test that all publish methods return the bool from send_event."""
        user_id = uuid4()
        methods = [
            service.publish_verification_code("u", "c", "email", "t@t.com"),
            service.publish_user_blocked(user_id, "admin"),
            service.publish_user_unblocked(user_id, "admin"),
            service.publish_password_changed(user_id),
            service.publish_session_revoked(user_id),
            service.publish_user_created(user_id, "hash"),
            service.publish_user_deleted(user_id, "hash"),
            service.publish_email_verified(user_id, "hash"),
        ]
        for coro in methods:
            result = await coro
            assert result is True

    async def test_mask_email_special_chars(self, service):
        """Test email masking with special characters."""
        result = service._mask_recipient("test.user+tag@domain.co.uk", "email")
        assert result == "tes***@domain.co.uk"

    async def test_mask_sms_with_plus(self, service):
        """Test SMS masking preserves + prefix."""
        result = service._mask_recipient("+1234567890", "sms")
        assert result == "+***7890"