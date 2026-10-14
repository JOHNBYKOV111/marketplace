"""
Unit tests for UserService.

Tests cover:
- create_user (success, duplicate email, duplicate phone)
- get_user_by_id (cache hit, cache miss, not found)
- get_user_by_email / get_user_by_phone
- update_user (success, not found, immutable fields, cache invalidation)
- delete_user (soft delete, already deleted, not found)
- hard_delete_expired_users (TTL cleanup)
- block_user / unblock_user
- verify_email / verify_phone
- get_active_sessions_count (Redis)
- Kafka event publishing (user.registered, user.deleted, user.updated, user.blocked)
- Graceful handling of Redis and Kafka failures
- Edge cases (empty phone, None values in update)
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest

from app.core.exceptions import NotFoundException, ConflictException
from app.models.user import User
from app.services.user_service import UserService


# ==================== FIXTURES ====================

@pytest.fixture
def mock_db():
    """Mock database session."""
    db = AsyncMock()
    db.commit = AsyncMock()
    db.add = MagicMock()
    return db


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    redis = AsyncMock()
    redis.get_json = AsyncMock(return_value=None)
    redis.setex = AsyncMock(return_value=True)
    redis.delete = AsyncMock(return_value=1)
    redis.get = AsyncMock(return_value=None)
    return redis


@pytest.fixture
def mock_kafka():
    """Mock Kafka producer."""
    kafka = AsyncMock()
    kafka.send = AsyncMock(return_value=True)
    return kafka


@pytest.fixture
def service(mock_db, mock_redis, mock_kafka):
    """Create UserService with mocked dependencies."""
    svc = UserService(db=mock_db, redis_client=mock_redis, kafka_producer=mock_kafka)
    svc.user_repo = AsyncMock()
    return svc


@pytest.fixture
def user_id():
    """Generate a random user ID."""
    return uuid4()


@pytest.fixture
def mock_user(user_id):
    """Create a mock User object with explicit return values."""
    user = MagicMock(spec=User)
    user.id = user_id
    user.email = "user@example.com"
    user.email_hash = "hashed_email"
    user.phone_hash = None
    user.password_hash = "hashed_pw"
    user.first_name = "John"
    user.last_name = "Doe"
    user.is_active = True
    user.is_email_verified = False
    user.is_superuser = False
    user.is_deleted = False
    user.deleted_at = None
    user.deletion_requested_at = None
    user.created_at = datetime.now(timezone.utc)
    user.updated_at = datetime.now(timezone.utc)
    return user


# ==================== CREATE USER TESTS ====================

class TestUserServiceCreateUser:
    """Tests for create_user method."""

    @pytest.mark.asyncio
    async def test_create_user_success(self, service, user_id, mock_user):
        """Test successful user creation."""
        service.user_repo.get_by_email_hash = AsyncMock(return_value=None)
        service.user_repo.create = AsyncMock(return_value=mock_user)

        with patch.object(service, "_publish_user_registered", AsyncMock()):
            user = await service.create_user(
                user_id=user_id,
                email="user@example.com",
                password_hash="hashed_password",
            )

        assert user == mock_user
        service.user_repo.create.assert_called_once()
        service.db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_user_with_phone(self, service, user_id, mock_user):
        """Test user creation with phone number."""
        service.user_repo.get_by_email_hash = AsyncMock(return_value=None)
        service.user_repo.get_by_phone_hash = AsyncMock(return_value=None)
        service.user_repo.create = AsyncMock(return_value=mock_user)

        user = await service.create_user(
            user_id=user_id,
            email="user@example.com",
            password_hash="hash",
            phone="+1234567890",
        )

        assert user == mock_user

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, service, user_id):
        """Test user creation with existing email."""
        service.user_repo.get_by_email_hash = AsyncMock(return_value=MagicMock())

        with pytest.raises(ConflictException, match="already exists"):
            await service.create_user(
                user_id=user_id,
                email="user@example.com",
                password_hash="hash",
            )

        service.user_repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_user_duplicate_phone(self, service, user_id):
        """Test user creation with existing phone."""
        service.user_repo.get_by_email_hash = AsyncMock(return_value=None)
        service.user_repo.get_by_phone_hash = AsyncMock(return_value=MagicMock())

        with pytest.raises(ConflictException, match="already exists"):
            await service.create_user(
                user_id=user_id,
                email="user@example.com",
                password_hash="hash",
                phone="+1234567890",
            )

    @pytest.mark.asyncio
    async def test_create_user_with_names(self, service, user_id, mock_user):
        """Test user creation with first and last name."""
        service.user_repo.get_by_email_hash = AsyncMock(return_value=None)
        service.user_repo.create = AsyncMock(return_value=mock_user)

        user = await service.create_user(
            user_id=user_id,
            email="user@example.com",
            password_hash="hash",
            first_name="Jane",
            last_name="Smith",
        )

        assert user == mock_user


# ==================== GET USER TESTS ====================

class TestUserServiceGetUser:
    """Tests for user retrieval methods."""

    @pytest.mark.asyncio
    async def test_get_user_by_id_cache_hit(self, service, user_id):
        """Test get_user_by_id with cache hit."""
        service._redis_client.get_json = AsyncMock(return_value={
            "id": str(user_id),
            "email": "cached@example.com",
            "is_active": True,
        })

        user = await service.get_user_by_id(user_id)

        assert user is not None
        service.user_repo.get_by_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_user_by_id_cache_miss(self, service, user_id, mock_user):
        """Test get_user_by_id with cache miss."""
        service._redis_client.get_json = AsyncMock(return_value=None)
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        user = await service.get_user_by_id(user_id)

        assert user == mock_user
        service.user_repo.get_by_id.assert_called_once_with(user_id)
        service._redis_client.setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_by_id_not_found(self, service, user_id):
        """Test get_user_by_id when user not found."""
        service._redis_client.get_json = AsyncMock(return_value=None)
        service.user_repo.get_by_id = AsyncMock(return_value=None)

        user = await service.get_user_by_id(user_id)

        assert user is None

    @pytest.mark.asyncio
    async def test_get_user_by_email(self, service, mock_user):
        """Test getting user by email."""
        service.user_repo.get_by_email_hash = AsyncMock(return_value=mock_user)

        user = await service.get_user_by_email("user@example.com")

        assert user == mock_user

    @pytest.mark.asyncio
    async def test_get_user_by_phone(self, service, mock_user):
        """Test getting user by phone."""
        mock_user.phone_hash = "hashed_phone"
        service.user_repo.get_by_phone_hash = AsyncMock(return_value=mock_user)

        user = await service.get_user_by_phone("+1234567890")

        assert user == mock_user


# ==================== UPDATE USER TESTS ====================

class TestUserServiceUpdateUser:
    """Tests for update_user method."""

    @pytest.mark.asyncio
    async def test_update_user_success(self, service, user_id, mock_user):
        """Test successful user update."""
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        with patch.object(service, "_publish_user_updated", AsyncMock()) as mock_publish:
            updated = await service.update_user(
                user_id=user_id,
                first_name="Jane",
                last_name="Smith",
            )

        assert updated == mock_user
        service.db.commit.assert_called_once()
        mock_publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_user_not_found(self, service, user_id):
        """Test updating non-existent user."""
        service.user_repo.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(NotFoundException, match="not found"):
            await service.update_user(user_id=user_id, first_name="Jane")

    @pytest.mark.asyncio
    async def test_update_user_invalidates_cache(self, service, user_id, mock_user):
        """Test updating user removes cached entry."""
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        await service.update_user(user_id=user_id, first_name="Jane")

        service._redis_client.delete.assert_called_once_with(f"user:{user_id}")

    @pytest.mark.asyncio
    async def test_update_user_partial_fields(self, service, user_id, mock_user):
        """Test updating only some fields."""
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        updated = await service.update_user(user_id=user_id, first_name="Jane")

        assert updated == mock_user


# ==================== DELETE USER TESTS ====================

class TestUserServiceDeleteUser:
    """Tests for delete_user method."""

    @pytest.mark.asyncio
    async def test_soft_delete_user(self, service, user_id, mock_user):
        """Test soft delete sets is_deleted flag."""
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        with patch.object(service, "_publish_user_deleted", AsyncMock()) as mock_publish:
            result = await service.delete_user(user_id=user_id)

        assert result is True
        assert mock_user.is_deleted is True
        assert mock_user.deleted_at is not None
        service.db.commit.assert_called_once()
        mock_publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_user_not_found(self, service, user_id):
        """Test deleting non-existent user."""
        service.user_repo.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(NotFoundException, match="not found"):
            await service.delete_user(user_id=user_id)

    @pytest.mark.asyncio
    async def test_delete_user_already_deleted(self, service, user_id, mock_user):
        """Test deleting already deleted user."""
        mock_user.is_deleted = True
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        result = await service.delete_user(user_id=user_id)

        assert result is True
        service.db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_hard_delete_expired_users(self, service):
        """Test hard delete of users past TTL."""
        service.user_repo.delete_expired_soft_deleted = AsyncMock(return_value=5)

        count = await service.hard_delete_expired_users()

        assert count == 5
        service.db.commit.assert_called_once()


# ==================== BLOCK/UNBLOCK TESTS ====================

class TestUserServiceBlockUnblock:
    """Tests for block_user and unblock_user methods."""

    @pytest.mark.asyncio
    async def test_block_user_success(self, service, user_id, mock_user):
        """Test successful user blocking."""
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        with patch.object(service, "_publish_user_blocked", AsyncMock()) as mock_publish:
            result = await service.block_user(user_id=user_id, reason="Violation")

        assert result is True
        assert mock_user.is_active is False
        service.db.commit.assert_called_once()
        mock_publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_block_user_already_blocked(self, service, user_id, mock_user):
        """Test blocking already blocked user."""
        mock_user.is_active = False
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        result = await service.block_user(user_id=user_id)

        assert result is True
        service.db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_block_user_not_found(self, service, user_id):
        """Test blocking non-existent user."""
        service.user_repo.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(NotFoundException, match="not found"):
            await service.block_user(user_id=user_id)

    @pytest.mark.asyncio
    async def test_unblock_user_success(self, service, user_id, mock_user):
        """Test successful user unblocking."""
        mock_user.is_active = False
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        with patch.object(service, "_publish_user_unblocked", AsyncMock()) as mock_publish:
            result = await service.unblock_user(user_id=user_id, reason="Appeal")

        assert result is True
        assert mock_user.is_active is True
        service.db.commit.assert_called_once()
        mock_publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_unblock_user_already_active(self, service, user_id, mock_user):
        """Test unblocking already active user."""
        mock_user.is_active = True
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        result = await service.unblock_user(user_id=user_id)

        assert result is True
        service.db.commit.assert_not_called()


# ==================== VERIFY TESTS ====================

class TestUserServiceVerify:
    """Tests for verify_email and verify_phone methods."""

    @pytest.mark.asyncio
    async def test_verify_email_success(self, service, user_id, mock_user):
        """Test successful email verification."""
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        with patch.object(service, "_publish_email_verified", AsyncMock()) as mock_publish:
            result = await service.verify_email(user_id)

        assert result is True
        assert mock_user.is_email_verified is True
        service.db.commit.assert_called_once()
        mock_publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_email_already_verified(self, service, user_id, mock_user):
        """Test verifying already verified email."""
        mock_user.is_email_verified = True
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        result = await service.verify_email(user_id)

        assert result is True
        service.db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_verify_email_user_not_found(self, service, user_id):
        """Test email verification for non-existent user."""
        service.user_repo.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(NotFoundException, match="not found"):
            await service.verify_email(user_id)

    @pytest.mark.asyncio
    async def test_verify_phone_success(self, service, user_id, mock_user):
        """Test successful phone verification."""
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        result = await service.verify_phone(user_id)

        assert result is True


# ==================== SESSION COUNT TESTS ====================

class TestUserServiceSessionCount:
    """Tests for get_active_sessions_count method."""

    @pytest.mark.asyncio
    async def test_get_active_sessions_count(self, service, user_id):
        """Test getting active sessions count from Redis."""
        service._redis_client.get = AsyncMock(return_value="3")

        count = await service.get_active_sessions_count(user_id)

        assert count == 3

    @pytest.mark.asyncio
    async def test_get_active_sessions_count_zero(self, service, user_id):
        """Test getting count when no active sessions."""
        service._redis_client.get = AsyncMock(return_value=None)

        count = await service.get_active_sessions_count(user_id)

        assert count == 0


# ==================== KAFKA EVENT TESTS ====================

class TestUserServiceKafkaEvents:
    """Tests for Kafka event publishing."""

    @pytest.mark.asyncio
    async def test_publish_user_registered(self, service, user_id):
        """Test publishing user.registered event."""
        await service._publish_user_registered(user_id, "user@example.com")

        service._kafka_producer.send.assert_called_once()
        call_args = service._kafka_producer.send.call_args
        assert call_args[0][0] == "user.registered"
        assert call_args[1]["value"]["user_id"] == str(user_id)
        assert call_args[1]["value"]["email"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_publish_user_deleted(self, service, user_id):
        """Test publishing user.deleted event."""
        await service._publish_user_deleted(user_id)

        service._kafka_producer.send.assert_called_once()
        call_args = service._kafka_producer.send.call_args
        assert call_args[0][0] == "user.deleted"
        assert call_args[1]["value"]["user_id"] == str(user_id)

    @pytest.mark.asyncio
    async def test_publish_user_updated(self, service, user_id):
        """Test publishing user.updated event."""
        changes = {"first_name": "NewName"}
        await service._publish_user_updated(user_id, changes)

        service._kafka_producer.send.assert_called_once()
        call_args = service._kafka_producer.send.call_args
        assert call_args[0][0] == "user.updated"
        assert call_args[1]["value"]["changes"] == changes

    @pytest.mark.asyncio
    async def test_publish_user_blocked(self, service, user_id):
        """Test publishing user.blocked event."""
        await service._publish_user_blocked(user_id, "Violation")

        service._kafka_producer.send.assert_called_once()
        call_args = service._kafka_producer.send.call_args
        assert call_args[0][0] == "user.blocked"
        assert call_args[1]["value"]["reason"] == "Violation"

    @pytest.mark.asyncio
    async def test_publish_user_unblocked(self, service, user_id):
        """Test publishing user.unblocked event."""
        await service._publish_user_unblocked(user_id, "Appeal")

        service._kafka_producer.send.assert_called_once()
        call_args = service._kafka_producer.send.call_args
        assert call_args[0][0] == "user.unblocked"

    @pytest.mark.asyncio
    async def test_publish_email_verified(self, service, user_id):
        """Test publishing user.email.verified event."""
        await service._publish_email_verified(user_id, "hashed_email")

        service._kafka_producer.send.assert_called_once()
        call_args = service._kafka_producer.send.call_args
        assert call_args[0][0] == "user.email.verified"


# ==================== EDGE CASES TESTS ====================

class TestUserServiceEdgeCases:
    """Tests for edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_create_user_with_empty_phone(self, service, user_id, mock_user):
        """Test user creation with empty phone string."""
        service.user_repo.get_by_email_hash = AsyncMock(return_value=None)
        service.user_repo.create = AsyncMock(return_value=mock_user)

        user = await service.create_user(
            user_id=user_id,
            email="user@example.com",
            password_hash="hash",
            phone="",
        )

        assert user == mock_user

    @pytest.mark.asyncio
    async def test_update_user_none_values(self, service, user_id, mock_user):
        """Test update with None values does not change fields."""
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        updated = await service.update_user(
            user_id=user_id,
            first_name=None,
            last_name=None,
        )

        assert updated == mock_user

    @pytest.mark.asyncio
    async def test_redis_failure_graceful(self, service, user_id, mock_user):
        """Test service handles Redis failure gracefully."""
        service._redis_client.get_json = AsyncMock(side_effect=Exception("Redis down"))
        service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        user = await service.get_user_by_id(user_id)

        assert user == mock_user

    @pytest.mark.asyncio
    async def test_kafka_failure_does_not_block(self, service, user_id, mock_user):
        """Test user creation succeeds even if Kafka fails."""
        service.user_repo.get_by_email_hash = AsyncMock(return_value=None)
        service.user_repo.create = AsyncMock(return_value=mock_user)
        service._kafka_producer.send = AsyncMock(side_effect=Exception("Kafka down"))

        user = await service.create_user(
            user_id=user_id,
            email="user@example.com",
            password_hash="hash",
        )

        assert user == mock_user
        service.db.commit.assert_called_once()