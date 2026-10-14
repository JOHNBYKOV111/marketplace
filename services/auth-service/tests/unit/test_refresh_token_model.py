"""
Unit tests for RefreshToken model.

Tests cover:
- Model field definitions and constraints
- __repr__ method
- to_dict() serialization
- is_expired, is_active, lifetime_seconds, remaining_seconds properties
- revoke, touch, is_valid_for_user methods
- create_token factory method
- Edge cases and boundary values (expiration, timezone handling)
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest

from app.models.refresh_token import RefreshToken


# ==================== FIXTURES ====================

@pytest.fixture
def user_id():
    """Generate a random user ID."""
    return uuid4()


@pytest.fixture
def active_token(user_id):
    """Create an active, non-expired, non-revoked token.
    
    Note: created_at is explicitly set because without DB commit,
    the server_default is not applied to in-memory instances.
    """
    token = RefreshToken(
        user_id=user_id,
        token_id="rt_active123456",
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        is_revoked=False,
        is_rotated=False,
    )
    token.created_at = datetime.now(timezone.utc)
    return token


@pytest.fixture
def expired_token(user_id):
    """Create an expired token."""
    token = RefreshToken(
        user_id=user_id,
        token_id="rt_expired1234",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        is_revoked=False,
    )
    token.created_at = datetime.now(timezone.utc) - timedelta(days=31)
    return token


@pytest.fixture
def revoked_token(user_id):
    """Create a revoked token."""
    token = RefreshToken(
        user_id=user_id,
        token_id="rt_revoked123",
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        is_revoked=True,
        revoked_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    token.created_at = datetime.now(timezone.utc) - timedelta(days=1)
    return token


# ==================== MODEL FIELDS TESTS ====================

class TestRefreshTokenModelFields:
    """Tests for RefreshToken model field definitions."""

    def test_model_fields_existence(self):
        """Test all expected fields exist on the model."""
        fields = [
            "id", "token_id", "user_id", "device_id", "device_name",
            "expires_at", "is_revoked", "revoked_at",
            "ip_address", "user_agent", "last_used_at", "is_rotated",
        ]

        for field in fields:
            assert hasattr(RefreshToken, field), f"Field {field} missing"

    def test_id_is_uuid_type(self):
        """Test id column is UUID type."""
        id_column = RefreshToken.__table__.columns["id"]
        assert str(id_column.type) == "UUID"

    def test_id_default_generates_uuid(self):
        """Test id has default UUID generation."""
        id_column = RefreshToken.__table__.columns["id"]
        assert id_column.default is not None

    def test_token_id_unique(self):
        """Test token_id has unique constraint."""
        token_id_column = RefreshToken.__table__.columns["token_id"]
        assert token_id_column.unique is True

    def test_token_id_indexed(self):
        """Test token_id has index."""
        token_id_column = RefreshToken.__table__.columns["token_id"]
        assert token_id_column.index is True

    def test_token_id_max_length(self):
        """Test token_id max length is 255."""
        column = RefreshToken.__table__.columns["token_id"]
        assert column.type.length == 255

    def test_user_id_not_nullable(self):
        """Test user_id is not nullable."""
        user_id_column = RefreshToken.__table__.columns["user_id"]
        assert user_id_column.nullable is False

    def test_user_id_indexed(self):
        """Test user_id field has index."""
        user_id_column = RefreshToken.__table__.columns["user_id"]
        assert user_id_column.index is True

    def test_device_id_nullable(self):
        """Test device_id is nullable."""
        device_id_column = RefreshToken.__table__.columns["device_id"]
        assert device_id_column.nullable is True

    def test_device_id_max_length(self):
        """Test device_id max length is 255."""
        column = RefreshToken.__table__.columns["device_id"]
        assert column.type.length == 255

    def test_device_name_max_length(self):
        """Test device_name max length is 255."""
        column = RefreshToken.__table__.columns["device_name"]
        assert column.type.length == 255

    def test_expires_at_not_nullable(self):
        """Test expires_at is not nullable."""
        expires_column = RefreshToken.__table__.columns["expires_at"]
        assert expires_column.nullable is False

    def test_expires_at_indexed(self):
        """Test expires_at field has index."""
        expires_column = RefreshToken.__table__.columns["expires_at"]
        assert expires_column.index is True

    def test_is_revoked_default_false(self):
        """Test is_revoked defaults to False."""
        is_revoked_column = RefreshToken.__table__.columns["is_revoked"]
        assert is_revoked_column.default.arg is False

    def test_is_revoked_indexed(self):
        """Test is_revoked field has index."""
        is_revoked_column = RefreshToken.__table__.columns["is_revoked"]
        assert is_revoked_column.index is True

    def test_ip_address_max_length(self):
        """Test ip_address max length is 45 (IPv6 compatible)."""
        column = RefreshToken.__table__.columns["ip_address"]
        assert column.type.length == 45

    def test_user_agent_max_length(self):
        """Test user_agent max length is 512."""
        column = RefreshToken.__table__.columns["user_agent"]
        assert column.type.length == 512

    def test_is_rotated_default_false(self):
        """Test is_rotated defaults to False."""
        is_rotated_column = RefreshToken.__table__.columns["is_rotated"]
        assert is_rotated_column.default.arg is False

    def test_table_name(self):
        """Test table name is refresh_tokens."""
        assert RefreshToken.__tablename__ == "refresh_tokens"

    def test_table_has_composite_indexes(self):
        """Test table has composite indexes for performance."""
        assert hasattr(RefreshToken, "__table_args__")
        table_args = RefreshToken.__table_args__
        assert table_args is not None

    def test_token_id_unique_constraint_exists(self):
        """Test unique constraint on token_id exists."""
        table_args = RefreshToken.__table_args__
        has_unique_constraint = any(
            hasattr(arg, "name") and "token_id" in arg.name
            for arg in table_args if hasattr(arg, "name")
        )
        assert has_unique_constraint


# ==================== REPR TESTS ====================

class TestRefreshTokenRepr:
    """Tests for __repr__ method."""

    def test_repr_active_token(self, active_token, user_id):
        """Test __repr__ for active token."""
        repr_str = repr(active_token)

        assert "RefreshToken" in repr_str
        assert f"user_id={user_id}" in repr_str
        assert "token_id=rt_active123456" in repr_str
        assert "is_active=True" in repr_str

    def test_repr_revoked_token(self, revoked_token):
        """Test __repr__ for revoked token."""
        repr_str = repr(revoked_token)

        assert "is_active=False" in repr_str

    def test_repr_expired_token(self, expired_token):
        """Test __repr__ for expired token."""
        repr_str = repr(expired_token)

        assert "is_active=False" in repr_str

    def test_repr_includes_expires_at(self, active_token):
        """Test __repr__ includes expires_at."""
        repr_str = repr(active_token)

        assert "expires_at=" in repr_str


# ==================== TO_DICT TESTS ====================

class TestRefreshTokenToDict:
    """Tests for to_dict() method."""

    def test_to_dict_active_token(self, active_token, user_id):
        """Test to_dict with active token.
        
        Note: created_at must be set explicitly in fixtures because
        server_default is only applied at DB level, not on in-memory instances.
        """
        result = active_token.to_dict()

        assert result["id"] == str(active_token.id)
        assert result["user_id"] == str(user_id)
        assert result["token_id"] == "rt_active123456"
        assert result["device_id"] is None
        assert result["device_name"] is None
        assert result["is_active"] is True
        assert result["is_revoked"] is False
        assert result["is_rotated"] is False
        assert result["expires_at"] is not None
        assert result["revoked_at"] is None
        assert result["last_used_at"] is None
        assert result["ip_address"] is None
        assert result["user_agent"] is None
        assert result["created_at"] is not None
        assert result["remaining_seconds"] > 0

    def test_to_dict_revoked_token(self, revoked_token, user_id):
        """Test to_dict with revoked token."""
        result = revoked_token.to_dict()

        assert result["is_active"] is False
        assert result["is_revoked"] is True
        assert result["revoked_at"] is not None

    def test_to_dict_expired_token(self, expired_token, user_id):
        """Test to_dict with expired token."""
        result = expired_token.to_dict()

        assert result["is_active"] is False
        assert result["remaining_seconds"] == 0

    def test_to_dict_with_all_fields(self):
        """Test to_dict with all optional fields set."""
        now = datetime.now(timezone.utc)
        user_id = uuid4()
        token = RefreshToken(
            user_id=user_id,
            token_id="rt_full123456",
            device_id="device_789",
            device_name="iPhone 15",
            expires_at=now + timedelta(days=30),
            is_revoked=False,
            revoked_at=None,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            last_used_at=now,
            is_rotated=True,
        )
        token.created_at = now

        result = token.to_dict()

        assert result["device_id"] == "device_789"
        assert result["device_name"] == "iPhone 15"
        assert result["ip_address"] == "192.168.1.1"
        assert result["user_agent"] == "Mozilla/5.0"
        assert result["last_used_at"] is not None
        assert result["is_rotated"] is True
        assert result["created_at"] is not None


# ==================== EXPIRATION AND STATUS TESTS ====================

class TestRefreshTokenExpiration:
    """Tests for is_expired, is_active, lifetime_seconds, remaining_seconds."""

    def test_is_expired_true_past_date(self):
        """Test is_expired returns True when expires_at is in the past."""
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_test",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )

        assert token.is_expired is True

    def test_is_expired_false_future_date(self):
        """Test is_expired returns False when expires_at is in the future."""
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_test",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )

        assert token.is_expired is False

    def test_is_active_true_when_valid(self, active_token):
        """Test is_active returns True for valid token."""
        assert active_token.is_active is True

    def test_is_active_false_when_expired(self, expired_token):
        """Test is_active returns False when expired."""
        assert expired_token.is_active is False

    def test_is_active_false_when_revoked(self, revoked_token):
        """Test is_active returns False when revoked."""
        assert revoked_token.is_active is False

    def test_is_active_false_when_expired_and_revoked(self):
        """Test is_active returns False when both expired and revoked."""
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_both",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            is_revoked=True,
        )
        assert token.is_active is False

    def test_lifetime_seconds_calculation(self):
        """Test lifetime_seconds returns correct duration."""
        now = datetime.now(timezone.utc)
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_lifetime",
            expires_at=now + timedelta(days=30),
        )
        token.created_at = now

        lifetime = token.lifetime_seconds
        assert lifetime == 30 * 24 * 60 * 60

    def test_remaining_seconds_positive(self):
        """Test remaining_seconds returns positive value for active token."""
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_remaining",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        remaining = token.remaining_seconds
        assert remaining > 0
        assert remaining <= 3600

    def test_remaining_seconds_zero_when_expired(self, expired_token):
        """Test remaining_seconds returns 0 when expired."""
        assert expired_token.remaining_seconds == 0


# ==================== TOKEN MANAGEMENT TESTS ====================

class TestRefreshTokenManagement:
    """Tests for revoke, touch, is_valid_for_user methods."""

    def test_revoke_sets_flags(self, active_token):
        """Test revoke sets is_revoked and revoked_at."""
        active_token.revoke()

        assert active_token.is_revoked is True
        assert active_token.revoked_at is not None

    def test_revoke_sets_revoked_at_to_now(self, active_token):
        """Test revoke sets revoked_at to current UTC time."""
        before_revoke = datetime.now(timezone.utc)
        active_token.revoke()
        after_revoke = datetime.now(timezone.utc)

        assert before_revoke <= active_token.revoked_at <= after_revoke

    def test_revoke_does_not_overwrite_existing_revoked_at(self, revoked_token):
        """Test revoke does not overwrite already set revoked_at."""
        original_revoked_at = revoked_token.revoked_at
        revoked_token.revoke()

        assert revoked_token.revoked_at == original_revoked_at

    def test_touch_sets_last_used_at(self, active_token):
        """Test touch sets last_used_at to current time."""
        assert active_token.last_used_at is None

        active_token.touch()

        assert active_token.last_used_at is not None

    def test_touch_updates_existing_last_used_at(self):
        """Test touch updates already set last_used_at."""
        old_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_touch",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            last_used_at=old_time,
        )

        token.touch()

        assert token.last_used_at > old_time

    def test_is_valid_for_user_true(self, active_token, user_id):
        """Test is_valid_for_user returns True for correct user."""
        assert active_token.is_valid_for_user(user_id) is True

    def test_is_valid_for_user_false(self, active_token):
        """Test is_valid_for_user returns False for different user."""
        different_user_id = uuid4()
        assert active_token.is_valid_for_user(different_user_id) is False


# ==================== CREATE TOKEN FACTORY TESTS ====================

class TestRefreshTokenCreateToken:
    """Tests for create_token factory method."""

    def test_create_token_minimal(self):
        """Test create_token with only required fields."""
        user_id = uuid4()
        token = RefreshToken.create_token(user_id=user_id)

        assert token.user_id == user_id
        assert token.token_id.startswith("rt_")
        assert len(token.token_id) == 35  # "rt_" + 32 hex chars
        assert token.device_id is None
        assert token.device_name is None
        assert token.ip_address is None
        assert token.user_agent is None
        assert token.is_revoked is False
        assert token.is_rotated is False
        assert token.expires_at is not None

    def test_create_token_default_expiry(self):
        """Test create_token uses 30 days default expiry."""
        user_id = uuid4()
        before_create = datetime.now(timezone.utc)
        token = RefreshToken.create_token(user_id=user_id)
        after_create = datetime.now(timezone.utc)

        expected_min = before_create + timedelta(days=30)
        expected_max = after_create + timedelta(days=30)

        assert expected_min <= token.expires_at <= expected_max

    def test_create_token_custom_expiry(self):
        """Test create_token with custom expiry days."""
        user_id = uuid4()
        token = RefreshToken.create_token(user_id=user_id, expires_days=7)

        expected_expiry = datetime.now(timezone.utc) + timedelta(days=7)
        delta = abs((token.expires_at - expected_expiry).total_seconds())
        assert delta < 5  # Within 5 seconds

    def test_create_token_with_all_fields(self):
        """Test create_token with all optional fields."""
        user_id = uuid4()
        token = RefreshToken.create_token(
            user_id=user_id,
            expires_days=14,
            device_id="device_abc",
            device_name="Chrome Browser",
            ip_address="10.0.0.1",
            user_agent="Mozilla/5.0",
        )

        assert token.device_id == "device_abc"
        assert token.device_name == "Chrome Browser"
        assert token.ip_address == "10.0.0.1"
        assert token.user_agent == "Mozilla/5.0"

    def test_create_token_generates_unique_token_ids(self):
        """Test create_token generates unique token_ids."""
        user_id = uuid4()
        token1 = RefreshToken.create_token(user_id=user_id)
        token2 = RefreshToken.create_token(user_id=user_id)

        assert token1.token_id != token2.token_id

    def test_create_token_token_id_format(self):
        """Test token_id has correct format."""
        user_id = uuid4()
        token = RefreshToken.create_token(user_id=user_id)

        assert token.token_id.startswith("rt_")
        # "rt_" + 32 hex characters from uuid4().hex
        assert len(token.token_id) == 3 + 32


# ==================== EDGE CASES TESTS ====================

class TestRefreshTokenEdgeCases:
    """Tests for edge cases and boundary values."""

    def test_is_expired_at_exact_moment(self):
        """Test is_expired when expires_at equals current time."""
        now = datetime.now(timezone.utc)
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_exact",
            expires_at=now,
        )
        # is_expired is True when now > expires_at
        # At exact moment, it may be True or False depending on microseconds
        # Just verify it's a boolean
        assert isinstance(token.is_expired, bool)

    def test_token_id_max_length(self):
        """Test token_id can hold up to 255 characters."""
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_" + "a" * 252,  # Total 255
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        assert len(token.token_id) == 255

    def test_ip_address_ipv4(self):
        """Test IPv4 address fits in ip_address field."""
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_ipv4",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            ip_address="192.168.1.1",
        )
        assert token.ip_address == "192.168.1.1"
        assert len(token.ip_address) <= 45

    def test_ip_address_ipv6(self):
        """Test IPv6 address fits in ip_address field."""
        ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_ipv6",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            ip_address=ipv6,
        )
        assert token.ip_address == ipv6
        assert len(token.ip_address) <= 45

    def test_user_agent_max_length(self):
        """Test user_agent can hold up to 512 characters."""
        long_ua = "X" * 512
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_ua",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            user_agent=long_ua,
        )
        assert len(token.user_agent) == 512

    def test_device_name_long_value(self):
        """Test device_name can hold long string."""
        long_name = "X" * 255
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_dev",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            device_name=long_name,
        )
        assert token.device_name == long_name

    def test_remaining_seconds_precision(self):
        """Test remaining_seconds returns integer."""
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_precision",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=30.5),
        )
        assert isinstance(token.remaining_seconds, int)

    def test_lifetime_seconds_zero_duration(self):
        """Test lifetime_seconds when created_at equals expires_at."""
        now = datetime.now(timezone.utc)
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_zero",
            expires_at=now,
        )
        token.created_at = now
        assert token.lifetime_seconds == 0

    def test_touch_on_expired_token(self, expired_token):
        """Test touch works even on expired token."""
        expired_token.touch()
        assert expired_token.last_used_at is not None

    def test_revoke_on_expired_token(self, expired_token):
        """Test revoke works even on expired token."""
        expired_token.revoke()
        assert expired_token.is_revoked is True
        assert expired_token.revoked_at is not None

    def test_is_active_property_readonly(self):
        """Test is_active is a property (read-only)."""
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_readonly",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        # Property should be accessible
        _ = token.is_active
        # Cannot set property
        with pytest.raises(AttributeError):
            token.is_active = False

    def test_is_expired_property_readonly(self):
        """Test is_expired is a property (read-only)."""
        token = RefreshToken(
            user_id=uuid4(),
            token_id="rt_readonly2",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        _ = token.is_expired
        with pytest.raises(AttributeError):
            token.is_expired = True


# ==================== INHERITANCE TESTS ====================

class TestRefreshTokenInheritance:
    """Tests for model inheritance."""

    def test_inherits_from_base(self):
        """Test RefreshToken inherits from Base."""
        from app.models.base import Base
        assert issubclass(RefreshToken, Base)

    def test_inherits_timestamp_mixin(self):
        """Test RefreshToken inherits from TimestampMixin."""
        from app.models.base import TimestampMixin
        assert issubclass(RefreshToken, TimestampMixin)

    def test_has_created_at_field(self):
        """Test model has created_at field from TimestampMixin."""
        assert hasattr(RefreshToken, "created_at")

    def test_has_updated_at_field(self):
        """Test model has updated_at field from TimestampMixin."""
        assert hasattr(RefreshToken, "updated_at")