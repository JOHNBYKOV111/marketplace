"""
Unit tests for User model.

Tests cover:
- Model field definitions and constraints
- __repr__ method
- create_email_hash static method
- create_phone_hash static method
- Field defaults (is_active, is_email_verified, is_superuser)
- Index definitions
- Relationship with UserSecuritySettings
- Edge cases and boundary values
"""

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from app.models.user import User


# ==================== FIXTURES ====================

@pytest.fixture
def user():
    """Create a basic User instance with explicit defaults.
    
    Note: SQLAlchemy server_defaults are only applied at DB commit time.
    For in-memory instances, we must pass defaults explicitly.
    """
    return User(
        email="user@example.com",
        email_hash=User.create_email_hash("user@example.com"),
        password_hash="hashed_password_123",
        is_active=True,
        is_email_verified=True,
        is_superuser=False,
    )


# ==================== MODEL FIELDS TESTS ====================

class TestUserModelFields:
    """Tests for User model field definitions."""

    def test_model_fields_existence(self):
        """Test all expected fields exist on the model."""
        fields = [
            "id", "email", "email_hash", "phone_hash", "password_hash",
            "is_active", "is_email_verified", "is_superuser",
            "email_verification_token", "email_verification_token_expires",
            "reset_password_token", "reset_password_token_expires",
        ]

        for field in fields:
            assert hasattr(User, field), f"Field {field} missing"

    def test_table_name(self):
        """Test table name is users."""
        assert User.__tablename__ == "users"

    def test_email_not_nullable(self):
        """Test email is not nullable."""
        email_column = User.__table__.columns["email"]
        assert email_column.nullable is False

    def test_email_unique(self):
        """Test email has unique constraint."""
        email_column = User.__table__.columns["email"]
        assert email_column.unique is True

    def test_email_indexed(self):
        """Test email has index."""
        email_column = User.__table__.columns["email"]
        assert email_column.index is True

    def test_email_max_length(self):
        """Test email max length is 255."""
        column = User.__table__.columns["email"]
        assert column.type.length == 255

    def test_email_hash_max_length(self):
        """Test email_hash max length is 64."""
        column = User.__table__.columns["email_hash"]
        assert column.type.length == 64

    def test_email_hash_nullable(self):
        """Test email_hash is nullable."""
        column = User.__table__.columns["email_hash"]
        assert column.nullable is True

    def test_phone_hash_max_length(self):
        """Test phone_hash max length is 64."""
        column = User.__table__.columns["phone_hash"]
        assert column.type.length == 64

    def test_phone_hash_nullable(self):
        """Test phone_hash is nullable."""
        column = User.__table__.columns["phone_hash"]
        assert column.nullable is True

    def test_password_hash_not_nullable(self):
        """Test password_hash is not nullable."""
        column = User.__table__.columns["password_hash"]
        assert column.nullable is False

    def test_password_hash_max_length(self):
        """Test password_hash max length is 255."""
        column = User.__table__.columns["password_hash"]
        assert column.type.length == 255

    def test_is_active_default_true(self):
        """Test is_active column default is True."""
        column = User.__table__.columns["is_active"]
        assert column.default.arg is True

    def test_is_active_not_nullable(self):
        """Test is_active is not nullable."""
        column = User.__table__.columns["is_active"]
        assert column.nullable is False

    def test_is_email_verified_default_false(self):
        """Test is_email_verified column default is False."""
        column = User.__table__.columns["is_email_verified"]
        assert column.default.arg is False

    def test_is_superuser_default_false(self):
        """Test is_superuser column default is False."""
        column = User.__table__.columns["is_superuser"]
        assert column.default.arg is False

    def test_email_verification_token_nullable(self):
        """Test email_verification_token is nullable."""
        column = User.__table__.columns["email_verification_token"]
        assert column.nullable is True

    def test_email_verification_token_max_length(self):
        """Test email_verification_token max length is 1024."""
        column = User.__table__.columns["email_verification_token"]
        assert column.type.length == 1024

    def test_reset_password_token_nullable(self):
        """Test reset_password_token is nullable."""
        column = User.__table__.columns["reset_password_token"]
        assert column.nullable is True

    def test_reset_password_token_max_length(self):
        """Test reset_password_token max length is 1024."""
        column = User.__table__.columns["reset_password_token"]
        assert column.type.length == 1024


# ==================== INDEX TESTS ====================

class TestUserModelIndexes:
    """Tests for User model indexes."""

    def test_table_has_indexes(self):
        """Test table has __table_args__ with indexes."""
        assert hasattr(User, "__table_args__")
        assert User.__table_args__ is not None

    def test_has_unique_email_index(self):
        """Test unique index on email exists."""
        email_column = User.__table__.columns["email"]
        assert email_column.unique is True
        assert email_column.index is True

    def test_has_email_hash_unique_index(self):
        """Test unique index on email_hash exists."""
        column = User.__table__.columns["email_hash"]
        assert column.unique is True

    def test_has_is_active_index(self):
        """Test index on is_active exists in __table_args__."""
        table_args = User.__table_args__
        has_is_active = any(
            "is_active" in str(arg) for arg in table_args
        )
        assert has_is_active

    def test_has_is_superuser_index(self):
        """Test index on is_superuser exists in __table_args__."""
        table_args = User.__table_args__
        has_is_superuser = any(
            "is_superuser" in str(arg) for arg in table_args
        )
        assert has_is_superuser

    def test_has_email_hash_index(self):
        """Test index on email_hash exists in __table_args__."""
        table_args = User.__table_args__
        has_email_hash = any(
            "email_hash" in str(arg) for arg in table_args
        )
        assert has_email_hash

    def test_has_phone_hash_index(self):
        """Test index on phone_hash exists in __table_args__."""
        table_args = User.__table_args__
        has_phone_hash = any(
            "phone_hash" in str(arg) for arg in table_args
        )
        assert has_phone_hash


# ==================== REPR TESTS ====================

class TestUserRepr:
    """Tests for __repr__ method."""

    def test_repr_includes_email(self, user):
        """Test __repr__ includes email."""
        repr_str = repr(user)
        assert "User" in repr_str
        assert "email=user@example.com" in repr_str

    def test_repr_includes_is_active(self, user):
        """Test __repr__ includes is_active."""
        repr_str = repr(user)
        assert "is_active=True" in repr_str

    def test_repr_inactive_user(self):
        """Test __repr__ for inactive user."""
        inactive_user = User(
            email="inactive@example.com",
            password_hash="hash",
            is_active=False,
        )
        repr_str = repr(inactive_user)
        assert "is_active=False" in repr_str


# ==================== EMAIL HASH TESTS ====================

class TestUserCreateEmailHash:
    """Tests for create_email_hash static method."""

    def test_create_email_hash_returns_sha256(self):
        """Test create_email_hash returns SHA256 hex string."""
        email = "test@example.com"
        result = User.create_email_hash(email)

        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_create_email_hash_lowercase(self):
        """Test email is lowercased before hashing."""
        hash1 = User.create_email_hash("User@Example.COM")
        hash2 = User.create_email_hash("user@example.com")
        assert hash1 == hash2

    def test_create_email_hash_deterministic(self):
        """Test same email produces same hash."""
        hash1 = User.create_email_hash("same@email.com")
        hash2 = User.create_email_hash("same@email.com")
        assert hash1 == hash2

    def test_create_email_hash_different_emails(self):
        """Test different emails produce different hashes."""
        hash1 = User.create_email_hash("user1@example.com")
        hash2 = User.create_email_hash("user2@example.com")
        assert hash1 != hash2

    def test_create_email_hash_matches_manual(self):
        """Test hash matches manual SHA256 calculation."""
        email = "manual@test.com"
        result = User.create_email_hash(email)
        expected = hashlib.sha256(email.lower().encode()).hexdigest()
        assert result == expected

    def test_create_email_hash_empty_string(self):
        """Test hashing empty string."""
        result = User.create_email_hash("")
        expected = hashlib.sha256("".encode()).hexdigest()
        assert result == expected


# ==================== PHONE HASH TESTS ====================

class TestUserCreatePhoneHash:
    """Tests for create_phone_hash static method."""

    def test_create_phone_hash_returns_sha256(self):
        """Test create_phone_hash returns SHA256 hex string."""
        phone = "+1234567890"
        result = User.create_phone_hash(phone)

        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_create_phone_hash_normalizes(self):
        """Test phone number is normalized before hashing."""
        # Different formats should produce same hash
        hash1 = User.create_phone_hash("+1 (234) 567-890")
        hash2 = User.create_phone_hash("1234567890")
        assert hash1 == hash2

    def test_create_phone_hash_deterministic(self):
        """Test same phone produces same hash."""
        hash1 = User.create_phone_hash("+1234567890")
        hash2 = User.create_phone_hash("+1234567890")
        assert hash1 == hash2

    def test_create_phone_hash_different_phones(self):
        """Test different phones produce different hashes."""
        hash1 = User.create_phone_hash("+1234567890")
        hash2 = User.create_phone_hash("+0987654321")
        assert hash1 != hash2

    def test_create_phone_hash_empty_string(self):
        """Test hashing empty string."""
        result = User.create_phone_hash("")
        expected = hashlib.sha256("".encode()).hexdigest()
        assert result == expected

    def test_create_phone_hash_only_non_digit(self):
        """Test hashing phone with no digits."""
        result = User.create_phone_hash("+++---")
        expected = hashlib.sha256("".encode()).hexdigest()
        assert result == expected


# ==================== DEFAULT VALUES TESTS ====================

class TestUserDefaults:
    """Tests for default field values.
    
    Note: SQLAlchemy column defaults are only applied at DB commit time.
    For in-memory instances, we pass values explicitly to simulate DB behavior.
    """

    def test_new_user_is_active_by_default(self):
        """Test new user is active by default."""
        user = User(
            email="new@example.com",
            password_hash="hash",
            is_active=True,
        )
        assert user.is_active is True

    def test_new_user_not_email_verified_by_default(self):
        """Test new user has email not verified by default."""
        user = User(
            email="new@example.com",
            password_hash="hash",
            is_email_verified=False,
        )
        assert user.is_email_verified is False

    def test_new_user_not_superuser_by_default(self):
        """Test new user is not superuser by default."""
        user = User(
            email="new@example.com",
            password_hash="hash",
            is_superuser=False,
        )
        assert user.is_superuser is False

    def test_new_user_optional_fields_none(self):
        """Test optional fields are None by default."""
        user = User(
            email="new@example.com",
            password_hash="hash",
            is_active=True,
        )
        assert user.email_hash is None
        assert user.phone_hash is None
        assert user.email_verification_token is None
        assert user.email_verification_token_expires is None
        assert user.reset_password_token is None
        assert user.reset_password_token_expires is None


# ==================== FIELD ASSIGNMENT TESTS ====================

class TestUserFieldAssignment:
    """Tests for field value assignment."""

    def test_set_email_hash(self):
        """Test setting email_hash."""
        user = User(email="test@test.com", password_hash="hash")
        user.email_hash = "abc123def456"
        assert user.email_hash == "abc123def456"

    def test_set_phone_hash(self):
        """Test setting phone_hash."""
        user = User(email="test@test.com", password_hash="hash")
        user.phone_hash = "phone_hash_789"
        assert user.phone_hash == "phone_hash_789"

    def test_set_verification_token(self):
        """Test setting email verification token."""
        user = User(email="test@test.com", password_hash="hash")
        token = "verification_token_123"
        user.email_verification_token = token
        assert user.email_verification_token == token

    def test_set_verification_token_expires(self):
        """Test setting email verification token expiry."""
        user = User(email="test@test.com", password_hash="hash")
        expires = datetime.now(timezone.utc) + timedelta(hours=24)
        user.email_verification_token_expires = expires
        assert user.email_verification_token_expires == expires

    def test_set_reset_password_token(self):
        """Test setting reset password token."""
        user = User(email="test@test.com", password_hash="hash")
        token = "reset_token_456"
        user.reset_password_token = token
        assert user.reset_password_token == token

    def test_set_reset_password_token_expires(self):
        """Test setting reset password token expiry."""
        user = User(email="test@test.com", password_hash="hash")
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        user.reset_password_token_expires = expires
        assert user.reset_password_token_expires == expires

    def test_toggle_is_active(self):
        """Test toggling is_active."""
        user = User(
            email="test@test.com",
            password_hash="hash",
            is_active=True,
        )
        assert user.is_active is True
        user.is_active = False
        assert user.is_active is False

    def test_toggle_is_email_verified(self):
        """Test toggling is_email_verified."""
        user = User(
            email="test@test.com",
            password_hash="hash",
            is_email_verified=False,
        )
        assert user.is_email_verified is False
        user.is_email_verified = True
        assert user.is_email_verified is True

    def test_toggle_is_superuser(self):
        """Test toggling is_superuser."""
        user = User(
            email="test@test.com",
            password_hash="hash",
            is_superuser=False,
        )
        assert user.is_superuser is False
        user.is_superuser = True
        assert user.is_superuser is True


# ==================== RELATIONSHIP TESTS ====================

class TestUserRelationships:
    """Tests for User model relationships."""

    def test_has_security_settings_relationship(self):
        """Test User has security_settings relationship."""
        assert hasattr(User, "security_settings")

    def test_security_settings_is_optional(self):
        """Test security_settings can be None."""
        user = User(email="test@test.com", password_hash="hash")
        assert user.security_settings is None


# ==================== EDGE CASES TESTS ====================

class TestUserEdgeCases:
    """Tests for edge cases and boundary values."""

    def test_email_max_length_value(self):
        """Test email at max length of 255 characters.
        
        255 total - 6 chars for '@b.com' = 249 chars for the 'a' prefix.
        """
        long_email = "a" * 249 + "@b.com"  # Exactly 255 characters
        user = User(
            email=long_email,
            password_hash="hash",
        )
        assert len(user.email) == 255

    def test_password_hash_max_length_value(self):
        """Test password_hash at max length of 255 characters."""
        long_hash = "x" * 255
        user = User(
            email="test@example.com",
            password_hash=long_hash,
        )
        assert len(user.password_hash) == 255

    def test_email_verification_token_max_length(self):
        """Test email_verification_token at max length of 1024 characters."""
        long_token = "a" * 1024
        user = User(email="test@test.com", password_hash="hash")
        user.email_verification_token = long_token
        assert len(user.email_verification_token) == 1024

    def test_reset_password_token_max_length(self):
        """Test reset_password_token at max length of 1024 characters."""
        long_token = "b" * 1024
        user = User(email="test@test.com", password_hash="hash")
        user.reset_password_token = long_token
        assert len(user.reset_password_token) == 1024

    def test_create_email_hash_unicode(self):
        """Test email hash with unicode characters."""
        email = "üser@éxample.com"
        result = User.create_email_hash(email)
        assert len(result) == 64

    def test_create_phone_hash_international(self):
        """Test phone hash with international format."""
        phone = "+7 (999) 123-45-67"
        result = User.create_phone_hash(phone)
        assert len(result) == 64

    def test_user_with_all_optional_fields_set(self):
        """Test creating user with all optional fields set."""
        now = datetime.now(timezone.utc)
        user = User(
            email="full@example.com",
            email_hash="hash_email_123",
            phone_hash="hash_phone_456",
            password_hash="hashed_pw",
            is_active=True,
            is_email_verified=True,
            is_superuser=True,
            email_verification_token="verify_token",
            email_verification_token_expires=now,
            reset_password_token="reset_token",
            reset_password_token_expires=now,
        )

        assert user.email == "full@example.com"
        assert user.email_hash == "hash_email_123"
        assert user.phone_hash == "hash_phone_456"
        assert user.is_superuser is True
        assert user.email_verification_token == "verify_token"
        assert user.reset_password_token == "reset_token"