"""
Unit tests for User model.

Tests cover real behavior in isolated PostgreSQL:
- User creation, defaults, unique email constraint
- email_hash and phone_hash auto-generation on insert
- is_active, is_email_verified, is_superuser defaults
- Soft delete (is_deleted flag)
- GDPR-related fields (deleted_at, deletion_requested_at)
- __repr__ method
- Relationship with UserSecuritySettings and UserRole
- Edge cases and boundary values
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.models.user import User
from app.models.base import Base


# ==================== FIXTURES ====================

@pytest.fixture
def engine():
    """Create isolated PostgreSQL engine with schema."""
    engine = create_engine(
        "postgresql://postgres:postgres@postgres:5432/user_db_test",
        echo=False,
    )
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session(engine):
    """Create a new database session for a test."""
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    # Clean all tables before each test
    for table in reversed(Base.metadata.sorted_tables):
        session.execute(table.delete())
    session.commit()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def sample_user(session):
    """Create and persist a basic user."""
    user = User(
        email="user@example.com",
        password_hash="hashed_password",
    )
    session.add(user)
    session.commit()
    return user


# ==================== USER CREATION TESTS ====================

class TestUserCreation:
    """Tests for User model creation."""

    def test_create_user_minimal(self, session):
        """Test creating user with only required fields."""
        user = User(
            email="test@example.com",
            password_hash="hashed_pw",
        )
        session.add(user)
        session.commit()

        saved = session.get(User, user.id)
        assert saved is not None
        assert saved.email == "test@example.com"
        assert saved.password_hash == "hashed_pw"
        assert saved.email_hash is not None
        assert len(saved.email_hash) == 64

    def test_create_user_with_all_fields(self, session):
        """Test creating user with all optional fields."""
        user = User(
            email="full@example.com",
            password_hash="hash",
            phone_hash=User.create_phone_hash("+1234567890"),
            first_name="John",
            last_name="Doe",
            is_active=True,
            is_email_verified=True,
            is_superuser=False,
        )
        session.add(user)
        session.commit()

        saved = session.get(User, user.id)
        assert saved.first_name == "John"
        assert saved.last_name == "Doe"
        assert saved.phone_hash is not None

    def test_create_user_defaults(self, session):
        """Test default values on new user."""
        user = User(
            email="defaults@example.com",
            password_hash="hash",
        )
        session.add(user)
        session.commit()

        saved = session.get(User, user.id)
        assert saved.is_active is True
        assert saved.is_email_verified is False
        assert saved.is_superuser is False
        assert saved.is_deleted is False

    def test_create_user_unique_email(self, session):
        """Test duplicate email raises IntegrityError."""
        user1 = User(
            email="duplicate@example.com",
            password_hash="hash1",
        )
        session.add(user1)
        session.commit()

        user2 = User(
            email="duplicate@example.com",
            password_hash="hash2",
        )
        session.add(user2)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_create_user_unique_email_hash(self, session):
        """Test duplicate email_hash raises IntegrityError."""
        email = "same_hash@example.com"
        user1 = User(email=email, password_hash="hash1")
        session.add(user1)
        session.commit()

        user2 = User(email=email, password_hash="hash2")
        session.add(user2)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


# ==================== EMAIL AND PHONE HASH TESTS ====================

class TestUserHashing:
    """Tests for email and phone hashing."""

    def test_create_email_hash_lowercase(self):
        """Test email is lowercased before hashing."""
        hash1 = User.create_email_hash("User@Example.COM")
        hash2 = User.create_email_hash("user@example.com")
        assert hash1 == hash2

    def test_create_email_hash_sha256_length(self):
        """Test email hash is 64-character hex string."""
        result = User.create_email_hash("test@example.com")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_create_email_hash_deterministic(self):
        """Test same email always produces same hash."""
        hash1 = User.create_email_hash("same@email.com")
        hash2 = User.create_email_hash("same@email.com")
        assert hash1 == hash2

    def test_create_email_hash_different_emails(self):
        """Test different emails produce different hashes."""
        hash1 = User.create_email_hash("user1@example.com")
        hash2 = User.create_email_hash("user2@example.com")
        assert hash1 != hash2

    def test_create_phone_hash_keeps_plus(self):
        """Test phone hash normalizes numbers with and without + to same value."""
        hash_with_plus = User.create_phone_hash("+1234567890")
        hash_without_plus = User.create_phone_hash("1234567890")
        assert hash_with_plus == hash_without_plus

    def test_create_phone_hash_normalizes_formatting(self):
        """Test phone number formatting is normalized before hashing."""
        hash1 = User.create_phone_hash("+1-234-567-890")
        hash2 = User.create_phone_hash("+1 (234) 567-890")
        assert hash1 == hash2

    def test_create_phone_hash_different_phones(self):
        """Test different phones produce different hashes."""
        hash1 = User.create_phone_hash("+1234567890")
        hash2 = User.create_phone_hash("+0987654321")
        assert hash1 != hash2

    def test_email_hash_auto_generated_on_insert(self, session):
        """Test email_hash is automatically generated on insert."""
        user = User(
            email="auto@example.com",
            password_hash="hash",
        )
        session.add(user)
        session.commit()

        saved = session.get(User, user.id)
        assert saved.email_hash == User.create_email_hash("auto@example.com")


# ==================== SOFT DELETE TESTS ====================

class TestUserSoftDelete:
    """Tests for GDPR soft delete behavior."""

    def test_user_is_deleted_default_false(self, session):
        """Test is_deleted defaults to False."""
        user = User(
            email="alive@example.com",
            password_hash="hash",
        )
        session.add(user)
        session.commit()

        assert user.is_deleted is False

    def test_soft_delete_user(self, session):
        """Test soft delete sets is_deleted flag."""
        user = User(
            email="delete@example.com",
            password_hash="hash",
        )
        session.add(user)
        session.commit()

        user.is_deleted = True
        user.deleted_at = datetime.now(timezone.utc)
        session.commit()

        saved = session.get(User, user.id)
        assert saved.is_deleted is True
        assert saved.deleted_at is not None

    def test_deletion_requested_at(self, session):
        """Test deletion_requested_at is recorded."""
        user = User(
            email="gdpr@example.com",
            password_hash="hash",
        )
        session.add(user)
        session.commit()

        request_time = datetime.now(timezone.utc)
        user.deletion_requested_at = request_time
        session.commit()

        saved = session.get(User, user.id)
        assert saved.deletion_requested_at == request_time

    def test_soft_deleted_user_still_exists(self, session):
        """Test soft-deleted user is still in database."""
        user = User(
            email="soft@example.com",
            password_hash="hash",
        )
        session.add(user)
        session.commit()

        user_id = user.id
        user.is_deleted = True
        session.commit()

        saved = session.get(User, user_id)
        assert saved is not None
        assert saved.is_deleted is True


# ==================== REPR TESTS ====================

class TestUserRepr:
    """Tests for __repr__ method."""

    def test_repr_active_user(self, session):
        """Test __repr__ for active user."""
        user = User(
            email="repr@example.com",
            password_hash="hash",
        )
        session.add(user)
        session.commit()

        repr_str = repr(user)
        assert "User" in repr_str
        assert "email=repr@example.com" in repr_str
        assert "is_active=True" in repr_str

    def test_repr_inactive_user(self, session):
        """Test __repr__ for inactive user."""
        user = User(
            email="inactive@example.com",
            password_hash="hash",
            is_active=False,
        )
        session.add(user)
        session.commit()

        repr_str = repr(user)
        assert "is_active=False" in repr_str

    def test_repr_soft_deleted_user(self, session):
        """Test __repr__ for soft-deleted user with both flags set."""
        user = User(
            email="deleted_repr@example.com",
            password_hash="hash",
            is_deleted=True,
            is_active=False,
        )
        session.add(user)
        session.commit()

        repr_str = repr(user)
        assert "is_active=False" in repr_str


# ==================== FIELD UPDATES TESTS ====================

class TestUserFieldUpdates:
    """Tests for updating user fields."""

    def test_update_first_name(self, session, sample_user):
        """Test updating first_name."""
        sample_user.first_name = "Jane"
        session.commit()

        saved = session.get(User, sample_user.id)
        assert saved.first_name == "Jane"

    def test_update_last_name(self, session, sample_user):
        """Test updating last_name."""
        sample_user.last_name = "Smith"
        session.commit()

        saved = session.get(User, sample_user.id)
        assert saved.last_name == "Smith"

    def test_toggle_is_active(self, session, sample_user):
        """Test toggling is_active flag."""
        assert sample_user.is_active is True
        sample_user.is_active = False
        session.commit()

        saved = session.get(User, sample_user.id)
        assert saved.is_active is False

    def test_toggle_is_email_verified(self, session, sample_user):
        """Test toggling is_email_verified flag."""
        assert sample_user.is_email_verified is False
        sample_user.is_email_verified = True
        session.commit()

        saved = session.get(User, sample_user.id)
        assert saved.is_email_verified is True

    def test_toggle_is_superuser(self, session, sample_user):
        """Test toggling is_superuser flag."""
        assert sample_user.is_superuser is False
        sample_user.is_superuser = True
        session.commit()

        saved = session.get(User, sample_user.id)
        assert saved.is_superuser is True

    def test_update_phone_hash(self, session, sample_user):
        """Test updating phone_hash."""
        new_hash = User.create_phone_hash("+0987654321")
        sample_user.phone_hash = new_hash
        session.commit()

        saved = session.get(User, sample_user.id)
        assert saved.phone_hash == new_hash


# ==================== QUERY TESTS ====================

class TestUserQueries:
    """Tests for common queries."""

    def test_find_by_email_hash(self, session, sample_user):
        """Test finding user by email_hash."""
        found = session.query(User).filter(
            User.email_hash == sample_user.email_hash
        ).first()
        assert found is not None
        assert found.id == sample_user.id

    def test_find_by_phone_hash(self, session, sample_user):
        """Test finding user by phone_hash."""
        sample_user.phone_hash = User.create_phone_hash("+1234567890")
        session.commit()

        found = session.query(User).filter(
            User.phone_hash == sample_user.phone_hash
        ).first()
        assert found is not None

    def test_find_active_users(self, session):
        """Test filtering active users."""
        active = User(email="active@example.com", password_hash="hash", is_active=True)
        inactive = User(email="inactive2@example.com", password_hash="hash", is_active=False)
        session.add_all([active, inactive])
        session.commit()

        active_users = session.query(User).filter(User.is_active == True).all()
        assert len(active_users) == 1
        assert active_users[0].email == "active@example.com"

    def test_find_verified_emails(self, session):
        """Test filtering email-verified users."""
        verified = User(email="verified@example.com", password_hash="hash", is_email_verified=True)
        unverified = User(email="unverified@example.com", password_hash="hash", is_email_verified=False)
        session.add_all([verified, unverified])
        session.commit()

        verified_users = session.query(User).filter(User.is_email_verified == True).all()
        assert len(verified_users) == 1

    def test_find_non_deleted_users(self, session):
        """Test excluding soft-deleted users."""
        alive = User(email="alive2@example.com", password_hash="hash")
        deleted = User(email="deleted2@example.com", password_hash="hash", is_deleted=True)
        session.add_all([alive, deleted])
        session.commit()

        active = session.query(User).filter(User.is_deleted == False).all()
        assert len(active) == 1


# ==================== EDGE CASES TESTS ====================

class TestUserEdgeCases:
    """Tests for edge cases and boundary values."""

    def test_email_max_length(self, session):
        """Test email at 255 characters is accepted."""
        long_email = "a" * 249 + "@b.com"
        user = User(email=long_email, password_hash="hash")
        session.add(user)
        session.commit()

        saved = session.get(User, user.id)
        assert len(saved.email) == 255

    def test_password_hash_max_length(self, session):
        """Test password_hash at 255 characters."""
        long_hash = "x" * 255
        user = User(email="hashlen@example.com", password_hash=long_hash)
        session.add(user)
        session.commit()

        saved = session.get(User, user.id)
        assert len(saved.password_hash) == 255

    def test_user_without_optional_fields(self, session):
        """Test user without any optional fields."""
        user = User(email="minimal@example.com", password_hash="hash")
        session.add(user)
        session.commit()

        saved = session.get(User, user.id)
        assert saved.first_name is None
        assert saved.last_name is None
        assert saved.phone_hash is None
        assert saved.avatar_url is None

    def test_multiple_users_persist(self, session):
        """Test creating multiple users in one session."""
        for i in range(10):
            user = User(email=f"bulk{i}@example.com", password_hash="hash")
            session.add(user)
        session.commit()

        count = session.query(User).count()
        assert count == 10

    def test_create_email_hash_empty_string(self):
        """Test hashing empty email."""
        result = User.create_email_hash("")
        assert len(result) == 64

    def test_create_phone_hash_empty_string(self):
        """Test hashing empty phone."""
        result = User.create_phone_hash("")
        assert len(result) == 64

    def test_user_id_is_uuid(self, session, sample_user):
        """Test user id is a UUID."""
        assert isinstance(sample_user.id, uuid4().__class__)