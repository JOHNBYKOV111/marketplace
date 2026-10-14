"""
Unit tests for UserSecuritySettings model.

Tests cover real behavior against PostgreSQL via SQLAlchemy:
- Creation with defaults (totp_enabled=False, empty backup_codes)
- enable_totp / disable_totp methods
- check_totp_enabled logic
- Backup codes management (JSONB column)
- last_password_change tracking
- Relationship with User (foreign key, cascade delete)
- Unique constraint on user_id
- Edge cases and boundary values
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.models.user import User
from app.models.user_security_settings import UserSecuritySettings
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
    """Create a user for security settings tests."""
    user = User(
        email="secure@example.com",
        password_hash="hash",
    )
    session.add(user)
    session.commit()
    return user


@pytest.fixture
def sample_settings(session, sample_user):
    """Create security settings for a user."""
    settings = UserSecuritySettings(user_id=sample_user.id)
    session.add(settings)
    session.commit()
    return settings


# ==================== CREATION TESTS ====================

class TestUserSecuritySettingsCreation:
    """Tests for UserSecuritySettings creation and defaults."""

    def test_create_settings(self, session, sample_user):
        """Test creating security settings for a user."""
        settings = UserSecuritySettings(user_id=sample_user.id)
        session.add(settings)
        session.commit()

        saved = session.get(UserSecuritySettings, settings.id)
        assert saved is not None
        assert saved.user_id == sample_user.id
        assert saved.totp_enabled is False
        assert saved.totp_secret is None
        assert saved.totp_backup_codes == []
        assert saved.last_password_change is None

    def test_create_settings_unique_per_user(self, session, sample_user):
        """Test only one settings record per user."""
        settings1 = UserSecuritySettings(user_id=sample_user.id)
        session.add(settings1)
        session.commit()

        settings2 = UserSecuritySettings(user_id=sample_user.id)
        session.add(settings2)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_create_settings_user_id_required(self, session):
        """Test user_id is required."""
        settings = UserSecuritySettings()
        session.add(settings)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_settings_linked_to_correct_user(self, session, sample_user, sample_settings):
        """Test settings reference the correct user."""
        assert sample_settings.user_id == sample_user.id
        found = session.query(UserSecuritySettings).filter(
            UserSecuritySettings.user_id == sample_user.id
        ).first()
        assert found is not None
        assert found.id == sample_settings.id


# ==================== TOTP TESTS ====================

class TestUserSecuritySettingsTOTP:
    """Tests for TOTP management."""

    def test_enable_totp(self, session, sample_settings):
        """Test enabling TOTP sets secret and flag."""
        secret = "JBSWY3DPEHPK3PXP"
        sample_settings.enable_totp(secret)
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_enabled is True
        assert saved.totp_secret == secret

    def test_enable_totp_preserves_backup_codes(self, session, sample_settings):
        """Test enabling TOTP does not clear existing backup codes."""
        sample_settings.totp_backup_codes = ["code1", "code2"]
        session.commit()

        sample_settings.enable_totp("secret")
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_backup_codes == ["code1", "code2"]

    def test_disable_totp_clears_all(self, session, sample_settings):
        """Test disabling TOTP clears secret and backup codes."""
        sample_settings.enable_totp("secret")
        sample_settings.totp_backup_codes = ["code1"]
        session.commit()

        sample_settings.disable_totp()
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_enabled is False
        assert saved.totp_secret is None
        assert saved.totp_backup_codes == []

    def test_disable_totp_when_already_disabled(self, session, sample_settings):
        """Test disable_totp is safe when already disabled."""
        sample_settings.disable_totp()
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_enabled is False

    def test_check_totp_enabled_true(self, session, sample_settings):
        """Test check_totp_enabled returns True when active."""
        sample_settings.enable_totp("secret")
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.check_totp_enabled() is True

    def test_check_totp_enabled_false_when_disabled(self, session, sample_settings):
        """Test check_totp_enabled returns False when totp_enabled is False."""
        sample_settings.totp_enabled = False
        sample_settings.totp_secret = "secret"
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.check_totp_enabled() is False

    def test_check_totp_enabled_false_when_no_secret(self, session, sample_settings):
        """Test check_totp_enabled returns False when secret is None."""
        sample_settings.totp_enabled = True
        sample_settings.totp_secret = None
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.check_totp_enabled() is False

    def test_enable_disable_enable_cycle(self, session, sample_settings):
        """Test full TOTP lifecycle."""
        sample_settings.enable_totp("first_secret")
        session.commit()
        assert sample_settings.check_totp_enabled() is True

        sample_settings.disable_totp()
        session.commit()
        assert sample_settings.check_totp_enabled() is False

        sample_settings.enable_totp("second_secret")
        session.commit()
        assert sample_settings.check_totp_enabled() is True
        assert sample_settings.totp_secret == "second_secret"


# ==================== BACKUP CODES TESTS ====================

class TestUserSecuritySettingsBackupCodes:
    """Tests for backup codes management with JSONB."""

    def test_set_backup_codes(self, session, sample_settings):
        """Test setting backup codes."""
        codes = ["backup1", "backup2", "backup3"]
        sample_settings.totp_backup_codes = codes
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_backup_codes == codes

    def test_clear_backup_codes(self, session, sample_settings):
        """Test clearing backup codes."""
        sample_settings.totp_backup_codes = ["code1", "code2"]
        session.commit()

        sample_settings.totp_backup_codes = []
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_backup_codes == []

    def test_backup_codes_default_empty_list(self, session, sample_settings):
        """Test backup codes default to empty list."""
        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_backup_codes == []

    def test_empty_backup_codes_after_disable_totp(self, session, sample_settings):
        """Test disable_totp empties backup codes."""
        sample_settings.enable_totp("secret")
        sample_settings.totp_backup_codes = ["code1", "code2"]
        session.commit()

        sample_settings.disable_totp()
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_backup_codes == []

    def test_replace_backup_codes_fully(self, session, sample_settings):
        """Test full replacement of backup codes."""
        sample_settings.totp_backup_codes = ["old1", "old2", "old3"]
        session.commit()

        sample_settings.totp_backup_codes = ["new1", "new2"]
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_backup_codes == ["new1", "new2"]


# ==================== PASSWORD CHANGE TESTS ====================

class TestUserSecuritySettingsPasswordChange:
    """Tests for last_password_change tracking."""

    def test_set_last_password_change(self, session, sample_settings):
        """Test recording password change timestamp."""
        now = datetime.now(timezone.utc)
        sample_settings.last_password_change = now
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.last_password_change == now

    def test_last_password_change_nullable(self, session, sample_settings):
        """Test last_password_change can be None."""
        assert sample_settings.last_password_change is None

    def test_update_last_password_change(self, session, sample_settings):
        """Test updating password change timestamp."""
        first_change = datetime(2024, 1, 1, tzinfo=timezone.utc)
        second_change = datetime(2024, 6, 1, tzinfo=timezone.utc)

        sample_settings.last_password_change = first_change
        session.commit()

        sample_settings.last_password_change = second_change
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.last_password_change == second_change


# ==================== RELATIONSHIP TESTS ====================

class TestUserSecuritySettingsRelationship:
    """Tests for relationship with User model."""

    def test_settings_belongs_to_user(self, session, sample_user, sample_settings):
        """Test settings are linked to the user."""
        assert sample_settings.user_id == sample_user.id

    def test_cascade_delete_with_user(self, session, sample_user, sample_settings):
        """Test deleting user removes their security settings."""
        settings_id = sample_settings.id

        session.delete(sample_user)
        session.commit()

        deleted = session.get(UserSecuritySettings, settings_id)
        assert deleted is None


# ==================== REPR TESTS ====================

class TestUserSecuritySettingsRepr:
    """Tests for __repr__ method."""

    def test_repr_includes_user_id(self, session, sample_settings):
        """Test __repr__ includes user_id."""
        repr_str = repr(sample_settings)
        assert str(sample_settings.user_id) in repr_str

    def test_repr_includes_totp_enabled(self, session, sample_settings):
        """Test __repr__ includes totp_enabled."""
        repr_str = repr(sample_settings)
        assert "totp_enabled=False" in repr_str

    def test_repr_when_totp_enabled(self, session, sample_settings):
        """Test __repr__ when TOTP is enabled."""
        sample_settings.enable_totp("secret")
        session.commit()

        repr_str = repr(sample_settings)
        assert "totp_enabled=True" in repr_str

    def test_repr_does_not_expose_secret(self, session, sample_settings):
        """Test __repr__ does not expose TOTP secret."""
        sample_settings.enable_totp("super_secret_key")
        session.commit()

        repr_str = repr(sample_settings)
        assert "super_secret_key" not in repr_str

    def test_repr_does_not_expose_backup_codes(self, session, sample_settings):
        """Test __repr__ does not expose backup codes."""
        sample_settings.totp_backup_codes = ["12345678", "87654321"]
        session.commit()

        repr_str = repr(sample_settings)
        assert "12345678" not in repr_str
        assert "87654321" not in repr_str


# ==================== EDGE CASES TESTS ====================

class TestUserSecuritySettingsEdgeCases:
    """Tests for edge cases and boundary values."""

    def test_enable_totp_with_empty_secret(self, session, sample_settings):
        """Test enabling TOTP with empty secret string."""
        sample_settings.enable_totp("")
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_enabled is True
        assert saved.totp_secret == ""

    def test_enable_totp_with_long_secret(self, session, sample_settings):
        """Test enabling TOTP with max length secret."""
        long_secret = "A" * 255
        sample_settings.enable_totp(long_secret)
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert len(saved.totp_secret) == 255

    def test_disable_totp_twice(self, session, sample_settings):
        """Test calling disable_totp twice is safe."""
        sample_settings.enable_totp("secret")
        session.commit()

        sample_settings.disable_totp()
        session.commit()

        sample_settings.disable_totp()
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_enabled is False

    def test_backup_codes_with_unicode(self, session, sample_settings):
        """Test backup codes with unicode characters."""
        codes = ["код1", "код2", "backup3"]
        sample_settings.totp_backup_codes = codes
        session.commit()

        saved = session.get(UserSecuritySettings, sample_settings.id)
        assert saved.totp_backup_codes == codes

    def test_multiple_settings_for_different_users(self, session):
        """Test creating settings for different users."""
        user1 = User(email="user1@example.com", password_hash="hash")
        user2 = User(email="user2@example.com", password_hash="hash")
        session.add_all([user1, user2])
        session.commit()

        settings1 = UserSecuritySettings(user_id=user1.id)
        settings2 = UserSecuritySettings(user_id=user2.id)
        session.add_all([settings1, settings2])
        session.commit()

        assert settings1.user_id != settings2.user_id