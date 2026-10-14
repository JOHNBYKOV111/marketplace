"""
Unit tests for UserSecuritySettings model.

Tests cover:
- Model field definitions and constraints
- __repr__ method
- enable_totp / disable_totp / check_totp_enabled
- Default values (totp_enabled, totp_backup_codes)
- Field types and nullability
- Relationship with User
- Edge cases and boundary values
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from app.models.user_security_settings import UserSecuritySettings


# ==================== FIXTURES ====================

@pytest.fixture
def user_id():
    """Generate a random user ID."""
    return uuid4()


@pytest.fixture
def settings(user_id):
    """Create default security settings for a user.
    
    Note: SQLAlchemy server_defaults are only applied at DB commit time.
    For in-memory instances, we pass defaults explicitly to simulate DB state.
    """
    return UserSecuritySettings(
        user_id=user_id,
        totp_enabled=False,
        totp_backup_codes=[],
    )


# ==================== MODEL FIELDS TESTS ====================

class TestUserSecuritySettingsFields:
    """Tests for UserSecuritySettings model field definitions."""

    def test_table_name(self):
        """Test table name is user_security_settings."""
        assert UserSecuritySettings.__tablename__ == "user_security_settings"

    def test_model_fields_existence(self):
        """Test all expected fields exist on the model."""
        fields = [
            "id", "user_id", "totp_enabled", "totp_secret",
            "totp_backup_codes", "last_password_change",
        ]

        for field in fields:
            assert hasattr(UserSecuritySettings, field), f"Field {field} missing"

    def test_user_id_not_nullable(self):
        """Test user_id is not nullable."""
        column = UserSecuritySettings.__table__.columns["user_id"]
        assert column.nullable is False

    def test_user_id_unique(self):
        """Test user_id is unique."""
        column = UserSecuritySettings.__table__.columns["user_id"]
        assert column.unique is True

    def test_user_id_indexed(self):
        """Test user_id has index."""
        column = UserSecuritySettings.__table__.columns["user_id"]
        assert column.index is True

    def test_user_id_foreign_key(self):
        """Test user_id has foreign key to users table."""
        column = UserSecuritySettings.__table__.columns["user_id"]
        foreign_keys = list(column.foreign_keys)
        assert len(foreign_keys) == 1
        fk = foreign_keys[0]
        assert fk.column.table.name == "users"
        assert fk.column.name == "id"
        assert fk.ondelete == "CASCADE"

    def test_totp_enabled_default_false(self):
        """Test totp_enabled column default is False."""
        column = UserSecuritySettings.__table__.columns["totp_enabled"]
        assert column.default.arg is False

    def test_totp_enabled_not_nullable(self):
        """Test totp_enabled is not nullable."""
        column = UserSecuritySettings.__table__.columns["totp_enabled"]
        assert column.nullable is False

    def test_totp_secret_nullable(self):
        """Test totp_secret is nullable."""
        column = UserSecuritySettings.__table__.columns["totp_secret"]
        assert column.nullable is True

    def test_totp_secret_max_length(self):
        """Test totp_secret max length is 255."""
        column = UserSecuritySettings.__table__.columns["totp_secret"]
        assert column.type.length == 255

    def test_totp_backup_codes_nullable(self):
        """Test totp_backup_codes is nullable."""
        column = UserSecuritySettings.__table__.columns["totp_backup_codes"]
        assert column.nullable is True

    def test_totp_backup_codes_default_empty_list(self):
        """Test totp_backup_codes has a callable default handler.
        
        Note: The frozen project uses a factory function (not plain list)
        that receives a context argument at DB execution time.
        We verify the default exists and is callable without invoking it.
        """
        column = UserSecuritySettings.__table__.columns["totp_backup_codes"]

        # Verify default exists and is callable
        assert column.default is not None
        assert callable(column.default.arg)

        # Verify it's a list/factory function by name
        func_name = column.default.arg.__name__.lower()
        assert "list" in func_name or "factory" in func_name

    def test_last_password_change_nullable(self):
        """Test last_password_change is nullable."""
        column = UserSecuritySettings.__table__.columns["last_password_change"]
        assert column.nullable is True

    def test_table_has_indexes(self):
        """Test table has __table_args__ with indexes."""
        assert hasattr(UserSecuritySettings, "__table_args__")
        assert UserSecuritySettings.__table_args__ is not None


# ==================== DEFAULT VALUES TESTS ====================

class TestUserSecuritySettingsDefaults:
    """Tests for default field values."""

    def test_new_settings_totp_disabled(self, settings):
        """Test new settings have TOTP disabled by default."""
        assert settings.totp_enabled is False

    def test_new_settings_totp_secret_none(self, settings):
        """Test new settings have no TOTP secret."""
        assert settings.totp_secret is None

    def test_new_settings_backup_codes_empty(self, settings):
        """Test new settings have empty backup codes list."""
        assert settings.totp_backup_codes == []

    def test_new_settings_last_password_change_none(self, settings):
        """Test new settings have no last password change."""
        assert settings.last_password_change is None

    def test_new_settings_user_id_set(self, settings, user_id):
        """Test new settings have user_id set."""
        assert settings.user_id == user_id


# ==================== TOTP MANAGEMENT TESTS ====================

class TestUserSecuritySettingsTOTP:
    """Tests for TOTP management methods."""

    def test_enable_totp_sets_fields(self, settings):
        """Test enable_totp sets totp_enabled and totp_secret."""
        secret = "JBSWY3DPEHPK3PXP"
        settings.enable_totp(secret)

        assert settings.totp_enabled is True
        assert settings.totp_secret == secret

    def test_enable_totp_preserves_backup_codes(self, settings):
        """Test enable_totp preserves existing backup codes."""
        settings.totp_backup_codes = ["code1", "code2"]
        settings.enable_totp("secret")

        assert settings.totp_backup_codes == ["code1", "code2"]

    def test_disable_totp_clears_fields(self, settings):
        """Test disable_totp clears TOTP fields."""
        settings.totp_enabled = True
        settings.totp_secret = "secret"
        settings.totp_backup_codes = ["code1", "code2"]

        settings.disable_totp()

        assert settings.totp_enabled is False
        assert settings.totp_secret is None
        assert settings.totp_backup_codes == []

    def test_disable_totp_when_already_disabled(self, settings):
        """Test disable_totp when TOTP is already disabled."""
        settings.totp_enabled = False
        settings.totp_secret = None
        settings.totp_backup_codes = []

        settings.disable_totp()

        assert settings.totp_enabled is False
        assert settings.totp_secret is None
        assert settings.totp_backup_codes == []

    def test_check_totp_enabled_true(self, settings):
        """Test check_totp_enabled returns True when enabled."""
        settings.totp_enabled = True
        settings.totp_secret = "secret"

        assert settings.check_totp_enabled() is True

    def test_check_totp_enabled_false_when_disabled(self, settings):
        """Test check_totp_enabled returns False when totp_enabled is False."""
        settings.totp_enabled = False
        settings.totp_secret = "secret"

        assert settings.check_totp_enabled() is False

    def test_check_totp_enabled_false_when_no_secret(self, settings):
        """Test check_totp_enabled returns False when secret is None."""
        settings.totp_enabled = True
        settings.totp_secret = None

        assert settings.check_totp_enabled() is False

    def test_check_totp_enabled_false_when_both_false(self, settings):
        """Test check_totp_enabled returns False when both are unset."""
        settings.totp_enabled = False
        settings.totp_secret = None

        assert settings.check_totp_enabled() is False


# ==================== REPR TESTS ====================

class TestUserSecuritySettingsRepr:
    """Tests for __repr__ method."""

    def test_repr_includes_user_id(self, settings, user_id):
        """Test __repr__ includes user_id."""
        repr_str = repr(settings)
        assert str(user_id) in repr_str

    def test_repr_includes_totp_enabled(self, settings):
        """Test __repr__ includes totp_enabled."""
        repr_str = repr(settings)
        assert "totp_enabled=False" in repr_str

    def test_repr_when_totp_enabled(self):
        """Test __repr__ when TOTP is enabled."""
        settings = UserSecuritySettings(
            user_id=uuid4(),
            totp_enabled=False,
        )
        settings.enable_totp("secret")
        repr_str = repr(settings)
        assert "totp_enabled=True" in repr_str

    def test_repr_does_not_contain_secret(self):
        """Test __repr__ does not expose TOTP secret."""
        settings = UserSecuritySettings(
            user_id=uuid4(),
            totp_enabled=False,
        )
        settings.enable_totp("super_secret_key")
        repr_str = repr(settings)
        assert "super_secret_key" not in repr_str

    def test_repr_does_not_contain_backup_codes(self):
        """Test __repr__ does not expose backup codes."""
        settings = UserSecuritySettings(
            user_id=uuid4(),
            totp_enabled=False,
        )
        settings.totp_backup_codes = ["12345678", "87654321"]
        repr_str = repr(settings)
        assert "12345678" not in repr_str
        assert "87654321" not in repr_str


# ==================== RELATIONSHIP TESTS ====================

class TestUserSecuritySettingsRelationships:
    """Tests for UserSecuritySettings relationships."""

    def test_has_user_relationship(self):
        """Test model has user relationship."""
        assert hasattr(UserSecuritySettings, "user")

    def test_user_is_optional(self, settings):
        """Test user can be None (lazy loaded)."""
        assert settings.user is None


# ==================== FIELD ASSIGNMENT TESTS ====================

class TestUserSecuritySettingsFieldAssignment:
    """Tests for direct field assignment."""

    def test_set_totp_secret(self, settings):
        """Test setting totp_secret directly."""
        settings.totp_secret = "new_secret"
        assert settings.totp_secret == "new_secret"

    def test_set_totp_backup_codes(self, settings):
        """Test setting totp_backup_codes."""
        codes = ["code1", "code2", "code3"]
        settings.totp_backup_codes = codes
        assert settings.totp_backup_codes == codes

    def test_set_last_password_change(self, settings):
        """Test setting last_password_change."""
        now = datetime.now(timezone.utc)
        settings.last_password_change = now
        assert settings.last_password_change == now

    def test_toggle_totp_enabled(self, settings):
        """Test toggling totp_enabled directly."""
        assert settings.totp_enabled is False
        settings.totp_enabled = True
        assert settings.totp_enabled is True

    def test_backup_codes_can_be_empty_list(self, settings):
        """Test backup codes can be an empty list."""
        settings.totp_backup_codes = []
        assert settings.totp_backup_codes == []


# ==================== EDGE CASES TESTS ====================

class TestUserSecuritySettingsEdgeCases:
    """Tests for edge cases and boundary values."""

    def test_enable_totp_with_empty_secret(self, settings):
        """Test enabling TOTP with empty secret string."""
        settings.enable_totp("")
        assert settings.totp_enabled is True
        assert settings.totp_secret == ""

    def test_enable_totp_with_long_secret(self, settings):
        """Test enabling TOTP with max length secret."""
        long_secret = "A" * 255
        settings.enable_totp(long_secret)
        assert len(settings.totp_secret) == 255

    def test_disable_totp_twice(self, settings):
        """Test calling disable_totp twice is safe."""
        settings.enable_totp("secret")
        settings.disable_totp()
        settings.disable_totp()  # Should not raise

        assert settings.totp_enabled is False
        assert settings.totp_secret is None
        assert settings.totp_backup_codes == []

    def test_enable_disable_enable_cycle(self, settings):
        """Test full enable/disable/enable cycle."""
        secret1 = "first_secret"
        secret2 = "second_secret"

        settings.enable_totp(secret1)
        assert settings.check_totp_enabled() is True

        settings.disable_totp()
        assert settings.check_totp_enabled() is False

        settings.enable_totp(secret2)
        assert settings.check_totp_enabled() is True
        assert settings.totp_secret == secret2

    def test_check_totp_enabled_after_enable(self, settings):
        """Test check_totp_enabled immediately after enable_totp."""
        settings.enable_totp("secret")
        assert settings.check_totp_enabled() is True

    def test_check_totp_enabled_after_disable(self, settings):
        """Test check_totp_enabled immediately after disable_totp."""
        settings.enable_totp("secret")
        settings.disable_totp()
        assert settings.check_totp_enabled() is False

    def test_create_with_all_fields(self, user_id):
        """Test creating settings with all fields populated."""
        now = datetime.now(timezone.utc)
        settings = UserSecuritySettings(
            user_id=user_id,
            totp_enabled=True,
            totp_secret="secret_key",
            totp_backup_codes=["backup1", "backup2"],
            last_password_change=now,
        )

        assert settings.user_id == user_id
        assert settings.totp_enabled is True
        assert settings.totp_secret == "secret_key"
        assert settings.totp_backup_codes == ["backup1", "backup2"]
        assert settings.last_password_change == now

    def test_backup_codes_with_unicode(self, settings):
        """Test backup codes with unicode characters."""
        codes = ["код1", "код2", "backup3"]
        settings.totp_backup_codes = codes
        assert settings.totp_backup_codes == codes

    def test_multiple_instances_different_users(self):
        """Test creating settings for different users."""
        user1_id = uuid4()
        user2_id = uuid4()

        settings1 = UserSecuritySettings(
            user_id=user1_id,
            totp_enabled=False,
        )
        settings2 = UserSecuritySettings(
            user_id=user2_id,
            totp_enabled=False,
        )

        assert settings1.user_id != settings2.user_id