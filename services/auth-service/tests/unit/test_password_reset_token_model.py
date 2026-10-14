"""
Unit tests for PasswordResetToken model.

Tests cover:
- Model field definitions and constraints
- __repr__ method
- is_expired, is_used, is_valid methods
- mark_as_used method
- create_token_hash static method
- generate_raw_token static method
- create_for_user factory method
- create_for_user_with_custom_ttl factory method
- Edge cases (expiration, TTL)
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest

from app.models.password_reset_token import PasswordResetToken


class TestPasswordResetTokenModelFields:
    """Tests for PasswordResetToken model field definitions."""

    def test_model_fields_existence(self):
        """Test all expected fields exist."""
        fields = [
            "id", "user_id", "token_hash", "expires_at", "used_at", "created_at", "updated_at"
        ]
        for field in fields:
            assert hasattr(PasswordResetToken, field)

    def test_id_uses_server_default(self):
        """Test id uses server default UUID generation."""
        id_column = PasswordResetToken.__table__.columns["id"]
        assert id_column.server_default is not None

    def test_user_id_indexed(self):
        """Test user_id field has index."""
        column = PasswordResetToken.__table__.columns["user_id"]
        assert column.index is True

    def test_token_hash_unique_and_indexed(self):
        """Test token_hash field is unique and indexed."""
        column = PasswordResetToken.__table__.columns["token_hash"]
        assert column.unique is True
        assert column.index is True

    def test_token_hash_length(self):
        """Test token_hash field max length is 64 (SHA-256 hex)."""
        column = PasswordResetToken.__table__.columns["token_hash"]
        assert column.type.length == 64

    def test_expires_at_indexed(self):
        """Test expires_at field has index."""
        column = PasswordResetToken.__table__.columns["expires_at"]
        assert column.index is True

    def test_used_at_nullable(self):
        """Test used_at field is nullable."""
        column = PasswordResetToken.__table__.columns["used_at"]
        assert column.nullable is True


class TestPasswordResetTokenRepr:
    """Tests for __repr__ method."""

    def test_repr_format(self):
        """Test __repr__ returns expected format."""
        user_id = uuid4()
        token = PasswordResetToken(
            user_id=user_id,
            token_hash="abcdef1234567890",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        repr_str = repr(token)
        assert "PasswordResetToken" in repr_str
        assert f"user_id={user_id}" in repr_str
        assert "token_hash=abcdef12..." in repr_str


class TestPasswordResetTokenExpiration:
    """Tests for is_expired, is_used, is_valid methods."""

    def test_is_expired_true(self):
        """Test is_expired returns True when expired."""
        token = PasswordResetToken(
            user_id=uuid4(),
            token_hash="hash",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        assert token.is_expired() is True

    def test_is_expired_false(self):
        """Test is_expired returns False when not expired."""
        token = PasswordResetToken(
            user_id=uuid4(),
            token_hash="hash",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert token.is_expired() is False

    def test_is_used_true(self):
        """Test is_used returns True when used_at is set."""
        token = PasswordResetToken(
            user_id=uuid4(),
            token_hash="hash",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            used_at=datetime.now(timezone.utc),
        )
        assert token.is_used() is True

    def test_is_used_false(self):
        """Test is_used returns False when used_at is None."""
        token = PasswordResetToken(
            user_id=uuid4(),
            token_hash="hash",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert token.is_used() is False

    def test_is_valid_true(self):
        """Test is_valid returns True when not expired and not used."""
        token = PasswordResetToken(
            user_id=uuid4(),
            token_hash="hash",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert token.is_valid() is True

    def test_is_valid_false_expired(self):
        """Test is_valid returns False when expired."""
        token = PasswordResetToken(
            user_id=uuid4(),
            token_hash="hash",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert token.is_valid() is False

    def test_is_valid_false_used(self):
        """Test is_valid returns False when used."""
        token = PasswordResetToken(
            user_id=uuid4(),
            token_hash="hash",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            used_at=datetime.now(timezone.utc),
        )
        assert token.is_valid() is False


class TestPasswordResetTokenMarkAsUsed:
    """Tests for mark_as_used method."""

    def test_mark_as_used(self):
        """Test mark_as_used sets used_at to current time."""
        token = PasswordResetToken(
            user_id=uuid4(),
            token_hash="hash",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        with patch("app.models.password_reset_token.datetime") as mock_dt:
            mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
            mock_dt.now.return_value = mock_now
            token.mark_as_used()

        assert token.used_at == mock_now


class TestPasswordResetTokenCreateTokenHash:
    """Tests for create_token_hash static method."""

    def test_create_token_hash(self):
        """Test create_token_hash returns SHA-256 hex."""
        result = PasswordResetToken.create_token_hash("test_token")
        assert len(result) == 64  # SHA-256 hex
        assert isinstance(result, str)

    def test_create_token_hash_consistency(self):
        """Test same input produces same hash."""
        hash1 = PasswordResetToken.create_token_hash("test_token")
        hash2 = PasswordResetToken.create_token_hash("test_token")
        assert hash1 == hash2

    def test_create_token_hash_different_inputs(self):
        """Test different inputs produce different hashes."""
        hash1 = PasswordResetToken.create_token_hash("token1")
        hash2 = PasswordResetToken.create_token_hash("token2")
        assert hash1 != hash2


class TestGenerateRawToken:
    """Tests for generate_raw_token static method."""

    def test_generate_raw_token_format(self):
        """Test raw token generation returns a string."""
        result = PasswordResetToken.generate_raw_token()
        assert isinstance(result, str)
        assert len(result) >= 86  # 64 bytes base64 encoded

    def test_generate_raw_token_uniqueness(self):
        """Test raw token generation produces unique values."""
        tokens = {PasswordResetToken.generate_raw_token() for _ in range(10)}
        assert len(tokens) == 10


class TestCreateForUser:
    """Tests for create_for_user factory method."""

    def test_create_for_user(self):
        """Test creating token for user."""
        user_id = uuid4()

        with patch.object(PasswordResetToken, "generate_raw_token", return_value="raw_token"):
            with patch.object(PasswordResetToken, "create_token_hash", return_value="hashed_token"):
                with patch("app.models.password_reset_token.datetime") as mock_dt:
                    mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
                    mock_dt.now.return_value = mock_now

                    token, raw_token = PasswordResetToken.create_for_user(user_id, ttl_hours=1)

        assert token.user_id == user_id
        assert token.token_hash == "hashed_token"
        assert token.expires_at == mock_now + timedelta(hours=1)
        assert token.used_at is None
        assert raw_token == "raw_token"

    def test_create_for_user_default_ttl(self):
        """Test create_for_user uses default TTL of 1 hour."""
        user_id = uuid4()

        with patch.object(PasswordResetToken, "generate_raw_token", return_value="raw"):
            with patch.object(PasswordResetToken, "create_token_hash", return_value="hash"):
                with patch("app.models.password_reset_token.datetime") as mock_dt:
                    mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
                    mock_dt.now.return_value = mock_now

                    token, _ = PasswordResetToken.create_for_user(user_id)

        assert token.expires_at == mock_now + timedelta(hours=1)

    def test_create_for_user_custom_ttl(self):
        """Test creating token with custom TTL."""
        user_id = uuid4()

        with patch.object(PasswordResetToken, "generate_raw_token", return_value="raw"):
            with patch.object(PasswordResetToken, "create_token_hash", return_value="hash"):
                with patch("app.models.password_reset_token.datetime") as mock_dt:
                    mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
                    mock_dt.now.return_value = mock_now

                    token, _ = PasswordResetToken.create_for_user(user_id, ttl_hours=24)

        assert token.expires_at == mock_now + timedelta(hours=24)


class TestCreateForUserWithCustomTTL:
    """Tests for create_for_user_with_custom_ttl factory method."""

    def test_create_with_ttl_seconds(self):
        """Test creating token with custom TTL in seconds."""
        user_id = uuid4()

        with patch.object(PasswordResetToken, "generate_raw_token", return_value="raw_token"):
            with patch.object(PasswordResetToken, "create_token_hash", return_value="hashed"):
                with patch("app.models.password_reset_token.datetime") as mock_dt:
                    mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
                    mock_dt.now.return_value = mock_now

                    token, raw = PasswordResetToken.create_for_user_with_custom_ttl(
                        user_id=user_id,
                        ttl_seconds=1800,
                    )

        assert token.user_id == user_id
        assert token.expires_at == mock_now + timedelta(seconds=1800)
        assert raw == "raw_token"

    def test_create_with_short_ttl(self):
        """Test creating token with very short TTL."""
        user_id = uuid4()

        with patch.object(PasswordResetToken, "generate_raw_token", return_value="raw"):
            with patch.object(PasswordResetToken, "create_token_hash", return_value="hash"):
                with patch("app.models.password_reset_token.datetime") as mock_dt:
                    mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
                    mock_dt.now.return_value = mock_now

                    token, _ = PasswordResetToken.create_for_user_with_custom_ttl(
                        user_id=user_id,
                        ttl_seconds=60,
                    )

        assert token.expires_at == mock_now + timedelta(seconds=60)


class TestEdgeCases:
    """Tests for edge cases."""

    def test_is_expired_at_exact_moment(self):
        """Test is_expired at exact current time."""
        now = datetime.now(timezone.utc)
        token = PasswordResetToken(
            user_id=uuid4(),
            token_hash="hash",
            expires_at=now,
        )
        assert token.is_expired() is True

    def test_is_expired_far_future(self):
        """Test is_expired with far future date."""
        token = PasswordResetToken(
            user_id=uuid4(),
            token_hash="hash",
            expires_at=datetime.now(timezone.utc) + timedelta(days=365),
        )
        assert token.is_expired() is False

    def test_multiple_tokens_same_user(self):
        """Test multiple tokens can exist for same user."""
        user_id = uuid4()

        with patch.object(PasswordResetToken, "generate_raw_token", side_effect=["raw1", "raw2"]):
            with patch.object(PasswordResetToken, "create_token_hash", side_effect=["hash1", "hash2"]):
                token1, _ = PasswordResetToken.create_for_user(user_id)
                token2, _ = PasswordResetToken.create_for_user(user_id)

        assert token1.user_id == token2.user_id
        assert token1.token_hash != token2.token_hash

    def test_create_token_hash_empty_string(self):
        """Test create_token_hash with empty string."""
        result = PasswordResetToken.create_token_hash("")
        assert len(result) == 64