"""
Unit tests for OAuthState model.

Tests cover:
- Model field definitions and constraints
- __repr__ method
- is_expired method
- generate_state, generate_code_verifier static methods
- create_login_state factory method
- create_link_state factory method
- Edge cases (expiration, TTL)
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest

from app.models.oauth_state import OAuthState


class TestOAuthStateModelFields:
    """Tests for OAuthState model field definitions."""

    def test_model_fields_existence(self):
        """Test all expected fields exist."""
        fields = [
            "id", "state", "code_verifier", "provider", "redirect_uri",
            "scope", "user_id", "is_linked", "expires_at",
        ]
        for field in fields:
            assert hasattr(OAuthState, field)

    def test_id_uses_server_default(self):
        """Test id uses server default UUID generation."""
        id_column = OAuthState.__table__.columns["id"]
        assert id_column.server_default is not None

    def test_state_unique_and_indexed(self):
        """Test state field is unique and indexed."""
        state_column = OAuthState.__table__.columns["state"]
        assert state_column.unique is True
        assert state_column.index is True

    def test_code_verifier_not_nullable(self):
        """Test code_verifier field is not nullable."""
        column = OAuthState.__table__.columns["code_verifier"]
        assert column.nullable is False

    def test_is_linked_default_false(self):
        """Test is_linked defaults to False."""
        column = OAuthState.__table__.columns["is_linked"]
        assert column.default.arg is False

    def test_user_id_nullable(self):
        """Test user_id field is nullable."""
        column = OAuthState.__table__.columns["user_id"]
        assert column.nullable is True

    def test_expires_at_indexed(self):
        """Test expires_at field has index."""
        column = OAuthState.__table__.columns["expires_at"]
        assert column.index is True


class TestOAuthStateRepr:
    """Tests for __repr__ method."""

    def test_repr_format(self):
        """Test __repr__ returns expected format."""
        state = OAuthState(
            state="abc123xyz456def789ghi",
            code_verifier="verifier",
            provider="google",
            redirect_uri="https://cb",
            expires_at=datetime.now(timezone.utc),
        )
        repr_str = repr(state)
        assert "OAuthState" in repr_str
        assert "state=abc123xy..." in repr_str
        assert "provider=google" in repr_str


class TestOAuthStateExpiration:
    """Tests for is_expired method."""

    def test_is_expired_true(self):
        """Test is_expired returns True when expired."""
        state = OAuthState(
            state="test",
            code_verifier="verifier",
            provider="google",
            redirect_uri="https://cb",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        assert state.is_expired() is True

    def test_is_expired_false(self):
        """Test is_expired returns False when not expired."""
        state = OAuthState(
            state="test",
            code_verifier="verifier",
            provider="google",
            redirect_uri="https://cb",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        assert state.is_expired() is False


class TestOAuthStateGenerate:
    """Tests for generate_state and generate_code_verifier."""

    def test_generate_state_format(self):
        """Test generate_state returns a string."""
        result = OAuthState.generate_state()
        assert isinstance(result, str)
        assert len(result) >= 43  # 32 bytes base64 encoded

    def test_generate_state_uniqueness(self):
        """Test generate_state produces unique values."""
        states = {OAuthState.generate_state() for _ in range(10)}
        assert len(states) == 10

    def test_generate_code_verifier_format(self):
        """Test generate_code_verifier returns a string."""
        result = OAuthState.generate_code_verifier()
        assert isinstance(result, str)
        assert len(result) >= 86  # 64 bytes base64 encoded

    def test_generate_code_verifier_uniqueness(self):
        """Test generate_code_verifier produces unique values."""
        verifiers = {OAuthState.generate_code_verifier() for _ in range(10)}
        assert len(verifiers) == 10


class TestCreateLoginState:
    """Tests for create_login_state factory method."""

    def test_create_login_state(self):
        """Test creating login state."""
        with patch.object(OAuthState, "generate_state", return_value="test_state"):
            with patch.object(OAuthState, "generate_code_verifier", return_value="test_verifier"):
                with patch("app.models.oauth_state.datetime") as mock_dt:
                    mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
                    mock_dt.now.return_value = mock_now

                    oauth_state, state, code_verifier = OAuthState.create_login_state(
                        provider="google",
                        redirect_uri="https://example.com/callback",
                        scope="email profile",
                        ttl_seconds=600,
                    )

        assert state == "test_state"
        assert code_verifier == "test_verifier"
        assert oauth_state.state == "test_state"
        assert oauth_state.code_verifier == "test_verifier"
        assert oauth_state.provider == "google"
        assert oauth_state.redirect_uri == "https://example.com/callback"
        assert oauth_state.scope == "email profile"
        assert oauth_state.is_linked is False
        assert oauth_state.user_id is None
        assert oauth_state.expires_at == mock_now + timedelta(seconds=600)

    def test_create_login_state_default_ttl(self):
        """Test create_login_state uses default TTL of 600 seconds."""
        with patch.object(OAuthState, "generate_state", return_value="s"):
            with patch.object(OAuthState, "generate_code_verifier", return_value="v"):
                with patch("app.models.oauth_state.datetime") as mock_dt:
                    mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
                    mock_dt.now.return_value = mock_now

                    oauth_state, _, _ = OAuthState.create_login_state(
                        provider="vk",
                        redirect_uri="https://cb",
                    )

        assert oauth_state.expires_at == mock_now + timedelta(seconds=600)

    def test_create_login_state_custom_ttl(self):
        """Test create_login_state with custom TTL."""
        with patch.object(OAuthState, "generate_state", return_value="s"):
            with patch.object(OAuthState, "generate_code_verifier", return_value="v"):
                with patch("app.models.oauth_state.datetime") as mock_dt:
                    mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
                    mock_dt.now.return_value = mock_now

                    oauth_state, _, _ = OAuthState.create_login_state(
                        provider="apple",
                        redirect_uri="https://cb",
                        ttl_seconds=300,
                    )

        assert oauth_state.expires_at == mock_now + timedelta(seconds=300)

    def test_create_login_state_without_scope(self):
        """Test create_login_state without optional scope."""
        with patch.object(OAuthState, "generate_state", return_value="s"):
            with patch.object(OAuthState, "generate_code_verifier", return_value="v"):
                oauth_state, _, _ = OAuthState.create_login_state(
                    provider="google",
                    redirect_uri="https://cb",
                )

        assert oauth_state.scope is None


class TestCreateLinkState:
    """Tests for create_link_state factory method."""

    def test_create_link_state(self):
        """Test creating link state."""
        user_id = uuid4()

        with patch.object(OAuthState, "generate_state", return_value="link_state"):
            with patch.object(OAuthState, "generate_code_verifier", return_value="link_verifier"):
                with patch("app.models.oauth_state.datetime") as mock_dt:
                    mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
                    mock_dt.now.return_value = mock_now

                    oauth_state, state, code_verifier = OAuthState.create_link_state(
                        provider="google",
                        redirect_uri="https://example.com/callback",
                        user_id=user_id,
                        scope="email",
                        ttl_seconds=300,
                    )

        assert state == "link_state"
        assert code_verifier == "link_verifier"
        assert oauth_state.provider == "google"
        assert oauth_state.is_linked is True
        assert oauth_state.user_id == user_id
        assert oauth_state.scope == "email"
        assert oauth_state.expires_at == mock_now + timedelta(seconds=300)

    def test_create_link_state_default_ttl(self):
        """Test create_link_state uses default TTL."""
        user_id = uuid4()

        with patch.object(OAuthState, "generate_state", return_value="s"):
            with patch.object(OAuthState, "generate_code_verifier", return_value="v"):
                with patch("app.models.oauth_state.datetime") as mock_dt:
                    mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
                    mock_dt.now.return_value = mock_now

                    oauth_state, _, _ = OAuthState.create_link_state(
                        provider="vk",
                        redirect_uri="https://cb",
                        user_id=user_id,
                    )

        assert oauth_state.expires_at == mock_now + timedelta(seconds=600)


class TestEdgeCases:
    """Tests for edge cases."""

    def test_is_expired_at_exact_moment(self):
        """Test is_expired at exact current time."""
        now = datetime.now(timezone.utc)
        state = OAuthState(
            state="test",
            code_verifier="verifier",
            provider="google",
            redirect_uri="https://cb",
            expires_at=now,
        )
        assert state.is_expired() is True

    def test_is_expired_far_future(self):
        """Test is_expired with far future date."""
        state = OAuthState(
            state="test",
            code_verifier="verifier",
            provider="google",
            redirect_uri="https://cb",
            expires_at=datetime.now(timezone.utc) + timedelta(days=365),
        )
        assert state.is_expired() is False

    def test_is_expired_far_past(self):
        """Test is_expired with far past date."""
        state = OAuthState(
            state="test",
            code_verifier="verifier",
            provider="google",
            redirect_uri="https://cb",
            expires_at=datetime.now(timezone.utc) - timedelta(days=30),
        )
        assert state.is_expired() is True