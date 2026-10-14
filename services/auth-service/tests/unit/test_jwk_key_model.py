"""
Unit tests for JWKKey model.

Tests cover:
- Model field definitions and constraints
- __repr__ method
- to_dict() serialization (excludes private key by default)
- get_jwks_public_data (RSA/EC formats, JSON vs PEM)
- is_expired, is_valid properties
- activate, deactivate, expire methods
- rotate method
- should_rotate method
- create_rsa_key, create_ec_key factory methods
- Edge cases and boundary values
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest

from app.models.jwk_key import JWKKey


class TestJWKKeyModelFields:
    """Tests for JWKKey model field definitions."""

    def test_model_fields_existence(self):
        """Test all expected fields exist."""
        fields = [
            "id", "kid", "private_key_encrypted", "public_key",
            "algorithm", "key_type", "is_active", "is_verification_enabled",
            "expires_at", "activated_at", "rotated_at",
            "created_by", "activated_by", "rotated_by",
            "key_size", "key_metadata",
        ]
        for field in fields:
            assert hasattr(JWKKey, field)

    def test_id_uses_server_default(self):
        """Test id uses server default UUID generation."""
        id_column = JWKKey.__table__.columns["id"]
        assert id_column.server_default is not None

    def test_kid_unique_and_indexed(self):
        """Test kid field is unique and indexed."""
        kid_column = JWKKey.__table__.columns["kid"]
        assert kid_column.unique is True
        assert kid_column.index is True

    def test_private_key_encrypted_is_text(self):
        """Test private_key_encrypted is Text type."""
        column = JWKKey.__table__.columns["private_key_encrypted"]
        assert column.type.__class__.__name__ == "Text"

    def test_is_active_indexed(self):
        """Test is_active field has index."""
        column = JWKKey.__table__.columns["is_active"]
        assert column.index is True

    def test_is_active_default_true(self):
        """Test is_active column default is True."""
        column = JWKKey.__table__.columns["is_active"]
        assert column.default.arg is True

    def test_is_verification_enabled_default(self):
        """Test is_verification_enabled column default is True."""
        column = JWKKey.__table__.columns["is_verification_enabled"]
        assert column.default.arg is True


class TestJWKKeyRepr:
    """Tests for __repr__ method."""

    def test_repr_format(self):
        """Test __repr__ returns expected format with explicit values."""
        key = JWKKey(
            kid="test_kid_123",
            private_key_encrypted="enc",
            public_key="pub",
            algorithm="RS256",
            key_type="RSA",
            is_active=True,
        )
        repr_str = repr(key)
        assert "JWKKey" in repr_str
        assert "kid=test_kid_123" in repr_str
        assert "algorithm=RS256" in repr_str
        assert "is_active=True" in repr_str


class TestJWKKeyToDict:
    """Tests for to_dict() method."""

    def test_to_dict_excludes_private_by_default(self):
        """Test to_dict() does not include private key by default."""
        key = JWKKey(
            id=uuid4(),
            kid="key_123",
            private_key_encrypted="secret",
            public_key="public_pem",
            algorithm="RS256",
            key_type="RSA",
            key_size=2048,
        )
        result = key.to_dict()
        assert "private_key_encrypted" not in result
        assert "public_key" not in result
        assert result["kid"] == "key_123"
        assert result["algorithm"] == "RS256"
        assert result["key_type"] == "RSA"
        assert result["key_size"] == 2048

    def test_to_dict_include_private(self):
        """Test to_dict() includes private data when requested."""
        key = JWKKey(
            id=uuid4(),
            kid="key_123",
            private_key_encrypted="secret",
            public_key="public_pem",
            algorithm="RS256",
            key_type="RSA",
            created_by="admin",
        )
        result = key.to_dict(include_private=True)
        assert result["private_key_encrypted"] == "secret"
        assert result["public_key"] == "public_pem"
        assert result["created_by"] == "admin"

    def test_to_dict_with_dates(self):
        """Test to_dict() with datetime fields."""
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=30)
        key = JWKKey(
            kid="key_123",
            private_key_encrypted="enc",
            public_key="pub",
            algorithm="RS256",
            key_type="RSA",
            created_at=now,
            expires_at=expires,
            activated_at=now,
            rotated_at=None,
        )
        result = key.to_dict()
        assert result["created_at"] == now.isoformat()
        assert result["expires_at"] == expires.isoformat()
        assert result["activated_at"] == now.isoformat()
        assert result["rotated_at"] is None

    def test_to_dict_with_none_dates(self):
        """Test to_dict() when date fields are None."""
        key = JWKKey(
            kid="key_123",
            private_key_encrypted="enc",
            public_key="pub",
            algorithm="RS256",
            key_type="RSA",
        )
        result = key.to_dict()
        assert result["created_at"] is None
        assert result["expires_at"] is None


class TestJWKKeyGetJWKSPublicData:
    """Tests for get_jwks_public_data method."""

    def test_json_public_key(self):
        """Test JWKS data when public_key is JSON."""
        import json
        jwk_json = json.dumps({"kty": "RSA", "n": "abc", "e": "AQAB"})
        key = JWKKey(
            kid="json_kid",
            private_key_encrypted="enc",
            public_key=jwk_json,
            algorithm="RS256",
            key_type="RSA",
        )
        result = key.get_jwks_public_data()
        assert result["kid"] == "json_kid"
        assert result["alg"] == "RS256"
        assert result["use"] == "sig"
        assert result["kty"] == "RSA"
        assert result["n"] == "abc"

    def test_pem_public_key(self):
        """Test JWKS data when public_key is PEM (fallback)."""
        key = JWKKey(
            kid="pem_kid",
            private_key_encrypted="enc",
            public_key="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
            algorithm="RS256",
            key_type="RSA",
        )
        result = key.get_jwks_public_data()
        assert result["kid"] == "pem_kid"
        assert result["kty"] == "RSA"
        assert result["alg"] == "RS256"
        assert result["use"] == "sig"
        assert "n" in result

    def test_invalid_json_fallback(self):
        """Test invalid JSON falls back to PEM format."""
        key = JWKKey(
            kid="bad_json_kid",
            private_key_encrypted="enc",
            public_key="{invalid json",
            algorithm="ES256",
            key_type="EC",
        )
        result = key.get_jwks_public_data()
        assert result["kid"] == "bad_json_kid"
        assert result["alg"] == "ES256"


class TestJWKKeyExpiration:
    """Tests for expiration properties."""

    def test_is_expired_true(self):
        """Test is_expired returns True when expired."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert key.is_expired is True

    def test_is_expired_false(self):
        """Test is_expired returns False when not expired."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        assert key.is_expired is False

    def test_is_expired_none(self):
        """Test is_expired returns False when expires_at is None."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.expires_at = None
        assert key.is_expired is False

    def test_is_valid_true(self):
        """Test is_valid returns True for active unexpired key."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.is_active = True
        key.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        assert key.is_valid is True

    def test_is_valid_false_inactive(self):
        """Test is_valid returns False when inactive."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.is_active = False
        key.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        assert key.is_valid is False

    def test_is_valid_false_expired(self):
        """Test is_valid returns False when expired."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.is_active = True
        key.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert key.is_valid is False


class TestJWKKeyActivation:
    """Tests for activate, deactivate, expire methods."""

    def test_activate(self):
        """Test activate sets is_active and activated_at."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.is_active = False
        key.activated_at = None

        with patch("app.models.jwk_key.datetime") as mock_dt:
            mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
            mock_dt.now.return_value = mock_now
            key.activate(activated_by="admin")

        assert key.is_active is True
        assert key.activated_at == mock_now
        assert key.activated_by == "admin"

    def test_activate_without_user(self):
        """Test activate without activated_by."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.activate()
        assert key.is_active is True
        assert key.activated_by is None

    def test_deactivate(self):
        """Test deactivate sets is_active to False."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.is_active = True
        key.deactivate()
        assert key.is_active is False

    def test_expire(self):
        """Test expire sets is_active to False."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.is_active = True
        key.expire()
        assert key.is_active is False


class TestJWKKeyRotate:
    """Tests for rotate method."""

    def test_rotate_updates_keys(self):
        """Test rotate updates key materials."""
        key = JWKKey(
            kid="k", private_key_encrypted="old_priv", public_key="old_pub",
            algorithm="RS256", key_type="RSA",
        )
        key.is_active = True

        with patch("app.models.jwk_key.datetime") as mock_dt:
            mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
            mock_dt.now.return_value = mock_now
            key.rotate("new_priv", "new_pub", rotated_by="admin")

        assert key.private_key_encrypted == "new_priv"
        assert key.public_key == "new_pub"
        assert key.is_active is False
        assert key.rotated_at == mock_now
        assert key.rotated_by == "admin"

    def test_should_rotate_from_created(self):
        """Test should_rotate based on created_at."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.created_at = datetime.now(timezone.utc) - timedelta(days=100)
        assert key.should_rotate(rotation_interval_days=90) is True

    def test_should_rotate_from_rotated(self):
        """Test should_rotate based on rotated_at."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.created_at = datetime.now(timezone.utc) - timedelta(days=200)
        key.rotated_at = datetime.now(timezone.utc) - timedelta(days=30)
        assert key.should_rotate(rotation_interval_days=90) is False

    def test_should_rotate_not_needed(self):
        """Test should_rotate returns False for recent key."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.created_at = datetime.now(timezone.utc) - timedelta(days=10)
        assert key.should_rotate(rotation_interval_days=90) is False


class TestJWKKeyFactoryMethods:
    """Tests for create_rsa_key and create_ec_key factory methods."""

    def test_create_rsa_key(self):
        """Test RSA key creation."""
        key = JWKKey.create_rsa_key(
            kid="rsa_key_1",
            private_key_encrypted="encrypted_private",
            public_key="public_pem",
            algorithm="RS256",
            expires_days=365,
            key_size=2048,
            created_by="system",
        )
        assert key.kid == "rsa_key_1"
        assert key.private_key_encrypted == "encrypted_private"
        assert key.public_key == "public_pem"
        assert key.algorithm == "RS256"
        assert key.key_type == "RSA"
        assert key.is_active is False
        assert key.is_verification_enabled is True
        assert key.key_size == 2048
        assert key.created_by == "system"
        assert key.expires_at is not None

    def test_create_rsa_key_defaults(self):
        """Test RSA key creation with default values."""
        key = JWKKey.create_rsa_key(
            kid="rsa_default",
            private_key_encrypted="enc",
            public_key="pub",
        )
        assert key.algorithm == "RS256"
        assert key.key_size == 2048
        assert key.created_by is None

    def test_create_ec_key(self):
        """Test EC key creation."""
        key = JWKKey.create_ec_key(
            kid="ec_key_1",
            private_key_encrypted="encrypted_private",
            public_key="public_pem",
            algorithm="ES256",
            expires_days=180,
            key_size=256,
            created_by="admin",
        )
        assert key.kid == "ec_key_1"
        assert key.algorithm == "ES256"
        assert key.key_type == "EC"
        assert key.is_active is False
        assert key.key_size == 256

    def test_create_ec_key_defaults(self):
        """Test EC key creation with default values."""
        key = JWKKey.create_ec_key(
            kid="ec_default",
            private_key_encrypted="enc",
            public_key="pub",
        )
        assert key.algorithm == "ES256"
        assert key.key_size == 256
        assert key.created_by is None


class TestJWKKeyEdgeCases:
    """Tests for edge cases."""

    def test_is_valid_no_expiry(self):
        """Test is_valid when expires_at is None."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.is_active = True
        key.expires_at = None
        assert key.is_valid is True

    def test_is_expired_exact_boundary(self):
        """Test is_expired at exact current time."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
        )
        key.expires_at = datetime.now(timezone.utc)
        assert key.is_expired is True  # Strictly less than

    def test_to_dict_with_key_metadata(self):
        """Test to_dict with key_metadata."""
        key = JWKKey(
            kid="k", private_key_encrypted="e", public_key="p",
            algorithm="RS256", key_type="RSA",
            key_metadata={"env": "prod", "region": "us-east"},
        )
        result = key.to_dict()
        assert result["key_metadata"] == {"env": "prod", "region": "us-east"}