"""
Unit tests for JWKS Pydantic schemas (RFC 7517).

Tests cover:
- JWKPublicData (RSA and EC formats, field validation, required fields)
- JWKSResponse (keys list, structure)
- JWKKeyResponse (admin info with UUID, dates, rotation metadata, validators)
- JWKKeyListResponse (items, total)
- RotateKeysRequest (algorithm validation, key_size ge/le, grace_period_hours, validators)
- RotateKeysResponse (success, new_kid, expires_at)
- ActivateKeyResponse, DeactivateKeyResponse
- CleanupExpiredResponse
- JWKSMetricsResponse (metrics fields, keys_by_algorithm)
- JWKSErrorResponse (error, message, details, timestamp)
- RFC 7517 compliance checks
- Edge cases and boundary values
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.schemas.jwks import (
    ActivateKeyResponse,
    CleanupExpiredResponse,
    DeactivateKeyResponse,
    JWKKeyListResponse,
    JWKKeyResponse,
    JWKPublicData,
    JWKSErrorResponse,
    JWKSMetricsResponse,
    JWKSResponse,
    RotateKeysRequest,
    RotateKeysResponse,
)


class TestJWKPublicData:
    """Tests for JWKPublicData schema (RFC 7517)."""

    def test_valid_rsa_key(self):
        """Test creating valid RSA JWK."""
        key = JWKPublicData(
            kid="key_abc123",
            kty="RSA",
            alg="RS256",
            n="0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            e="AQAB",
        )
        assert key.kid == "key_abc123"
        assert key.kty == "RSA"
        assert key.alg == "RS256"
        assert key.use == "sig"
        assert key.n is not None
        assert key.e == "AQAB"

    def test_valid_ec_key(self):
        """Test creating valid EC JWK."""
        key = JWKPublicData(
            kid="key_ec456",
            kty="EC",
            alg="ES256",
            crv="P-256",
            x="MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            y="4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        )
        assert key.kty == "EC"
        assert key.crv == "P-256"
        assert key.x is not None
        assert key.y is not None

    def test_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            JWKPublicData()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"kid", "kty", "alg"}
        assert required_fields.issubset(errors)

    def test_use_default(self):
        """Test use defaults to 'sig'."""
        key = JWKPublicData(kid="k", kty="RSA", alg="RS256")
        assert key.use == "sig"

    def test_use_validator_invalid(self):
        """Test use validator rejects invalid values."""
        with pytest.raises(ValidationError):
            JWKPublicData(kid="k", kty="RSA", alg="RS256", use="invalid")


class TestJWKSResponse:
    """Tests for JWKSResponse schema."""

    def test_valid_jwks_response(self):
        """Test creating valid JWKS response."""
        keys = [
            JWKPublicData(kid="k1", kty="RSA", alg="RS256"),
            JWKPublicData(kid="k2", kty="EC", alg="ES256"),
        ]
        response = JWKSResponse(keys=keys)
        assert len(response.keys) == 2

    def test_empty_keys(self):
        """Test JWKS with empty keys."""
        response = JWKSResponse(keys=[])
        assert response.keys == []

    def test_default_keys(self):
        """Test keys defaults to empty list."""
        response = JWKSResponse()
        assert response.keys == []


class TestJWKKeyResponse:
    """Tests for JWKKeyResponse (admin info)."""

    @pytest.fixture
    def key_id(self):
        return uuid4()

    @pytest.fixture
    def now(self):
        return datetime.now(timezone.utc)

    def test_valid_key_response(self, key_id, now):
        """Test creating valid admin key response."""
        key = JWKKeyResponse(
            id=key_id,
            kid="key_abc",
            key_type="RSA",
            algorithm="RS256",
            is_active=True,
            created_at=now,
        )
        assert key.id == key_id
        assert key.key_type == "RSA"
        assert key.algorithm == "RS256"
        assert key.is_expired is False

    def test_with_all_fields(self, key_id, now):
        """Test with all optional fields."""
        key = JWKKeyResponse(
            id=key_id,
            kid="key_full",
            key_type="RSA",
            algorithm="RS256",
            is_active=True,
            is_verification_enabled=True,
            is_expired=False,
            created_at=now,
            activated_at=now,
            expires_at=now + timedelta(days=30),
            rotated_at=now,
            key_size=2048,
            created_by="admin",
            activated_by="admin",
            rotated_by="system",
            key_metadata={"env": "prod"},
        )
        assert key.key_size == 2048
        assert key.created_by == "admin"
        assert key.key_metadata == {"env": "prod"}

    def test_required_fields(self):
        """Test required fields."""
        with pytest.raises(ValidationError) as exc_info:
            JWKKeyResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"id", "kid", "key_type", "algorithm", "is_active", "created_at"}
        assert required_fields.issubset(errors)

    def test_key_type_validator_invalid(self, key_id, now):
        """Test key_type validator."""
        with pytest.raises(ValidationError):
            JWKKeyResponse(id=key_id, kid="k", key_type="INVALID", algorithm="RS256", is_active=True, created_at=now)

    def test_algorithm_validator_invalid(self, key_id, now):
        """Test algorithm validator."""
        with pytest.raises(ValidationError):
            JWKKeyResponse(id=key_id, kid="k", key_type="RSA", algorithm="HS256", is_active=True, created_at=now)


class TestJWKKeyListResponse:
    """Tests for JWKKeyListResponse."""

    def test_valid_list_response(self):
        """Test creating valid key list."""
        key = JWKKeyResponse(
            id=uuid4(), kid="k", key_type="RSA", algorithm="RS256",
            is_active=True, created_at=datetime.now(timezone.utc),
        )
        response = JWKKeyListResponse(items=[key], total=1)
        assert len(response.items) == 1
        assert response.total == 1

    def test_empty_list(self):
        """Test empty list."""
        response = JWKKeyListResponse(items=[], total=0)
        assert response.items == []

    def test_required_fields(self):
        """Test required fields."""
        with pytest.raises(ValidationError) as exc_info:
            JWKKeyListResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "items" in errors
        assert "total" in errors


class TestRotateKeysRequest:
    """Tests for RotateKeysRequest schema."""

    def test_defaults(self):
        """Test default values."""
        request = RotateKeysRequest()
        assert request.algorithm == "RS256"
        assert request.key_size == 2048
        assert request.grace_period_hours == 24
        assert request.rotated_by is None

    @pytest.mark.parametrize("algorithm", ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"])
    def test_valid_algorithms(self, algorithm):
        """Test all valid algorithms."""
        request = RotateKeysRequest(algorithm=algorithm)
        assert request.algorithm == algorithm

    def test_invalid_algorithm(self):
        """Test invalid algorithm."""
        with pytest.raises(ValidationError):
            RotateKeysRequest(algorithm="HS256")

    def test_key_size_boundaries(self):
        """Test key_size boundaries."""
        assert RotateKeysRequest(key_size=2048).key_size == 2048
        assert RotateKeysRequest(key_size=4096).key_size == 4096
        with pytest.raises(ValidationError):
            RotateKeysRequest(key_size=1024)
        with pytest.raises(ValidationError):
            RotateKeysRequest(key_size=8192)

    def test_grace_period_boundaries(self):
        """Test grace_period_hours boundaries."""
        assert RotateKeysRequest(grace_period_hours=1).grace_period_hours == 1
        assert RotateKeysRequest(grace_period_hours=168).grace_period_hours == 168
        with pytest.raises(ValidationError):
            RotateKeysRequest(grace_period_hours=0)
        with pytest.raises(ValidationError):
            RotateKeysRequest(grace_period_hours=169)

    def test_custom_rotated_by(self):
        """Test custom rotated_by."""
        request = RotateKeysRequest(rotated_by="admin@example.com")
        assert request.rotated_by == "admin@example.com"

    def test_key_size_validator_odd(self):
        """Test key_size validator rejects odd values."""
        with pytest.raises(ValidationError):
            RotateKeysRequest(key_size=2049)


class TestRotateKeysResponse:
    """Tests for RotateKeysResponse schema."""

    @pytest.fixture
    def now(self):
        return datetime.now(timezone.utc)

    def test_valid_response(self, now):
        """Test valid rotate response."""
        response = RotateKeysResponse(
            new_kid="key_new",
            expires_at=now + timedelta(hours=24),
        )
        assert response.success is True
        assert response.new_kid == "key_new"
        assert response.message == "Keys rotated successfully"

    def test_required_fields(self):
        """Test required fields."""
        with pytest.raises(ValidationError) as exc_info:
            RotateKeysResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "new_kid" in errors
        assert "expires_at" in errors


class TestActivateKeyResponse:
    """Tests for ActivateKeyResponse."""

    def test_valid_response(self):
        """Test valid activate response."""
        response = ActivateKeyResponse(kid="key_123")
        assert response.success is True
        assert response.kid == "key_123"
        assert response.message == "Key activated successfully"


class TestDeactivateKeyResponse:
    """Tests for DeactivateKeyResponse."""

    def test_valid_response(self):
        """Test valid deactivate response."""
        response = DeactivateKeyResponse(kid="key_456")
        assert response.kid == "key_456"
        assert response.message == "Key deactivated successfully"


class TestCleanupExpiredResponse:
    """Tests for CleanupExpiredResponse."""

    def test_valid_response(self):
        """Test valid cleanup response."""
        response = CleanupExpiredResponse(deleted_count=5)
        assert response.success is True
        assert response.deleted_count == 5

    def test_zero_deleted(self):
        """Test zero deleted."""
        response = CleanupExpiredResponse(deleted_count=0)
        assert response.deleted_count == 0

    def test_required_fields(self):
        """Test required fields."""
        with pytest.raises(ValidationError) as exc_info:
            CleanupExpiredResponse()
        assert "deleted_count" in str(exc_info.value)


class TestJWKSMetricsResponse:
    """Tests for JWKSMetricsResponse."""

    def test_valid_metrics(self):
        """Test valid metrics response."""
        metrics = JWKSMetricsResponse(
            active_keys=2,
            expired_keys=1,
            total_keys=3,
        )
        assert metrics.active_keys == 2
        assert metrics.expired_keys == 1
        assert metrics.total_keys == 3
        assert metrics.keys_by_algorithm == {}
        assert metrics.grace_period_hours == 24
        assert metrics.algorithm == "RS256"
        assert metrics.cache_hit is False

    def test_with_keys_by_algorithm(self):
        """Test with algorithm distribution."""
        metrics = JWKSMetricsResponse(
            active_keys=3,
            expired_keys=0,
            total_keys=3,
            keys_by_algorithm={"RS256": 2, "ES256": 1},
        )
        assert metrics.keys_by_algorithm == {"RS256": 2, "ES256": 1}

    def test_required_fields(self):
        """Test required fields."""
        with pytest.raises(ValidationError) as exc_info:
            JWKSMetricsResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"active_keys", "expired_keys", "total_keys"}
        assert required_fields.issubset(errors)


class TestJWKSErrorResponse:
    """Tests for JWKSErrorResponse."""

    def test_valid_error(self):
        """Test valid error response."""
        error = JWKSErrorResponse(
            error="NOT_FOUND",
            message="Key not found",
        )
        assert error.error == "NOT_FOUND"
        assert error.message == "Key not found"
        assert error.timestamp is not None

    def test_with_details(self):
        """Test error with details."""
        error = JWKSErrorResponse(
            error="VALIDATION_ERROR",
            message="Invalid key size",
            details={"key_size": 1024, "min": 2048},
        )
        assert error.details == {"key_size": 1024, "min": 2048}

    def test_required_fields(self):
        """Test required fields."""
        with pytest.raises(ValidationError) as exc_info:
            JWKSErrorResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "error" in errors
        assert "message" in errors


class TestSchemasEdgeCases:
    """Tests for edge cases."""

    def test_extra_fields_ignored(self):
        """Test extra fields are ignored (x5c not in schema)."""
        key = JWKPublicData(kid="k", kty="RSA", alg="RS256", x5c=["cert1"])
        assert key.kid == "k"

    def test_rotate_request_key_size_even(self):
        """Test key_size must be even."""
        with pytest.raises(ValidationError):
            RotateKeysRequest(key_size=2049)

    def test_key_response_optional_fields_none(self):
        """Test optional fields default to None."""
        key = JWKKeyResponse(
            id=uuid4(), kid="k", key_type="RSA", algorithm="RS256",
            is_active=True, created_at=datetime.now(timezone.utc),
        )
        assert key.expires_at is None
        assert key.rotated_at is None
        assert key.key_size is None

    def test_key_list_total_matches_items(self):
        """Test total can differ from items length."""
        key = JWKKeyResponse(
            id=uuid4(), kid="k", key_type="RSA", algorithm="RS256",
            is_active=True, created_at=datetime.now(timezone.utc),
        )
        response = JWKKeyListResponse(items=[key], total=100)
        assert len(response.items) == 1
        assert response.total == 100