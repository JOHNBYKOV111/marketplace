"""
Unit tests for Admin Pydantic schemas.

Tests cover:
- Field validation (types, constraints, defaults)
- Required vs optional fields
- Field constraints (min_length, max_length)
- Serialization/deserialization
- Edge cases and boundary values

Note: Pydantic V2 uses different error type names:
- 'string_too_short' instead of 'min_length'
- 'string_too_long' instead of 'max_length'
"""

from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.schemas.admin import (
    BlockRequest,
    BlockResponse,
    AdminUserResponse,
    UnblockResponse,
    AdminMetricsResponse,
)


class TestAdminUserResponse:
    """Tests for AdminUserResponse schema (extends UserResponse)."""

    @pytest.fixture
    def valid_admin_user_data(self) -> dict:
        """Generate valid admin user response data."""
        return {
            "id": uuid4(),
            "email": "admin@example.com",
            "email_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "is_active": True,
            "is_email_verified": True,
            "is_superuser": True,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "password_hash": "hashed_admin_password",
        }

    def test_valid_admin_user_response(self, valid_admin_user_data: dict):
        """Test creating valid AdminUserResponse."""
        response = AdminUserResponse(**valid_admin_user_data)
        
        assert response.id == valid_admin_user_data["id"]
        assert response.email == valid_admin_user_data["email"]
        assert response.email_hash == valid_admin_user_data["email_hash"]
        assert response.is_active is True
        assert response.is_email_verified is True
        assert response.is_superuser is True
        assert response.created_at == valid_admin_user_data["created_at"]
        assert response.updated_at == valid_admin_user_data["updated_at"]
        assert response.password_hash == valid_admin_user_data["password_hash"]

    def test_admin_user_response_required_fields(self):
        """Test all strictly required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            AdminUserResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {
            "id", "created_at", "updated_at", "email",
            "is_active", "is_email_verified", "is_superuser",
        }
        assert required_fields.issubset(errors)

    def test_admin_user_response_optional_password_hash(self, valid_admin_user_data: dict):
        """Test password_hash field is optional (admin-only field)."""
        valid_admin_user_data.pop("password_hash")
        response = AdminUserResponse(**valid_admin_user_data)
        
        assert response.password_hash is None

    def test_admin_user_response_uuid_validation(self, valid_admin_user_data: dict):
        """Test id field must be a valid UUID."""
        valid_admin_user_data["id"] = "not-a-uuid"
        
        with pytest.raises(ValidationError) as exc_info:
            AdminUserResponse(**valid_admin_user_data)
        
        assert "uuid_parsing" in str(exc_info.value).lower() or "id" in str(exc_info.value)

    def test_admin_user_response_boolean_fields(self, valid_admin_user_data: dict):
        """Test boolean fields accept boolean values."""
        valid_admin_user_data["is_active"] = False
        valid_admin_user_data["is_email_verified"] = False
        valid_admin_user_data["is_superuser"] = False
        
        response = AdminUserResponse(**valid_admin_user_data)
        
        assert response.is_active is False
        assert response.is_email_verified is False
        assert response.is_superuser is False

    def test_admin_user_response_datetime_types(self, valid_admin_user_data: dict):
        """Test datetime fields are properly typed."""
        response = AdminUserResponse(**valid_admin_user_data)
        
        assert isinstance(response.created_at, datetime)
        assert isinstance(response.updated_at, datetime)


class TestBlockRequest:
    """Tests for BlockRequest schema."""

    def test_valid_block_request(self):
        """Test creating valid block request."""
        reason = "Suspicious activity detected"
        request = BlockRequest(reason=reason)
        
        assert request.reason == reason

    def test_block_request_min_length_constraint(self):
        """Test reason must be at least 1 character."""
        with pytest.raises(ValidationError) as exc_info:
            BlockRequest(reason="")
        
        error = exc_info.value.errors()[0]
        assert error["loc"][0] == "reason"
        assert "string_too_short" in error["type"]

    def test_block_request_max_length_constraint(self):
        """Test reason cannot exceed 500 characters."""
        long_reason = "a" * 501
        
        with pytest.raises(ValidationError) as exc_info:
            BlockRequest(reason=long_reason)
        
        error = exc_info.value.errors()[0]
        assert error["loc"][0] == "reason"
        assert "string_too_long" in error["type"]

    def test_block_request_exact_boundary_values(self):
        """Test reason at boundary values (1 and 500 chars)."""
        request_min = BlockRequest(reason="a")
        assert request_min.reason == "a"
        
        reason_500 = "a" * 500
        request_max = BlockRequest(reason=reason_500)
        assert request_max.reason == reason_500

    def test_block_request_whitespace_reason(self):
        """Test reason with whitespace characters — model strips whitespace."""
        reason = "   User violated terms   "
        request = BlockRequest(reason=reason)
        
        # BlockRequest auto-strips whitespace
        assert request.reason == "User violated terms"

    def test_block_request_required_field(self):
        """Test reason field is required."""
        with pytest.raises(ValidationError) as exc_info:
            BlockRequest()
        
        error = exc_info.value.errors()[0]
        assert error["loc"][0] == "reason"
        assert error["type"] == "missing"


class TestBlockResponse:
    """Tests for BlockResponse schema."""

    @pytest.fixture
    def valid_block_response_data(self) -> dict:
        """Generate valid block response data."""
        return {
            "success": True,
            "message": "User blocked successfully",
            "user_id": uuid4(),
        }

    def test_valid_block_response(self, valid_block_response_data: dict):
        """Test creating valid block response."""
        response = BlockResponse(**valid_block_response_data)
        
        assert response.success is True
        assert response.message == "User blocked successfully"
        assert isinstance(response.user_id, UUID)

    def test_block_response_required_fields(self):
        """Test required fields must be provided (without defaults)."""
        with pytest.raises(ValidationError) as exc_info:
            BlockResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"message", "user_id"}
        assert required_fields.issubset(errors)

    def test_block_response_boolean_success(self, valid_block_response_data: dict):
        """Test success field accepts boolean values."""
        valid_block_response_data["success"] = False
        response = BlockResponse(**valid_block_response_data)
        
        assert response.success is False

    def test_block_response_message_string(self):
        """Test message field accepts string values."""
        response = BlockResponse(
            success=True,
            message="Custom block message",
            user_id=uuid4(),
        )
        
        assert response.message == "Custom block message"


class TestUnblockResponse:
    """Tests for UnblockResponse schema."""

    @pytest.fixture
    def valid_unblock_response_data(self) -> dict:
        """Generate valid unblock response data."""
        return {
            "success": True,
            "message": "User unblocked successfully",
            "user_id": uuid4(),
        }

    def test_valid_unblock_response(self, valid_unblock_response_data: dict):
        """Test creating valid unblock response."""
        response = UnblockResponse(**valid_unblock_response_data)
        
        assert response.success is True
        assert response.message == "User unblocked successfully"
        assert isinstance(response.user_id, UUID)

    def test_unblock_response_required_fields(self):
        """Test required fields must be provided (without defaults)."""
        with pytest.raises(ValidationError) as exc_info:
            UnblockResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"message", "user_id"}
        assert required_fields.issubset(errors)

    def test_unblock_response_boolean_success(self, valid_unblock_response_data: dict):
        """Test success field accepts boolean values."""
        valid_unblock_response_data["success"] = False
        response = UnblockResponse(**valid_unblock_response_data)
        
        assert response.success is False


class TestAdminMetricsResponse:
    """Tests for AdminMetricsResponse schema."""

    @pytest.fixture
    def valid_metrics_data(self) -> dict:
        """Generate valid metrics response data."""
        return {
            "total_users": 1500,
            "active_users": 1200,
            "blocked_users": 50,
            "verified_users": 1000,
            "superusers": 5,
        }

    def test_valid_metrics_response(self, valid_metrics_data: dict):
        """Test creating valid metrics response."""
        response = AdminMetricsResponse(**valid_metrics_data)
        
        assert response.total_users == 1500
        assert response.active_users == 1200
        assert response.blocked_users == 50
        assert response.verified_users == 1000
        assert response.superusers == 5

    def test_metrics_response_required_fields(self):
        """Test all fields are required."""
        with pytest.raises(ValidationError) as exc_info:
            AdminMetricsResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"total_users", "active_users", "blocked_users", "verified_users", "superusers"}
        assert required_fields.issubset(errors)

    def test_metrics_response_zero_values(self):
        """Test metrics can be zero."""
        response = AdminMetricsResponse(
            total_users=0,
            active_users=0,
            blocked_users=0,
            verified_users=0,
            superusers=0,
        )
        
        assert response.total_users == 0
        assert response.active_users == 0

    def test_metrics_response_negative_blocked_users(self):
        """Test blocked_users accepts negative values (Pydantic allows ints)."""
        response = AdminMetricsResponse(
            total_users=100,
            active_users=90,
            blocked_users=-5,
            verified_users=80,
            superusers=2,
        )
        
        assert response.blocked_users == -5