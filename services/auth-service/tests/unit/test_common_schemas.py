"""
Unit tests for Common Pydantic schemas.

Tests cover:
- BaseSchema, PaginationParams, PaginatedResponse
- MessageResponse, ErrorResponse
- SuccessResponse, TokenResponse, RefreshTokenResponse
- VerificationResponse, LogoutResponse
- UUIDSchema
- Field validation and constraints
- Default values and edge cases
"""

from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.common import (
    BaseSchema,
    ErrorResponse,
    LogoutResponse,
    MessageResponse,
    PaginatedResponse,
    PaginationParams,
    RefreshTokenResponse,
    SuccessResponse,
    TokenResponse,
    UUIDSchema,
    VerificationResponse,
)


class TestBaseSchema:
    """Tests for BaseSchema."""

    def test_base_schema_config(self):
        """Test BaseSchema has correct config."""
        config = BaseSchema.model_config
        
        assert config["from_attributes"] is True
        assert config["populate_by_name"] is True
        assert config["str_strip_whitespace"] is True
        assert config["extra"] == "ignore"

    def test_base_schema_strips_whitespace(self):
        """Test BaseSchema strips whitespace from string fields."""
        class TestSchema(BaseSchema):
            name: str
            email: str
        
        obj = TestSchema(name="  John  ", email="  user@example.com  ")
        
        assert obj.name == "John"
        assert obj.email == "user@example.com"


class TestPaginationParams:
    """Tests for PaginationParams schema."""

    def test_valid_pagination_params(self):
        """Test creating valid pagination parameters."""
        params = PaginationParams(limit=50, offset=10)
        
        assert params.limit == 50
        assert params.offset == 10

    def test_pagination_params_defaults(self):
        """Test default values."""
        params = PaginationParams()
        
        assert params.limit == 20
        assert params.offset == 0

    def test_pagination_params_limit_min(self):
        """Test limit minimum value is 1."""
        with pytest.raises(ValidationError) as exc_info:
            PaginationParams(limit=0)
        
        error = exc_info.value.errors()[0]
        assert error["loc"][0] == "limit"
        assert "greater_than_equal" in error["type"]

    def test_pagination_params_limit_max(self):
        """Test limit maximum value is 100."""
        with pytest.raises(ValidationError) as exc_info:
            PaginationParams(limit=101)
        
        error = exc_info.value.errors()[0]
        assert "less_than_equal" in error["type"]

    def test_pagination_params_limit_boundary_values(self):
        """Test limit at boundary values."""
        params_min = PaginationParams(limit=1)
        params_max = PaginationParams(limit=100)
        
        assert params_min.limit == 1
        assert params_max.limit == 100

    def test_pagination_params_offset_min(self):
        """Test offset minimum value is 0."""
        with pytest.raises(ValidationError) as exc_info:
            PaginationParams(offset=-1)
        
        error = exc_info.value.errors()[0]
        assert error["loc"][0] == "offset"
        assert "greater_than_equal" in error["type"]

    def test_pagination_params_offset_zero(self):
        """Test offset can be zero."""
        params = PaginationParams(offset=0)
        assert params.offset == 0


class TestPaginatedResponse:
    """Tests for PaginatedResponse schema."""

    def test_valid_paginated_response(self):
        """Test creating valid paginated response."""
        items = [{"id": 1}, {"id": 2}]
        
        response = PaginatedResponse(
            items=items,
            total=100,
            limit=20,
            offset=0,
        )
        
        assert response.items == items
        assert response.total == 100
        assert response.limit == 20
        assert response.offset == 0

    def test_paginated_response_empty_items(self):
        """Test paginated response with empty items list."""
        response = PaginatedResponse(items=[], total=0, limit=20, offset=0)
        
        assert response.items == []
        assert response.total == 0

    def test_paginated_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            PaginatedResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"items", "total", "limit", "offset"}
        assert required_fields.issubset(errors)

    def test_paginated_response_create_method(self):
        """Test create classmethod."""
        items = [1, 2, 3]
        response = PaginatedResponse.create(items=items, total=10, limit=5, offset=0)
        
        assert response.items == items
        assert response.total == 10
        assert response.limit == 5
        assert response.offset == 0

    def test_paginated_response_generic_types(self):
        """Test paginated response with different types."""
        str_response = PaginatedResponse[str](items=["a", "b"], total=2, limit=10, offset=0)
        int_response = PaginatedResponse[int](items=[1, 2], total=2, limit=10, offset=0)
        
        assert str_response.items == ["a", "b"]
        assert int_response.items == [1, 2]


class TestMessageResponse:
    """Tests for MessageResponse schema."""

    def test_valid_message_response(self):
        """Test creating valid message response."""
        response = MessageResponse(success=True, message="Operation completed")
        
        assert response.success is True
        assert response.message == "Operation completed"
        assert response.details is None

    def test_message_response_default_success(self):
        """Test success defaults to True."""
        response = MessageResponse(message="Test")
        
        assert response.success is True

    def test_message_response_with_details(self):
        """Test message response with additional details."""
        response = MessageResponse(
            success=False,
            message="Operation failed",
            details={"error_code": "ERR_001"},
        )
        
        assert response.success is False
        assert response.details == {"error_code": "ERR_001"}

    def test_message_response_required_fields(self):
        """Test message is required."""
        with pytest.raises(ValidationError) as exc_info:
            MessageResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "message" in errors


class TestErrorResponse:
    """Tests for ErrorResponse schema."""

    def test_valid_error_response(self):
        """Test creating valid error response."""
        response = ErrorResponse(
            error="UNAUTHORIZED",
            detail="Invalid email or password",
            code="AUTH_001",
        )
        
        assert response.error == "UNAUTHORIZED"
        assert response.detail == "Invalid email or password"
        assert response.code == "AUTH_001"

    def test_error_response_minimal(self):
        """Test error response with only required field."""
        response = ErrorResponse(error="BAD_REQUEST")
        
        assert response.error == "BAD_REQUEST"
        assert response.detail is None
        assert response.code is None

    def test_error_response_required_fields(self):
        """Test error field is required."""
        with pytest.raises(ValidationError) as exc_info:
            ErrorResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "error" in errors


class TestSuccessResponse:
    """Tests for SuccessResponse schema."""

    def test_valid_success_response(self):
        """Test creating valid success response."""
        user_id = str(uuid4())
        response = SuccessResponse(
            success=True,
            message="Operation completed successfully",
            data={"user_id": user_id},
        )
        
        assert response.success is True
        assert response.message == "Operation completed successfully"
        assert response.data == {"user_id": user_id}

    def test_success_response_defaults(self):
        """Test default values."""
        response = SuccessResponse(message="Done")
        
        assert response.success is True
        assert response.data is None

    def test_success_response_required_fields(self):
        """Test message is required."""
        with pytest.raises(ValidationError) as exc_info:
            SuccessResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "message" in errors


class TestTokenResponse:
    """Tests for TokenResponse schema."""

    def test_valid_token_response(self):
        """Test creating valid token response."""
        response = TokenResponse(
            access_token="eyJhbGciOiJSUzI1NiIs...",
            expires_in=900,
        )
        
        assert response.access_token == "eyJhbGciOiJSUzI1NiIs..."
        assert response.token_type == "bearer"
        assert response.expires_in == 900
        assert response.refresh_token is None

    def test_token_response_with_refresh_token(self):
        """Test token response with refresh token."""
        response = TokenResponse(
            access_token="access_123",
            expires_in=900,
            refresh_token="refresh_456",
        )
        
        assert response.refresh_token == "refresh_456"

    def test_token_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            TokenResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"access_token", "expires_in"}
        assert required_fields.issubset(errors)

    def test_token_response_custom_token_type(self):
        """Test token_type can be overridden."""
        response = TokenResponse(
            access_token="token123",
            token_type="custom",
            expires_in=3600,
        )
        assert response.token_type == "custom"


class TestRefreshTokenResponse:
    """Tests for RefreshTokenResponse schema."""

    def test_valid_refresh_token_response(self):
        """Test creating valid refresh token response."""
        response = RefreshTokenResponse(
            access_token="new_access_token",
            expires_in=900,
        )
        
        assert response.access_token == "new_access_token"
        assert response.token_type == "bearer"
        assert response.expires_in == 900

    def test_refresh_token_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            RefreshTokenResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"access_token", "expires_in"}
        assert required_fields.issubset(errors)


class TestVerificationResponse:
    """Tests for VerificationResponse schema."""

    def test_valid_verification_response(self):
        """Test creating valid verification response."""
        response = VerificationResponse(
            success=True,
            message="Email verified successfully",
        )
        
        assert response.success is True
        assert response.message == "Email verified successfully"
        assert response.verified is True

    def test_verification_response_failed(self):
        """Test verification response with failure."""
        response = VerificationResponse(
            success=False,
            message="Verification failed",
            verified=False,
        )
        
        assert response.success is False
        assert response.verified is False

    def test_verification_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            VerificationResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"success", "message"}
        assert required_fields.issubset(errors)


class TestLogoutResponse:
    """Tests for LogoutResponse schema."""

    def test_valid_logout_response(self):
        """Test creating valid logout response."""
        response = LogoutResponse(
            success=True,
            message="Successfully logged out",
        )
        
        assert response.success is True
        assert response.message == "Successfully logged out"
        assert response.revoked_tokens is None

    def test_logout_response_with_revoked_count(self):
        """Test logout response with revoked tokens count."""
        response = LogoutResponse(
            success=True,
            message="Logged out from all devices",
            revoked_tokens=5,
        )
        
        assert response.revoked_tokens == 5

    def test_logout_response_required_fields(self):
        """Test message is required."""
        with pytest.raises(ValidationError) as exc_info:
            LogoutResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "message" in errors


class TestUUIDSchema:
    """Tests for UUIDSchema."""

    def test_valid_uuid_schema(self):
        """Test creating valid UUID schema."""
        now = datetime.now()
        user_id = uuid4()
        
        schema = UUIDSchema(
            id=user_id,
            created_at=now,
            updated_at=now,
        )
        
        assert schema.id == user_id
        assert schema.created_at == now
        assert schema.updated_at == now

    def test_uuid_schema_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            UUIDSchema()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"id", "created_at", "updated_at"}
        assert required_fields.issubset(errors)

    def test_uuid_schema_uuid_validation(self):
        """Test id must be valid UUID."""
        now = datetime.now()
        
        with pytest.raises(ValidationError):
            UUIDSchema(id="not-a-uuid", created_at=now, updated_at=now)