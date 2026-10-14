"""
Unit tests for Internal API Pydantic schemas.

Tests cover:
- CreateUserRequest/Response
- DeleteUserRequest/Response
- UpdatePasswordRequest/Response
- RevokeAllSessionsRequest/Response
- UserExistsResponse
- SessionsCountResponse
- ErrorResponse
- BaseInternalModel config
- Field validation, types, defaults
- Serialization/deserialization
- Edge cases and required fields
"""

from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.schemas.internal import (
    BaseInternalModel,
    CreateUserRequest,
    CreateUserResponse,
    DeleteUserRequest,
    DeleteUserResponse,
    ErrorResponse,
    RevokeAllSessionsRequest,
    RevokeAllSessionsResponse,
    SessionsCountResponse,
    UpdatePasswordRequest,
    UpdatePasswordResponse,
    UserExistsResponse,
)


class TestBaseInternalModel:
    """Tests for BaseInternalModel."""

    def test_base_model_config(self):
        """Test BaseInternalModel has correct config."""
        config = BaseInternalModel.model_config
        assert config["extra"] == "allow"
        assert config["from_attributes"] is True


class TestCreateUserRequest:
    """Tests for CreateUserRequest schema."""

    @pytest.fixture
    def user_id(self):
        return uuid4()

    def test_valid_create_request(self, user_id):
        """Test creating valid create user request."""
        request = CreateUserRequest(
            user_id=user_id,
            email_hash="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            email="user@example.com",
            password_hash="$2b$12$KIXxYz9K.3yL9kZ9kZ9kZ9kZ9kZ9kZ9kZ9kZ9kZ9kZ9kZ9kZ9kZ",
        )

        assert request.user_id == user_id
        assert request.email_hash == "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        assert request.email == "user@example.com"
        assert request.is_active is True
        assert request.is_email_verified is False
        assert request.metadata is None

    def test_create_request_with_metadata(self, user_id):
        """Test create request with metadata."""
        metadata = {"source": "import", "role": "admin"}
        request = CreateUserRequest(
            user_id=user_id,
            email_hash="hash",
            email="test@test.com",
            password_hash="pass",
            metadata=metadata,
        )
        assert request.metadata == metadata

    def test_create_request_required_fields(self):
        """Test all required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            CreateUserRequest()

        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"user_id", "email_hash", "email", "password_hash"}
        assert required_fields.issubset(errors)

    def test_create_request_uuid_validation(self):
        """Test user_id must be valid UUID."""
        with pytest.raises(ValidationError):
            CreateUserRequest(
                user_id="not-a-uuid",
                email_hash="hash",
                email="test@test.com",
                password_hash="pass",
            )

    def test_create_request_boolean_defaults(self, user_id):
        """Test boolean field defaults."""
        request = CreateUserRequest(
            user_id=user_id,
            email_hash="hash",
            email="test@test.com",
            password_hash="pass",
        )
        assert request.is_active is True
        assert request.is_email_verified is False

    def test_create_request_custom_booleans(self, user_id):
        """Test custom boolean values."""
        request = CreateUserRequest(
            user_id=user_id,
            email_hash="hash",
            email="test@test.com",
            password_hash="pass",
            is_active=False,
            is_email_verified=True,
        )
        assert request.is_active is False
        assert request.is_email_verified is True


class TestCreateUserResponse:
    """Tests for CreateUserResponse schema."""

    def test_valid_create_response(self):
        """Test creating valid create user response."""
        user_id = str(uuid4())
        response = CreateUserResponse(user_id=user_id)
        assert response.success is True
        assert response.user_id == user_id
        assert response.message == "User created successfully"

    def test_create_response_custom_message(self):
        """Test create response with custom message."""
        response = CreateUserResponse(
            user_id=str(uuid4()),
            message="Custom message",
        )
        assert response.message == "Custom message"

    def test_create_response_failure(self):
        """Test create response with failure."""
        response = CreateUserResponse(
            success=False,
            user_id=str(uuid4()),
            message="User already exists",
        )
        assert response.success is False

    def test_create_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            CreateUserResponse()

        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "user_id" in errors


class TestDeleteUserRequest:
    """Tests for DeleteUserRequest schema."""

    def test_valid_delete_request(self):
        """Test creating valid delete user request."""
        user_id = uuid4()
        request = DeleteUserRequest(user_id=user_id)
        assert request.user_id == user_id
        assert request.except_session_id is None

    def test_delete_request_with_except_session(self):
        """Test delete request with except_session_id."""
        request = DeleteUserRequest(
            user_id=uuid4(),
            except_session_id="session_123",
        )
        assert request.except_session_id == "session_123"

    def test_delete_request_required_field(self):
        """Test user_id field is required."""
        with pytest.raises(ValidationError) as exc_info:
            DeleteUserRequest()
        assert "user_id" in str(exc_info.value)


class TestDeleteUserResponse:
    """Tests for DeleteUserResponse schema."""

    def test_valid_delete_response(self):
        """Test creating valid delete user response."""
        response = DeleteUserResponse(user_id=str(uuid4()))
        assert response.success is True
        assert response.revoked_sessions_count == 0

    def test_delete_response_with_count(self):
        """Test delete response with revoked sessions count."""
        response = DeleteUserResponse(
            user_id=str(uuid4()),
            revoked_sessions_count=5,
            message="User deleted, 5 sessions revoked",
        )
        assert response.revoked_sessions_count == 5

    def test_delete_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            DeleteUserResponse()
        assert "user_id" in str(exc_info.value)


class TestUpdatePasswordRequest:
    """Tests for UpdatePasswordRequest schema."""

    def test_valid_update_request(self):
        """Test creating valid password update request."""
        request = UpdatePasswordRequest(
            user_id=uuid4(),
            new_password_hash="hashed_password",
        )
        assert request.new_password_hash == "hashed_password"
        assert request.except_session_id is None

    def test_update_request_with_except_session(self):
        """Test update request with except_session_id."""
        request = UpdatePasswordRequest(
            user_id=uuid4(),
            new_password_hash="hashed",
            except_session_id="session_123",
        )
        assert request.except_session_id == "session_123"

    def test_update_request_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            UpdatePasswordRequest()

        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"user_id", "new_password_hash"}
        assert required_fields.issubset(errors)


class TestUpdatePasswordResponse:
    """Tests for UpdatePasswordResponse schema."""

    def test_valid_update_response(self):
        """Test creating valid password update response."""
        response = UpdatePasswordResponse(user_id=str(uuid4()))
        assert response.success is True
        assert response.revoked_sessions_count == 0

    def test_update_response_with_count(self):
        """Test update response with revoked sessions count."""
        response = UpdatePasswordResponse(
            user_id=str(uuid4()),
            revoked_sessions_count=3,
        )
        assert response.revoked_sessions_count == 3

    def test_update_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            UpdatePasswordResponse()
        assert "user_id" in str(exc_info.value)


class TestRevokeAllSessionsRequest:
    """Tests for RevokeAllSessionsRequest schema."""

    def test_valid_revoke_request(self):
        """Test creating valid sessions revoke request."""
        user_id = uuid4()
        request = RevokeAllSessionsRequest(
            user_id=user_id,
            except_session_id="current_session",
            reason="Password changed",
        )
        assert request.user_id == user_id
        assert request.except_session_id == "current_session"
        assert request.reason == "Password changed"
        assert request.publish_event is True

    def test_revoke_request_minimal(self):
        """Test revoke request with only required field."""
        request = RevokeAllSessionsRequest(user_id=uuid4())
        assert request.except_session_id is None
        assert request.reason is None
        assert request.publish_event is True

    def test_revoke_request_publish_event_false(self):
        """Test revoke request with publish_event=False."""
        request = RevokeAllSessionsRequest(
            user_id=uuid4(),
            publish_event=False,
        )
        assert request.publish_event is False

    def test_revoke_request_required_field(self):
        """Test user_id field is required."""
        with pytest.raises(ValidationError) as exc_info:
            RevokeAllSessionsRequest()
        assert "user_id" in str(exc_info.value)


class TestRevokeAllSessionsResponse:
    """Tests for RevokeAllSessionsResponse schema."""

    def test_valid_revoke_response(self):
        """Test creating valid sessions revoke response."""
        response = RevokeAllSessionsResponse(
            user_id=str(uuid4()),
            revoked_sessions_count=5,
        )
        assert response.success is True
        assert response.revoked_sessions_count == 5

    def test_revoke_response_zero_sessions(self):
        """Test revoke response with zero sessions revoked."""
        response = RevokeAllSessionsResponse(
            user_id=str(uuid4()),
            revoked_sessions_count=0,
        )
        assert response.revoked_sessions_count == 0

    def test_revoke_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            RevokeAllSessionsResponse()
        assert "user_id" in str(exc_info.value)


class TestUserExistsResponse:
    """Tests for UserExistsResponse schema."""

    def test_valid_exists_response(self):
        """Test exists response with all fields."""
        user_id = str(uuid4())
        response = UserExistsResponse(
            user_id=user_id,
            exists=True,
            is_active=True,
            is_email_verified=True,
        )
        assert response.user_id == user_id
        assert response.exists is True
        assert response.is_active is True
        assert response.is_email_verified is True

    def test_exists_response_not_found(self):
        """Test exists response for non-existent user."""
        response = UserExistsResponse(user_id=str(uuid4()))
        assert response.exists is False
        assert response.is_active is None
        assert response.is_email_verified is None

    def test_exists_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            UserExistsResponse()
        assert "user_id" in str(exc_info.value)


class TestSessionsCountResponse:
    """Tests for SessionsCountResponse schema."""

    def test_valid_sessions_count_response(self):
        """Test creating valid sessions count response."""
        response = SessionsCountResponse(
            user_id=str(uuid4()),
            active_sessions_count=3,
        )
        assert response.active_sessions_count == 3

    def test_sessions_count_zero(self):
        """Test sessions count with zero."""
        response = SessionsCountResponse(
            user_id=str(uuid4()),
            active_sessions_count=0,
        )
        assert response.active_sessions_count == 0

    def test_sessions_count_default(self):
        """Test sessions count default value."""
        response = SessionsCountResponse(user_id=str(uuid4()))
        assert response.active_sessions_count == 0

    def test_sessions_count_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            SessionsCountResponse()
        assert "user_id" in str(exc_info.value)


class TestErrorResponse:
    """Tests for ErrorResponse schema."""

    def test_valid_error_response(self):
        """Test creating valid error response."""
        response = ErrorResponse(detail="Something went wrong")
        assert response.detail == "Something went wrong"
        assert response.error_code is None

    def test_error_response_with_code(self):
        """Test error response with error code."""
        response = ErrorResponse(
            detail="Not found",
            error_code="NOT_FOUND",
        )
        assert response.error_code == "NOT_FOUND"

    def test_error_response_required_fields(self):
        """Test detail field is required."""
        with pytest.raises(ValidationError) as exc_info:
            ErrorResponse()
        assert "detail" in str(exc_info.value)


class TestInternalSchemasEdgeCases:
    """Tests for edge cases across internal schemas."""

    def test_uuid_serialization(self):
        """Test UUID is preserved as UUID in model_dump (not converted to string)."""
        user_id = uuid4()
        request = CreateUserRequest(
            user_id=user_id,
            email_hash="hash",
            email="test@test.com",
            password_hash="pass",
        )
        data = request.model_dump()
        assert data["user_id"] == user_id

    def test_long_strings(self):
        """Test handling of long strings."""
        long_msg = "x" * 1000
        response = CreateUserResponse(user_id=str(uuid4()), message=long_msg)
        assert response.message == long_msg

    def test_empty_strings(self):
        """Test empty strings are allowed."""
        request = CreateUserRequest(
            user_id=uuid4(),
            email_hash="",
            email="",
            password_hash="",
        )
        assert request.email_hash == ""

    def test_extra_fields_allowed(self):
        """Test extra fields are allowed in base model."""
        response = CreateUserResponse(
            user_id=str(uuid4()),
            extra_field="should be allowed",
        )
        assert response.user_id is not None