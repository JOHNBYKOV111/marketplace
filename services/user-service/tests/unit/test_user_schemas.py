"""
Unit tests for User Pydantic schemas.

Tests cover:
- UserCreate (email, password validation, defaults)
- UserUpdate (optional fields, partial updates)
- UserResponse (serialization, model_validate)
- UserProfileResponse (all profile fields)
- UserListResponse (items, total, limit, offset)
- UserUpdateRequest (email, username, is_active)
- DeleteAccountRequest / DeleteAccountResponse
- PasswordChangeRequest
- SessionInfoResponse / SessionListResponse
- Edge cases and boundary values
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.schemas.user import (
    DeleteAccountRequest,
    DeleteAccountResponse,
    PasswordChangeRequest,
    SessionInfoResponse,
    SessionListResponse,
    UserCreate,
    UserListResponse,
    UserProfileResponse,
    UserResponse,
    UserUpdate,
    UserUpdateRequest,
)


# ==================== FIXTURES ====================

@pytest.fixture
def user_id():
    """Generate a random user ID."""
    return uuid4()


@pytest.fixture
def now():
    """Current UTC datetime."""
    return datetime.now(timezone.utc)


# ==================== USER CREATE TESTS ====================

class TestUserCreate:
    """Tests for UserCreate schema."""

    def test_valid_user_create(self):
        """Test valid user creation schema."""
        user = UserCreate(email="user@example.com", password="SecurePass123!")
        assert user.email == "user@example.com"
        assert user.password == "SecurePass123!"

    def test_user_create_email_required(self):
        """Test email is required."""
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(password="SecurePass123!")
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "email" in errors

    def test_user_create_password_required(self):
        """Test password is required."""
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(email="user@example.com")
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "password" in errors

    def test_user_create_invalid_email(self):
        """Test invalid email raises validation error."""
        with pytest.raises(ValidationError):
            UserCreate(email="not-an-email", password="SecurePass123!")

    def test_user_create_password_min_length(self):
        """Test password below minimum length."""
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(email="user@example.com", password="Short1!")
        error_types = {err["type"] for err in exc_info.value.errors()}
        assert "string_too_short" in error_types or "value_error" in error_types

    def test_user_create_password_max_length(self):
        """Test password above maximum length."""
        long_password = "A" * 129
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(email="user@example.com", password=long_password)
        error_types = {err["type"] for err in exc_info.value.errors()}
        assert "string_too_long" in error_types or "value_error" in error_types

    def test_user_create_password_exact_min_length(self):
        """Test password at exact minimum length."""
        user = UserCreate(email="user@example.com", password="12345678")
        assert len(user.password) == 8

    def test_user_create_password_exact_max_length(self):
        """Test password at exact maximum length."""
        password = "A" * 128
        user = UserCreate(email="user@example.com", password=password)
        assert len(user.password) == 128


# ==================== USER UPDATE TESTS ====================

class TestUserUpdate:
    """Tests for UserUpdate schema."""

    def test_valid_user_update_all_fields(self):
        """Test user update with all fields."""
        user = UserUpdate(
            email="new@example.com",
            password="NewSecurePass123!",
            is_active=True,
            is_email_verified=True,
            is_superuser=False,
        )
        assert user.email == "new@example.com"
        assert user.password == "NewSecurePass123!"
        assert user.is_active is True
        assert user.is_email_verified is True
        assert user.is_superuser is False

    def test_user_update_empty(self):
        """Test user update with no fields (all optional)."""
        user = UserUpdate()
        assert user.email is None
        assert user.password is None
        assert user.is_active is None
        assert user.is_email_verified is None
        assert user.is_superuser is None

    def test_user_update_partial_fields(self):
        """Test user update with partial fields."""
        user = UserUpdate(is_active=False)
        assert user.is_active is False
        assert user.email is None

    def test_user_update_invalid_email(self):
        """Test invalid email in update."""
        with pytest.raises(ValidationError):
            UserUpdate(email="bad-email")

    def test_user_update_password_too_short(self):
        """Test password too short in update."""
        with pytest.raises(ValidationError) as exc_info:
            UserUpdate(password="1234567")
        error_types = {err["type"] for err in exc_info.value.errors()}
        assert "string_too_short" in error_types or "value_error" in error_types


# ==================== USER RESPONSE TESTS ====================

class TestUserResponse:
    """Tests for UserResponse schema."""

    def test_valid_user_response(self, user_id, now):
        """Test valid user response with all fields."""
        response = UserResponse(
            id=user_id,
            email="user@example.com",
            is_active=True,
            is_email_verified=True,
            is_superuser=False,
            email_hash="a" * 64,
            created_at=now,
            updated_at=now,
        )
        assert response.id == user_id
        assert response.email == "user@example.com"
        assert response.is_active is True
        assert response.is_superuser is False

    def test_user_response_email_hash_optional(self, user_id, now):
        """Test email_hash is auto-generated when email is provided."""
        response = UserResponse(
            id=user_id,
            email="user@example.com",
            is_active=True,
            is_email_verified=False,
            is_superuser=False,
            created_at=now,
            updated_at=now,
        )
        assert response.email_hash is not None
        assert len(response.email_hash) == 64

    def test_user_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            UserResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required = {"is_active", "is_email_verified", "is_superuser"}
        assert required.issubset(errors)

    def test_model_validate_creates_valid_response(self, user_id, now):
        """Test model_validate creates UserResponse from ORM model."""
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.email = "test@example.com"
        mock_user.first_name = "Test"
        mock_user.last_name = "User"
        mock_user.is_active = True
        mock_user.is_email_verified = True
        mock_user.is_superuser = False
        mock_user.created_at = now
        mock_user.updated_at = now

        response = UserResponse.model_validate(mock_user)
        assert response.id == user_id
        assert response.email == "test@example.com"
        assert response.email_hash is not None
        assert len(response.email_hash) == 64

    def test_model_validate_email_hash_matches_model(self, user_id, now):
        """Test model_validate generates correct email_hash from model email."""
        import hashlib
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.email = "hashcheck@example.com"
        mock_user.first_name = "Hash"
        mock_user.last_name = "Check"
        mock_user.is_active = True
        mock_user.is_email_verified = False
        mock_user.is_superuser = False
        mock_user.created_at = now
        mock_user.updated_at = now

        response = UserResponse.model_validate(mock_user)
        expected_hash = hashlib.sha256("hashcheck@example.com".encode()).hexdigest()
        assert response.email_hash == expected_hash

    def test_model_validate_none_email(self, user_id, now):
        """Test model_validate with None email."""
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.email = None
        mock_user.first_name = None
        mock_user.last_name = None
        mock_user.is_active = True
        mock_user.is_email_verified = False
        mock_user.is_superuser = False
        mock_user.created_at = now
        mock_user.updated_at = now

        response = UserResponse.model_validate(mock_user)
        assert response.email_hash is None


# ==================== USER PROFILE RESPONSE TESTS ====================

class TestUserProfileResponse:
    """Tests for UserProfileResponse schema."""

    def test_valid_profile_response(self, user_id, now):
        """Test valid profile response with all fields."""
        response = UserProfileResponse(
            id=user_id,
            email="user@example.com",
            username="john_doe",
            is_active=True,
            is_email_verified=True,
            is_superuser=False,
            created_at=now,
            updated_at=now,
            last_login_at=now,
        )
        assert response.id == user_id
        assert response.username == "john_doe"
        assert response.last_login_at == now

    def test_profile_response_minimal(self, user_id, now):
        """Test profile response with only required fields."""
        response = UserProfileResponse(
            id=user_id,
            email="user@example.com",
            is_active=True,
            is_email_verified=True,
            is_superuser=False,
            created_at=now,
            updated_at=now,
        )
        assert response.username is None
        assert response.last_login_at is None

    def test_profile_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            UserProfileResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required = {"is_active", "is_email_verified", "is_superuser", "created_at", "updated_at"}
        assert required.issubset(errors)


# ==================== USER UPDATE REQUEST TESTS ====================

class TestUserUpdateRequest:
    """Tests for UserUpdateRequest schema."""

    def test_valid_update_request_all_fields(self):
        """Test update request with all fields."""
        request = UserUpdateRequest(
            email="new@example.com",
            username="new_username",
            is_active=True,
        )
        assert request.email == "new@example.com"
        assert request.username == "new_username"
        assert request.is_active is True

    def test_update_request_empty(self):
        """Test update request with no fields."""
        request = UserUpdateRequest()
        assert request.email is None
        assert request.username is None
        assert request.is_active is None

    def test_update_request_username_max_length(self):
        """Test username max length is 100."""
        long_username = "a" * 101
        with pytest.raises(ValidationError) as exc_info:
            UserUpdateRequest(username=long_username)
        error_types = {err["type"] for err in exc_info.value.errors()}
        assert "string_too_long" in error_types or "value_error" in error_types

    def test_update_request_username_exact_max(self):
        """Test username at exact max length."""
        username = "a" * 100
        request = UserUpdateRequest(username=username)
        assert len(request.username) == 100


# ==================== USER LIST RESPONSE TESTS ====================

class TestUserListResponse:
    """Tests for UserListResponse schema."""

    def test_valid_list_response(self, user_id, now):
        """Test valid list response."""
        user1 = UserResponse(
            id=user_id,
            email="user1@example.com",
            is_active=True,
            is_email_verified=True,
            is_superuser=False,
            created_at=now,
            updated_at=now,
        )
        user2 = UserResponse(
            id=uuid4(),
            email="user2@example.com",
            is_active=False,
            is_email_verified=False,
            is_superuser=True,
            created_at=now,
            updated_at=now,
        )
        response = UserListResponse(items=[user1, user2], total=50, limit=20, offset=0)
        assert len(response.items) == 2
        assert response.total == 50
        assert response.limit == 20

    def test_list_response_empty_items(self):
        """Test list response with empty items."""
        response = UserListResponse(items=[], total=0, limit=20, offset=0)
        assert response.items == []

    def test_list_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            UserListResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required = {"items", "total", "limit", "offset"}
        assert required.issubset(errors)


# ==================== PASSWORD CHANGE REQUEST TESTS ====================

class TestPasswordChangeRequest:
    """Tests for PasswordChangeRequest schema."""

    def test_valid_password_change_request(self):
        """Test valid password change request."""
        request = PasswordChangeRequest(
            current_password="OldSecurePass123!",
            new_password="NewSecurePass456!",
        )
        assert request.current_password == "OldSecurePass123!"
        assert request.new_password == "NewSecurePass456!"

    def test_password_change_current_required(self):
        """Test current_password is required."""
        with pytest.raises(ValidationError) as exc_info:
            PasswordChangeRequest(new_password="NewPass123!")
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "current_password" in errors

    def test_password_change_new_required(self):
        """Test new_password is required."""
        with pytest.raises(ValidationError) as exc_info:
            PasswordChangeRequest(current_password="OldPass123!")
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "new_password" in errors

    def test_password_change_new_min_length(self):
        """Test new_password below minimum length."""
        with pytest.raises(ValidationError) as exc_info:
            PasswordChangeRequest(current_password="OldPass123!", new_password="Short1!")
        error_types = {err["type"] for err in exc_info.value.errors()}
        assert "string_too_short" in error_types or "value_error" in error_types

    def test_password_change_new_max_length(self):
        """Test new_password above maximum length."""
        long_password = "A" * 129
        with pytest.raises(ValidationError) as exc_info:
            PasswordChangeRequest(current_password="OldPass123!", new_password=long_password)
        error_types = {err["type"] for err in exc_info.value.errors()}
        assert "string_too_long" in error_types or "value_error" in error_types


# ==================== DELETE ACCOUNT TESTS ====================

class TestDeleteAccountRequest:
    """Tests for DeleteAccountRequest schema."""

    def test_valid_delete_request(self):
        """Test valid delete account request."""
        request = DeleteAccountRequest(password="MySecurePass123!")
        assert request.password == "MySecurePass123!"

    def test_delete_request_password_required(self):
        """Test password is required."""
        with pytest.raises(ValidationError) as exc_info:
            DeleteAccountRequest()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "password" in errors


class TestDeleteAccountResponse:
    """Tests for DeleteAccountResponse schema."""

    def test_valid_delete_response(self, user_id):
        """Test valid delete account response."""
        response = DeleteAccountResponse(
            success=True,
            message="Account deleted successfully",
            user_id=user_id,
        )
        assert response.success is True
        assert response.message == "Account deleted successfully"
        assert response.user_id == user_id

    def test_delete_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            DeleteAccountResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required = {"success", "message", "user_id"}
        assert required.issubset(errors)


# ==================== SESSION INFO RESPONSE TESTS ====================

class TestSessionInfoResponse:
    """Tests for SessionInfoResponse schema."""

    def test_valid_session_info(self, user_id, now):
        """Test valid session info response."""
        session = SessionInfoResponse(
            id=uuid4(),
            user_id=user_id,
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            created_at=now,
            expires_at=now,
            is_active=True,
            last_used_at=now,
        )
        assert session.user_id == user_id
        assert session.client_ip == "192.168.1.1"
        assert session.is_active is True

    def test_session_info_minimal(self, user_id, now):
        """Test session info with minimal fields."""
        session = SessionInfoResponse(
            id=uuid4(),
            user_id=user_id,
            created_at=now,
            expires_at=now,
            is_active=True,
        )
        assert session.client_ip is None
        assert session.user_agent is None
        assert session.last_used_at is None

    def test_session_info_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            SessionInfoResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required = {"id", "user_id", "created_at", "expires_at", "is_active"}
        assert required.issubset(errors)


# ==================== SESSION LIST RESPONSE TESTS ====================

class TestSessionListResponse:
    """Tests for SessionListResponse schema."""

    def test_valid_session_list(self, user_id, now):
        """Test valid session list response."""
        session1 = SessionInfoResponse(
            id=uuid4(), user_id=user_id, created_at=now, expires_at=now, is_active=True,
        )
        session2 = SessionInfoResponse(
            id=uuid4(), user_id=user_id, created_at=now, expires_at=now, is_active=False,
        )
        response = SessionListResponse(sessions=[session1, session2], total=5)
        assert len(response.sessions) == 2
        assert response.total == 5

    def test_session_list_empty(self):
        """Test session list with no sessions."""
        response = SessionListResponse(sessions=[], total=0)
        assert response.sessions == []

    def test_session_list_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            SessionListResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required = {"sessions", "total"}
        assert required.issubset(errors)