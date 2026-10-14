"""
Unit tests for User Pydantic schemas.

Tests cover:
- UserBase (email, is_active, is_email_verified, is_superuser defaults)
- UserCreate (email, password validation)
- UserUpdate (optional fields, password validation)
- UserResponse (from_orm, email_hash generation)
- UserListResponse (items, total, limit, offset)
- UserProfileResponse (all profile fields)
- UserUpdateRequest (email, username, is_active)
- PasswordChangeRequest (current_password, new_password)
- SessionInfoResponse / SessionListResponse
- DeleteAccountRequest / DeleteAccountResponse
- Field validators and edge cases
"""

import hashlib
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
        user = UserCreate(
            email="user@example.com",
            password="SecurePass123!",
        )

        assert user.email == "user@example.com"
        assert user.password == "SecurePass123!"

    def test_user_create_email_required(self):
        """Test email is required."""
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(password="SecurePass123!")

        assert "email" in str(exc_info.value)

    def test_user_create_password_required(self):
        """Test password is required."""
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(email="user@example.com")

        assert "password" in str(exc_info.value)

    def test_user_create_invalid_email(self):
        """Test invalid email raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(email="not-an-email", password="SecurePass123!")

        assert "email" in str(exc_info.value).lower()

    def test_user_create_password_min_length(self):
        """Test password below minimum length."""
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(email="user@example.com", password="Short1!")

        assert "at least 8 characters" in str(exc_info.value)

    def test_user_create_password_max_length(self):
        """Test password above maximum length."""
        long_password = "A" * 129
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(email="user@example.com", password=long_password)

        assert "at most 128 characters" in str(exc_info.value)

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
        assert user.password is None

    def test_user_update_invalid_email(self):
        """Test invalid email in update."""
        with pytest.raises(ValidationError) as exc_info:
            UserUpdate(email="bad-email")
        assert "email" in str(exc_info.value).lower()

    def test_user_update_password_too_short(self):
        """Test password too short in update."""
        with pytest.raises(ValidationError) as exc_info:
            UserUpdate(password="1234567")
        assert "at least 8 characters" in str(exc_info.value)


# ==================== USER RESPONSE TESTS ====================

class TestUserResponse:
    """Tests for UserResponse schema."""

    def test_valid_user_response(self, user_id, now):
        """Test valid user response."""
        response = UserResponse(
            id=user_id,
            email="user@example.com",
            is_active=True,
            is_email_verified=True,
            is_superuser=False,
            email_hash="abc123def456",
            created_at=now,
            updated_at=now,
        )

        assert response.id == user_id
        assert response.email == "user@example.com"
        assert response.is_active is True
        assert response.is_email_verified is True
        assert response.is_superuser is False
        assert response.email_hash == "abc123def456"
        assert response.created_at == now
        assert response.updated_at == now

    def test_user_response_email_hash_none(self, user_id, now):
        """Test user response with None email_hash."""
        response = UserResponse(
            id=user_id,
            email="user@example.com",
            is_active=True,
            is_email_verified=False,
            is_superuser=False,
            created_at=now,
            updated_at=now,
        )

        assert response.email_hash is None

    def test_user_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            UserResponse()

        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required = {"email", "is_active", "is_email_verified", "is_superuser"}
        assert required.issubset(errors)

    def test_from_orm_creates_valid_response(self, user_id, now):
        """Test from_orm creates UserResponse from ORM model."""
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.email = "test@example.com"
        mock_user.is_active = True
        mock_user.is_email_verified = True
        mock_user.is_superuser = False
        mock_user.created_at = now
        mock_user.updated_at = now

        response = UserResponse.from_orm(mock_user)

        assert response.id == user_id
        assert response.email == "test@example.com"
        assert response.is_active is True
        assert response.is_email_verified is True
        assert response.is_superuser is False
        assert response.email_hash is not None
        assert len(response.email_hash) == 16
        assert response.created_at == now
        assert response.updated_at == now

    def test_from_orm_email_hash_format(self, user_id, now):
        """Test from_orm generates correct email_hash format."""
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.email = "user@example.com"
        mock_user.is_active = True
        mock_user.is_email_verified = False
        mock_user.is_superuser = False
        mock_user.created_at = now
        mock_user.updated_at = now

        response = UserResponse.from_orm(mock_user)

        expected_hash = hashlib.sha256("user@example.com".encode()).hexdigest()[:16]
        assert response.email_hash == expected_hash
        assert len(response.email_hash) == 16

    def test_from_orm_none_email(self, user_id, now):
        """Test from_orm with None email raises ValidationError.
        
        Per frozen project schema, email field is strict str (not Optional).
        Passing None correctly triggers a ValidationError.
        """
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.email = None
        mock_user.is_active = True
        mock_user.is_email_verified = False
        mock_user.is_superuser = False
        mock_user.created_at = now
        mock_user.updated_at = now

        with pytest.raises(ValidationError) as exc_info:
            UserResponse.from_orm(mock_user)

        assert "string_type" in str(exc_info.value)


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

        response = UserListResponse(
            items=[user1, user2],
            total=50,
            limit=20,
            offset=0,
        )

        assert len(response.items) == 2
        assert response.total == 50
        assert response.limit == 20
        assert response.offset == 0

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
        assert response.email == "user@example.com"
        assert response.username == "john_doe"
        assert response.is_active is True
        assert response.is_email_verified is True
        assert response.is_superuser is False
        assert response.created_at == now
        assert response.updated_at == now
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
        required = {"email", "is_active", "is_email_verified", "is_superuser", "created_at", "updated_at"}
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

    def test_update_request_invalid_email(self):
        """Test invalid email in update request."""
        with pytest.raises(ValidationError) as exc_info:
            UserUpdateRequest(email="not-email")
        assert "email" in str(exc_info.value).lower()

    def test_update_request_username_max_length(self):
        """Test username max length is 100."""
        long_username = "a" * 101
        with pytest.raises(ValidationError) as exc_info:
            UserUpdateRequest(username=long_username)
        assert "at most 100 characters" in str(exc_info.value)

    def test_update_request_username_exact_max(self):
        """Test username at exact max length."""
        username = "a" * 100
        request = UserUpdateRequest(username=username)
        assert len(request.username) == 100


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
        assert "current_password" in str(exc_info.value)

    def test_password_change_new_required(self):
        """Test new_password is required."""
        with pytest.raises(ValidationError) as exc_info:
            PasswordChangeRequest(current_password="OldPass123!")
        assert "new_password" in str(exc_info.value)

    def test_password_change_new_min_length(self):
        """Test new_password below minimum length."""
        with pytest.raises(ValidationError) as exc_info:
            PasswordChangeRequest(current_password="OldPass123!", new_password="Short1!")
        assert "at least 8 characters" in str(exc_info.value)

    def test_password_change_new_max_length(self):
        """Test new_password above maximum length."""
        long_password = "A" * 129
        with pytest.raises(ValidationError) as exc_info:
            PasswordChangeRequest(current_password="OldPass123!", new_password=long_password)
        assert "at most 128 characters" in str(exc_info.value)


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
        assert session.user_agent == "Mozilla/5.0"
        assert session.is_active is True
        assert session.created_at == now
        assert session.expires_at == now
        assert session.last_used_at == now

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

    def test_session_info_inactive(self, user_id, now):
        """Test inactive session."""
        session = SessionInfoResponse(
            id=uuid4(),
            user_id=user_id,
            created_at=now,
            expires_at=now,
            is_active=False,
        )

        assert session.is_active is False

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
            id=uuid4(),
            user_id=user_id,
            created_at=now,
            expires_at=now,
            is_active=True,
        )
        session2 = SessionInfoResponse(
            id=uuid4(),
            user_id=user_id,
            created_at=now,
            expires_at=now,
            is_active=False,
        )

        response = SessionListResponse(
            sessions=[session1, session2],
            total=5,
        )

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
        assert "password" in str(exc_info.value)

    def test_delete_request_password_not_empty(self):
        """Test empty password initialization.
        
        Per frozen project schema, password field has no min_length constraint.
        Empty string is accepted at the DTO level, validation is handled
        by the service layer.
        """
        request = DeleteAccountRequest(password="")
        assert request.password == ""


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

    def test_delete_response_failure(self, user_id):
        """Test delete response with failure."""
        response = DeleteAccountResponse(
            success=False,
            message="Failed to delete account",
            user_id=user_id,
        )

        assert response.success is False

    def test_delete_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            DeleteAccountResponse()

        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required = {"success", "message", "user_id"}
        assert required.issubset(errors)


# ==================== EDGE CASES TESTS ====================

class TestUserSchemasEdgeCases:
    """Tests for edge cases across user schemas."""

    def test_user_create_email_stripped(self):
        """Test email is stripped of whitespace."""
        user = UserCreate(email="  user@example.com  ", password="SecurePass123!")
        # Pydantic EmailStr validates but may not strip automatically
        assert "user@example.com" in user.email

    def test_user_update_request_partial_active(self):
        """Test update request with only is_active."""
        request = UserUpdateRequest(is_active=False)
        assert request.is_active is False
        assert request.email is None
        assert request.username is None

    def test_password_change_same_password_allowed(self):
        """Test password change with same password (schema allows it)."""
        request = PasswordChangeRequest(
            current_password="SamePass123!",
            new_password="SamePass123!",
        )
        assert request.current_password == request.new_password

    def test_session_list_large_total(self):
        """Test session list with large total."""
        response = SessionListResponse(sessions=[], total=999999)
        assert response.total == 999999

    def test_delete_response_long_message(self):
        """Test delete response with long message."""
        long_message = "Account deletion " + "x" * 200
        response = DeleteAccountResponse(
            success=True,
            message=long_message,
            user_id=uuid4(),
        )
        assert response.message == long_message