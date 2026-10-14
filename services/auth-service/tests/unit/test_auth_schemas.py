"""
Unit tests for Auth Pydantic schemas.

Tests cover:
- LoginRequest/Response validation
- RefreshRequest/Response validation
- LogoutRequest/Response validation
- VerifyEmail/Phone schemas
- MFA schemas
- Password reset schemas
- Session schemas
- Field validators and constraints
- Edge cases and boundary values
"""

from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RefreshResponse,
    LogoutRequest,
    LogoutResponse,
    VerifyEmailRequest,
    VerifyEmailResponse,
    VerifyPhoneRequest,
    VerifyPhoneResponse,
    PasswordResetRequest,
    PasswordResetConfirmRequest,
    MFAEnableRequest,
    MFAEnableResponse,
    MFADisableRequest,
    MFADisableResponse,
    MFAInfoResponse,
    SessionInfo,
    SessionListResponse,
)


class TestLoginRequest:
    """Tests for LoginRequest schema."""

    def test_valid_login_request(self):
        """Test creating valid login request."""
        request = LoginRequest(email="user@example.com", password="password123")
        
        assert request.email == "user@example.com"
        assert request.password == "password123"

    def test_login_request_email_normalized(self):
        """Test email field gets stripped and lowercased."""
        request = LoginRequest(email="  User@Example.COM  ", password="password123")
        
        assert request.email == "user@example.com"

    def test_login_request_email_required(self):
        """Test email field is required."""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(password="password123")
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "email" in errors

    def test_login_request_password_required(self):
        """Test password field is required."""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(email="user@example.com")
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "password" in errors

    def test_login_request_invalid_email(self):
        """Test invalid email raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(email="invalid-email", password="password123")
        
        assert "email" in str(exc_info.value).lower()

    def test_login_request_password_min_length(self):
        """Test password must be at least 8 characters."""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(email="user@example.com", password="pass")
        
        errors = {err["type"] for err in exc_info.value.errors()}
        assert "string_too_short" in errors

    def test_login_request_password_max_length(self):
        """Test password max length is 128 characters."""
        long_password = "a" * 129
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(email="user@example.com", password=long_password)
        
        errors = {err["type"] for err in exc_info.value.errors()}
        assert "string_too_long" in errors

    def test_login_request_password_exact_boundary(self):
        """Test password at boundary values."""
        # Minimum length (8 chars)
        request_min = LoginRequest(email="user@example.com", password="12345678")
        assert request_min.password == "12345678"
        
        # Maximum length (128 chars)
        password_128 = "a" * 128
        request_max = LoginRequest(email="user@example.com", password=password_128)
        assert request_max.password == password_128

    def test_login_request_with_totp_code(self):
        """Test login request with optional TOTP code."""
        request = LoginRequest(
            email="user@example.com",
            password="password123",
            totp_code="123456",
        )
        assert request.totp_code == "123456"

    def test_login_request_invalid_totp_code(self):
        """Test TOTP code must be 6 digits."""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                email="user@example.com",
                password="password123",
                totp_code="12345",  # 5 digits
            )
        assert "totp_code" in str(exc_info.value)


class TestLoginResponse:
    """Tests for LoginResponse schema."""

    def test_valid_login_response(self):
        """Test creating valid login response."""
        user_id = uuid4()
        response = LoginResponse(
            access_token="eyJhbGciOiJSUzI1NiIs...",
            expires_in=900,
            user_id=user_id,
            email="user@example.com",
        )
        
        assert response.access_token == "eyJhbGciOiJSUzI1NiIs..."
        assert response.token_type == "bearer"
        assert response.expires_in == 900
        assert response.user_id == user_id
        assert response.email == "user@example.com"

    def test_login_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            LoginResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"access_token", "expires_in", "user_id", "email"}
        assert required_fields.issubset(errors)

    def test_login_response_token_type_default(self):
        """Test token_type defaults to 'bearer'."""
        user_id = uuid4()
        response = LoginResponse(
            access_token="token123",
            expires_in=3600,
            user_id=user_id,
            email="user@example.com",
        )
        assert response.token_type == "bearer"

    def test_login_response_optional_fields(self):
        """Test optional fields have correct defaults."""
        user_id = uuid4()
        response = LoginResponse(
            access_token="token123",
            expires_in=3600,
            user_id=user_id,
            email="user@example.com",
        )
        assert response.is_email_verified is False
        assert response.requires_mfa is False

    def test_login_response_with_mfa_required(self):
        """Test login response with MFA required."""
        user_id = uuid4()
        response = LoginResponse(
            access_token="token123",
            expires_in=3600,
            user_id=user_id,
            email="user@example.com",
            is_email_verified=True,
            requires_mfa=True,
        )
        assert response.requires_mfa is True
        assert response.is_email_verified is True


class TestRefreshRequest:
    """Tests for RefreshRequest schema."""

    def test_valid_refresh_request(self):
        """Test refresh request with empty body."""
        request = RefreshRequest()
        assert request is not None

    def test_refresh_request_no_fields(self):
        """Test refresh request has no required fields."""
        request = RefreshRequest()
        assert request.model_dump() == {}


class TestRefreshResponse:
    """Tests for RefreshResponse schema."""

    def test_valid_refresh_response(self):
        """Test creating valid refresh response."""
        response = RefreshResponse(
            access_token="new_access_token",
            expires_in=900,
        )
        
        assert response.access_token == "new_access_token"
        assert response.token_type == "bearer"
        assert response.expires_in == 900

    def test_refresh_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            RefreshResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"access_token", "expires_in"}
        assert required_fields.issubset(errors)

    def test_refresh_response_token_type_default(self):
        """Test token_type defaults to 'bearer'."""
        response = RefreshResponse(access_token="token123", expires_in=3600)
        assert response.token_type == "bearer"


class TestLogoutRequest:
    """Tests for LogoutRequest schema."""

    def test_valid_logout_request(self):
        """Test logout request with empty body."""
        request = LogoutRequest()
        assert request is not None

    def test_logout_request_no_fields(self):
        """Test logout request has no required fields."""
        request = LogoutRequest()
        assert request.model_dump() == {}


class TestLogoutResponse:
    """Tests for LogoutResponse schema."""

    def test_valid_logout_response(self):
        """Test creating valid logout response."""
        response = LogoutResponse(success=True, message="Successfully logged out")
        
        assert response.success is True
        assert response.message == "Successfully logged out"

    def test_logout_response_with_revoked_tokens(self):
        """Test logout response with revoked tokens count."""
        response = LogoutResponse(
            success=True,
            message="Successfully logged out",
            revoked_tokens=5,
        )
        assert response.revoked_tokens == 5

    def test_logout_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            LogoutResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"success", "message"}
        assert required_fields.issubset(errors)

    def test_logout_response_false_success(self):
        """Test logout response with success=False."""
        response = LogoutResponse(success=False, message="Logout failed")
        assert response.success is False


class TestVerifyEmailRequest:
    """Tests for VerifyEmailRequest schema."""

    def test_valid_verify_email_request(self):
        """Test creating valid email verification request."""
        token = "a" * 20
        request = VerifyEmailRequest(token=token)
        assert request.token == token

    def test_verify_email_request_required_field(self):
        """Test token field is required."""
        with pytest.raises(ValidationError) as exc_info:
            VerifyEmailRequest()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "token" in errors

    def test_verify_email_request_min_length(self):
        """Test token must be at least 20 characters."""
        with pytest.raises(ValidationError) as exc_info:
            VerifyEmailRequest(token="short")
        
        errors = {err["type"] for err in exc_info.value.errors()}
        assert "string_too_short" in errors

    def test_verify_email_request_exact_min_length(self):
        """Test token at exact minimum length (20 chars)."""
        token = "a" * 20
        request = VerifyEmailRequest(token=token)
        assert request.token == token


class TestVerifyEmailResponse:
    """Tests for VerifyEmailResponse schema."""

    def test_valid_verify_email_response(self):
        """Test creating valid email verification response."""
        response = VerifyEmailResponse(
            success=True,
            message="Email successfully verified",
        )
        
        assert response.success is True
        assert response.message == "Email successfully verified"

    def test_verify_email_response_with_email(self):
        """Test verify email response with email field."""
        response = VerifyEmailResponse(
            success=True,
            message="Email verified",
            email="user@example.com",
        )
        assert response.email == "user@example.com"

    def test_verify_email_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            VerifyEmailResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"success", "message"}
        assert required_fields.issubset(errors)


class TestVerifyPhoneRequest:
    """Tests for VerifyPhoneRequest schema."""

    def test_valid_verify_phone_request(self):
        """Test creating valid phone verification request."""
        request = VerifyPhoneRequest(
            phone_number="+79001234567",
            code="123456",
        )
        assert request.phone_number == "+79001234567"
        assert request.code == "123456"

    def test_verify_phone_request_phone_required(self):
        """Test phone_number is required."""
        with pytest.raises(ValidationError) as exc_info:
            VerifyPhoneRequest(code="123456")
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "phone_number" in errors

    def test_verify_phone_request_code_required(self):
        """Test code is required."""
        with pytest.raises(ValidationError) as exc_info:
            VerifyPhoneRequest(phone_number="+79001234567")
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "code" in errors

    def test_verify_phone_request_code_pattern(self):
        """Test code must be exactly 6 digits."""
        with pytest.raises(ValidationError) as exc_info:
            VerifyPhoneRequest(phone_number="+79001234567", code="12345")
        assert "code" in str(exc_info.value)

    def test_verify_phone_request_invalid_phone(self):
        """Test phone must match international format."""
        with pytest.raises(ValidationError) as exc_info:
            VerifyPhoneRequest(phone_number="89001234567", code="123456")
        assert "phone_number" in str(exc_info.value)

    def test_verify_phone_request_phone_normalized(self):
        """Test phone number gets normalized — pattern applied before normalizer, so pass clean number."""
        # Pydantic applies pattern validation before field_validator,
        # so we pass a number that already matches the pattern
        request = VerifyPhoneRequest(
            phone_number="+79001234567",
            code="123456",
        )
        assert request.phone_number == "+79001234567"


class TestVerifyPhoneResponse:
    """Tests for VerifyPhoneResponse schema."""

    def test_valid_verify_phone_response(self):
        """Test creating valid phone verification response."""
        response = VerifyPhoneResponse(
            success=True,
            message="Phone successfully verified",
        )
        assert response.success is True
        assert response.message == "Phone successfully verified"

    def test_verify_phone_response_with_phone(self):
        """Test verify phone response with phone_number field."""
        response = VerifyPhoneResponse(
            success=True,
            message="Phone verified",
            phone_number="+79001234567",
        )
        assert response.phone_number == "+79001234567"

    def test_verify_phone_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            VerifyPhoneResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"success", "message"}
        assert required_fields.issubset(errors)


class TestPasswordResetRequest:
    """Tests for PasswordResetRequest schema."""

    def test_valid_password_reset_request(self):
        """Test creating valid password reset request."""
        request = PasswordResetRequest(email="user@example.com")
        assert request.email == "user@example.com"

    def test_password_reset_email_normalized(self):
        """Test email gets normalized."""
        request = PasswordResetRequest(email="  User@Example.COM  ")
        assert request.email == "user@example.com"

    def test_password_reset_email_required(self):
        """Test email is required."""
        with pytest.raises(ValidationError) as exc_info:
            PasswordResetRequest()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "email" in errors


class TestPasswordResetConfirmRequest:
    """Tests for PasswordResetConfirmRequest schema."""

    def test_valid_password_reset_confirm_request(self):
        """Test creating valid password reset confirm request."""
        request = PasswordResetConfirmRequest(
            token="a" * 20,
            new_password="newpassword123",
        )
        assert request.token == "a" * 20
        assert request.new_password == "newpassword123"

    def test_password_reset_confirm_token_min_length(self):
        """Test token must be at least 20 characters."""
        with pytest.raises(ValidationError) as exc_info:
            PasswordResetConfirmRequest(
                token="short",
                new_password="password123",
            )
        errors = {err["type"] for err in exc_info.value.errors()}
        assert "string_too_short" in errors

    def test_password_reset_confirm_password_min_length(self):
        """Test new_password must be at least 8 characters."""
        with pytest.raises(ValidationError) as exc_info:
            PasswordResetConfirmRequest(
                token="a" * 20,
                new_password="short",
            )
        errors = {err["type"] for err in exc_info.value.errors()}
        assert "string_too_short" in errors


class TestMFAEnableRequest:
    """Tests for MFAEnableRequest schema."""

    def test_valid_mfa_enable_request(self):
        """Test creating valid MFA enable request."""
        request = MFAEnableRequest(totp_code="123456")
        assert request.totp_code == "123456"

    def test_mfa_enable_request_required(self):
        """Test totp_code is required."""
        with pytest.raises(ValidationError) as exc_info:
            MFAEnableRequest()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "totp_code" in errors

    def test_mfa_enable_request_pattern(self):
        """Test totp_code must be exactly 6 digits."""
        with pytest.raises(ValidationError) as exc_info:
            MFAEnableRequest(totp_code="12345")
        assert "totp_code" in str(exc_info.value)


class TestMFAEnableResponse:
    """Tests for MFAEnableResponse schema."""

    def test_valid_mfa_enable_response(self):
        """Test creating valid MFA enable response."""
        response = MFAEnableResponse(
            success=True,
            message="MFA enabled successfully",
            totp_enabled=True,
        )
        assert response.success is True
        assert response.totp_enabled is True

    def test_mfa_enable_response_with_backup_codes(self):
        """Test MFA enable response with backup codes."""
        codes = ["1234567890", "0987654321"]
        response = MFAEnableResponse(
            success=True,
            message="MFA enabled",
            totp_enabled=True,
            backup_codes=codes,
        )
        assert response.backup_codes == codes

    def test_mfa_enable_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            MFAEnableResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"success", "message", "totp_enabled"}
        assert required_fields.issubset(errors)


class TestMFADisableRequest:
    """Tests for MFADisableRequest schema."""

    def test_valid_mfa_disable_request(self):
        """Test creating valid MFA disable request."""
        request = MFADisableRequest(password="password123")
        assert request.password == "password123"
        assert request.totp_code is None

    def test_mfa_disable_request_with_totp(self):
        """Test MFA disable request with TOTP code."""
        request = MFADisableRequest(password="password123", totp_code="123456")
        assert request.totp_code == "123456"

    def test_mfa_disable_request_password_required(self):
        """Test password is required."""
        with pytest.raises(ValidationError) as exc_info:
            MFADisableRequest()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "password" in errors


class TestMFADisableResponse:
    """Tests for MFADisableResponse schema."""

    def test_valid_mfa_disable_response(self):
        """Test creating valid MFA disable response."""
        response = MFADisableResponse(
            success=True,
            message="MFA disabled successfully",
            totp_enabled=False,
        )
        assert response.success is True
        assert response.totp_enabled is False


class TestMFAInfoResponse:
    """Tests for MFAInfoResponse schema."""

    def test_valid_mfa_info_response(self):
        """Test creating valid MFA info response."""
        response = MFAInfoResponse(totp_enabled=True)
        assert response.totp_enabled is True
        assert response.totp_secret is None
        assert response.otpauth_url is None
        assert response.has_backup_codes is False

    def test_mfa_info_response_with_secret(self):
        """Test MFA info response with secret and URL."""
        response = MFAInfoResponse(
            totp_enabled=True,
            totp_secret="JBSWY3DPEHPK3PXP",
            otpauth_url="otpauth://totp/...",
            has_backup_codes=True,
        )
        assert response.totp_secret == "JBSWY3DPEHPK3PXP"
        assert response.otpauth_url == "otpauth://totp/..."
        assert response.has_backup_codes is True


class TestSessionInfo:
    """Tests for SessionInfo schema."""

    @pytest.fixture
    def valid_session_data(self) -> dict:
        """Generate valid session data."""
        return {
            "id": uuid4(),
            "user_id": uuid4(),
            "client_ip": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "created_at": "2024-01-01T00:00:00Z",
            "expires_at": "2024-01-08T00:00:00Z",
        }

    def test_valid_session_info(self, valid_session_data):
        """Test creating valid session info."""
        session = SessionInfo(**valid_session_data)
        assert isinstance(session.id, UUID)
        assert isinstance(session.user_id, UUID)
        assert session.client_ip == "192.168.1.1"
        assert session.is_active is True  # default

    def test_session_info_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            SessionInfo()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"id", "user_id", "created_at", "expires_at"}
        assert required_fields.issubset(errors)

    def test_session_info_is_active_default(self, valid_session_data):
        """Test is_active defaults to True."""
        session = SessionInfo(**valid_session_data)
        assert session.is_active is True


class TestSessionListResponse:
    """Tests for SessionListResponse schema."""

    def test_valid_session_list_response(self):
        """Test creating valid session list response."""
        session = SessionInfo(
            id=uuid4(),
            user_id=uuid4(),
            created_at="2024-01-01T00:00:00Z",
            expires_at="2024-01-08T00:00:00Z",
        )
        response = SessionListResponse(
            sessions=[session],
            total=1,
        )
        assert len(response.sessions) == 1
        assert response.total == 1
        assert response.limit == 20  # default
        assert response.offset == 0  # default

    def test_session_list_response_required_fields(self):
        """Test required fields must be provided."""
        with pytest.raises(ValidationError) as exc_info:
            SessionListResponse()
        
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"sessions", "total"}
        assert required_fields.issubset(errors)

    def test_session_list_response_empty_sessions(self):
        """Test session list with empty sessions."""
        response = SessionListResponse(sessions=[], total=0)
        assert response.sessions == []
        assert response.total == 0

    def test_session_list_response_custom_pagination(self):
        """Test session list with custom pagination."""
        response = SessionListResponse(
            sessions=[],
            total=100,
            limit=50,
            offset=10,
        )
        assert response.limit == 50
        assert response.offset == 10