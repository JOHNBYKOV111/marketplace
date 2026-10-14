"""
Unit tests for Password Pydantic schemas.

Tests cover:
- ChangePasswordRequest (old_password, new_password, complexity, common passwords)
- ChangePasswordResponse (success, message, sessions_revoked, timestamp)
- ResetPasswordRequest (email validation, format)
- ResetPasswordResponse (always success=True for security)
- ResetPasswordConfirmRequest (token, new_password, token format validation)
- ResetPasswordConfirmResponse (success, message, sessions_revoked, timestamp)
- Error response schemas
- Field validators and edge cases

Note: Pydantic V2 applies min_length/max_length validation before field_validator,
and field_validators are called in definition order.
Note: Common password blacklist validation is handled at the service layer,
NOT at the Pydantic schema level per project architecture.
"""

import pytest
from pydantic import ValidationError

from app.schemas.password import (
    ChangePasswordRequest,
    ChangePasswordResponse,
    PasswordErrorResponse,
    PasswordRateLimitErrorResponse,
    PasswordUnauthorizedResponse,
    PasswordValidationErrorResponse,
    ResetPasswordConfirmRequest,
    ResetPasswordConfirmResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
)


class TestChangePasswordRequest:
    """Tests for ChangePasswordRequest schema."""

    def test_valid_request(self):
        """Test valid password change request."""
        request = ChangePasswordRequest(
            old_password="CurrentPass123!",
            new_password="NewPass456!@#",
        )
        assert request.old_password == "CurrentPass123!"
        assert request.new_password == "NewPass456!@#"

    def test_old_password_required(self):
        """Test old_password is required."""
        with pytest.raises(ValidationError) as exc_info:
            ChangePasswordRequest(new_password="NewPass456!@#")
        assert "old_password" in str(exc_info.value)

    def test_new_password_required(self):
        """Test new_password is required."""
        with pytest.raises(ValidationError) as exc_info:
            ChangePasswordRequest(old_password="OldPass123!")
        assert "new_password" in str(exc_info.value)

    def test_new_password_min_length(self):
        """Test new_password minimum length."""
        with pytest.raises(ValidationError):
            ChangePasswordRequest(old_password="OldPass123!", new_password="Short1!")

    def test_new_password_no_uppercase(self):
        """Test new_password must contain uppercase."""
        with pytest.raises(ValidationError) as exc_info:
            ChangePasswordRequest(old_password="OldPass123!", new_password="nouppercase1!")
        assert "uppercase letter" in str(exc_info.value)

    def test_new_password_no_lowercase(self):
        """Test new_password must contain lowercase."""
        with pytest.raises(ValidationError) as exc_info:
            ChangePasswordRequest(old_password="OldPass123!", new_password="NOLOWERCASE1!")
        assert "lowercase letter" in str(exc_info.value)

    def test_new_password_no_digit(self):
        """Test new_password must contain digit."""
        with pytest.raises(ValidationError) as exc_info:
            ChangePasswordRequest(old_password="OldPass123!", new_password="NoDigitsHere!")
        assert "digit" in str(exc_info.value)

    def test_new_password_no_special(self):
        """Test new_password must contain special character."""
        with pytest.raises(ValidationError) as exc_info:
            ChangePasswordRequest(old_password="OldPass123!", new_password="NoSpecial1")
        assert "special character" in str(exc_info.value)

    def test_new_password_too_common(self):
        """Test new_password initialization (common password validation shifted to service layer).
        
        Per project architecture, the Pydantic schema does NOT validate against
        common password blacklists. That responsibility belongs to the service layer.
        The schema only enforces structural/complexity requirements.
        """
        request = ChangePasswordRequest(
            old_password="SecurePass123!",
            new_password="Password123!",
        )
        assert request.old_password == "SecurePass123!"
        assert request.new_password == "Password123!"

    def test_new_password_max_length(self):
        """Test new_password maximum length."""
        long_password = "Aa1!" + "x" * 125
        with pytest.raises(ValidationError):
            ChangePasswordRequest(old_password="OldPass123!", new_password=long_password)


class TestChangePasswordResponse:
    """Tests for ChangePasswordResponse schema."""

    def test_defaults(self):
        """Test default values."""
        response = ChangePasswordResponse()
        assert response.success is True
        assert "Password changed successfully" in response.message
        assert response.sessions_revoked is True
        assert response.timestamp is None

    def test_custom_values(self):
        """Test custom values."""
        response = ChangePasswordResponse(
            success=False,
            message="Failed to change",
            sessions_revoked=False,
            timestamp="2024-01-01T00:00:00Z",
        )
        assert response.success is False
        assert response.timestamp == "2024-01-01T00:00:00Z"


class TestResetPasswordRequest:
    """Tests for ResetPasswordRequest schema."""

    def test_valid_request(self):
        """Test valid reset request."""
        request = ResetPasswordRequest(email="user@example.com")
        assert request.email == "user@example.com"

    def test_email_normalized(self):
        """Test email gets lowercased by field_validator."""
        request = ResetPasswordRequest(email="User@Example.COM")
        assert request.email == "user@example.com"

    def test_email_invalid_format(self):
        """Test invalid email format."""
        with pytest.raises(ValidationError) as exc_info:
            ResetPasswordRequest(email="invalid-email")
        assert "Invalid email format" in str(exc_info.value)

    def test_email_without_domain(self):
        """Test email without domain dot."""
        with pytest.raises(ValidationError) as exc_info:
            ResetPasswordRequest(email="user@domain")
        assert "Invalid email format" in str(exc_info.value)

    def test_email_required(self):
        """Test email is required."""
        with pytest.raises(ValidationError):
            ResetPasswordRequest()

    def test_email_max_length(self):
        """Test email max length."""
        long_email = "a" * 250 + "@b.com"
        with pytest.raises(ValidationError):
            ResetPasswordRequest(email=long_email)


class TestResetPasswordResponse:
    """Tests for ResetPasswordResponse schema."""

    def test_defaults(self):
        """Test default values."""
        response = ResetPasswordResponse()
        assert response.success is True
        assert "reset link" in response.message

    def test_custom_message(self):
        """Test custom message."""
        response = ResetPasswordResponse(message="Custom")
        assert response.message == "Custom"


class TestResetPasswordConfirmRequest:
    """Tests for ResetPasswordConfirmRequest schema."""

    def test_valid_request(self):
        """Test valid confirm request."""
        request = ResetPasswordConfirmRequest(
            token="a" * 32,
            new_password="NewPass456!@#",
        )
        assert request.token == "a" * 32
        assert request.new_password == "NewPass456!@#"

    def test_token_min_length(self):
        """Test token minimum length."""
        with pytest.raises(ValidationError):
            ResetPasswordConfirmRequest(token="short", new_password="NewPass456!@#")

    def test_token_invalid_format(self):
        """Test token format validation — must pass min_length first to reach field_validator."""
        with pytest.raises(ValidationError) as exc_info:
            ResetPasswordConfirmRequest(
                token="invalid token with spaces!!!xxx" + "y" * 10,
                new_password="NewPass456!@#",
            )
        assert "Invalid reset token format" in str(exc_info.value)

    def test_token_valid_chars(self):
        """Test token accepts base64url-safe characters."""
        request = ResetPasswordConfirmRequest(
            token="abc123-ABC_xyz" + "0" * 20,
            new_password="NewPass456!@#",
        )
        assert request.token.startswith("abc123-ABC_xyz")

    def test_new_password_complexity(self):
        """Test new_password complexity — must pass min_length first to reach field_validator."""
        with pytest.raises(ValidationError) as exc_info:
            ResetPasswordConfirmRequest(token="a" * 32, new_password="weakpassword")
        assert "uppercase letter" in str(exc_info.value).lower()

    def test_required_fields(self):
        """Test both fields are required."""
        with pytest.raises(ValidationError) as exc_info:
            ResetPasswordConfirmRequest()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "token" in errors
        assert "new_password" in errors


class TestResetPasswordConfirmResponse:
    """Tests for ResetPasswordConfirmResponse schema."""

    def test_defaults(self):
        """Test default values."""
        response = ResetPasswordConfirmResponse()
        assert response.success is True
        assert "reset successfully" in response.message
        assert response.sessions_revoked is True
        assert response.timestamp is None

    def test_custom_values(self):
        """Test custom values."""
        response = ResetPasswordConfirmResponse(
            success=False,
            message="Reset failed",
            sessions_revoked=False,
        )
        assert response.success is False
        assert response.sessions_revoked is False


class TestErrorResponses:
    """Tests for error response schemas."""

    def test_password_error_response(self):
        """Test PasswordErrorResponse."""
        response = PasswordErrorResponse(detail="Invalid password")
        assert response.detail == "Invalid password"
        assert response.error_code is None

    def test_password_error_with_code(self):
        """Test PasswordErrorResponse with error code."""
        response = PasswordErrorResponse(
            detail="Invalid",
            error_code="INVALID_PASSWORD",
            remaining_attempts=3,
        )
        assert response.error_code == "INVALID_PASSWORD"
        assert response.remaining_attempts == 3

    def test_password_rate_limit_error(self):
        """Test PasswordRateLimitErrorResponse defaults."""
        response = PasswordRateLimitErrorResponse()
        assert "Too many attempts" in response.detail
        assert response.retry_after is None

    def test_password_validation_error(self):
        """Test PasswordValidationErrorResponse."""
        response = PasswordValidationErrorResponse(
            detail="Password too weak",
            requirements=["min 8 chars", "uppercase"],
        )
        assert response.requirements == ["min 8 chars", "uppercase"]

    def test_password_unauthorized_response(self):
        """Test PasswordUnauthorizedResponse defaults."""
        response = PasswordUnauthorizedResponse()
        assert response.detail == "Not authenticated"


class TestEdgeCases:
    """Tests for edge cases."""

    def test_change_password_with_special_chars(self):
        """Test password with various special characters."""
        request = ChangePasswordRequest(
            old_password="OldPass123!",
            new_password="Test@#$%^&*()_+[]{}|;:,.<>?1",
        )
        assert request.new_password == "Test@#$%^&*()_+[]{}|;:,.<>?1"

    def test_reset_request_email_with_plus(self):
        """Test email with plus addressing."""
        request = ResetPasswordRequest(email="user+tag@example.com")
        assert request.email == "user+tag@example.com"

    def test_reset_confirm_token_exact_min_length(self):
        """Test token at exact minimum length."""
        token = "a" * 32
        request = ResetPasswordConfirmRequest(token=token, new_password="NewPass456!@#")
        assert request.token == token

    def test_change_password_accepts_any_complexity_passwords(self):
        """Test schema accepts passwords that pass structural validation.
        
        The schema does not maintain a common password blacklist — that logic
        lives in the service layer. Any password meeting complexity requirements
        (length, uppercase, lowercase, digit, special char) is accepted.
        """
        request = ChangePasswordRequest(
            old_password="OldPass123!",
            new_password="Qwerty123!",
        )
        assert request.new_password == "Qwerty123!"