"""
Unit tests for MFA Pydantic schemas.

Tests cover:
- TOTPSetupRequest/Response (secret_key, qr_code_url, qr_code_base64)
- TOTPVerifyRequest (code validation: digits, length 6)
- TOTPDisableRequest (password required)
- SMSSendRequest, SMSVerifyRequest, SMSSendResponse, SMSVerifyResponse
- EmailSendRequest, EmailVerifyRequest, EmailSendResponse, EmailVerifyResponse
- MFAVerifyRequest (mfa_session_id, code, method enum validation)
- MFAVerifyResponse (access_token, token_type, expires_in)
- BackupCodesResponse, BackupCodesRenewRequest/Response
- MFAMethod enum
- Error response schemas
- Edge cases and field validators

Note: Pydantic V2 applies pattern validation before field_validator.
"""

import pytest
from pydantic import ValidationError

from app.schemas.mfa import (
    BackupCodesRenewRequest,
    BackupCodesRenewResponse,
    BackupCodesResponse,
    EmailSendRequest,
    EmailSendResponse,
    EmailVerifyRequest,
    EmailVerifyResponse,
    MFAErrorResponse,
    MFAMethod,
    MFARateLimitErrorResponse,
    MFAUnauthorizedResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
    SMSSendRequest,
    SMSSendResponse,
    SMSVerifyRequest,
    SMSVerifyResponse,
    TOTPDisableRequest,
    TOTPDisableResponse,
    TOTPSetupRequest,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    TOTPVerifyResponse,
)


class TestMFAMethod:
    """Tests for MFAMethod enum."""

    def test_mfa_method_values(self):
        """Test MFAMethod has correct values."""
        assert MFAMethod.TOTP.value == "totp"
        assert MFAMethod.SMS.value == "sms"
        assert MFAMethod.EMAIL.value == "email"

    def test_mfa_method_from_string(self):
        """Test creating MFAMethod from string."""
        assert MFAMethod("totp") == MFAMethod.TOTP
        assert MFAMethod("sms") == MFAMethod.SMS
        assert MFAMethod("email") == MFAMethod.EMAIL

    def test_mfa_method_invalid(self):
        """Test invalid method raises error."""
        with pytest.raises(ValueError):
            MFAMethod("invalid")


class TestTOTPSetupRequest:
    """Tests for TOTPSetupRequest."""

    def test_totp_setup_request_empty(self):
        """Test TOTPSetupRequest accepts empty body."""
        request = TOTPSetupRequest()
        assert request is not None


class TestTOTPSetupResponse:
    """Tests for TOTPSetupResponse."""

    def test_valid_response(self):
        """Test creating valid TOTP setup response."""
        response = TOTPSetupResponse(
            secret_key="JBSWY3DPEHPK3PXP",
            qr_code_url="otpauth://totp/Marketplace:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Marketplace",
            qr_code_base64="data:image/png;base64,iVBORw0KGgoAAAANS...",
        )
        assert response.secret_key == "JBSWY3DPEHPK3PXP"
        assert response.qr_code_url.startswith("otpauth://")
        assert response.qr_code_base64 is not None

    def test_required_fields(self):
        """Test all fields are required."""
        with pytest.raises(ValidationError) as exc_info:
            TOTPSetupResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"secret_key", "qr_code_url", "qr_code_base64"}
        assert required_fields.issubset(errors)


class TestTOTPVerifyRequest:
    """Tests for TOTPVerifyRequest."""

    def test_valid_request(self):
        """Test valid TOTP verification request."""
        request = TOTPVerifyRequest(code="123456")
        assert request.code == "123456"

    def test_non_digits(self):
        """Test code must contain only digits."""
        with pytest.raises(ValidationError):
            TOTPVerifyRequest(code="12345a")

    def test_wrong_length(self):
        """Test code must be exactly 6 digits."""
        with pytest.raises(ValidationError):
            TOTPVerifyRequest(code="12345")
        with pytest.raises(ValidationError):
            TOTPVerifyRequest(code="1234567")

    def test_required_field(self):
        """Test code field is required."""
        with pytest.raises(ValidationError):
            TOTPVerifyRequest()

    def test_pattern_error_message(self):
        """Test pattern validation error (Pydantic V2 applies pattern before field_validator)."""
        with pytest.raises(ValidationError) as exc_info:
            TOTPVerifyRequest(code="abcde1")
        assert "string_pattern_mismatch" in str(exc_info.value)


class TestTOTPVerifyResponse:
    """Tests for TOTPVerifyResponse."""

    def test_valid_response(self):
        """Test valid TOTP verify response."""
        response = TOTPVerifyResponse(
            success=True,
            backup_codes=["ABCD-1234", "EFGH-5678"],
        )
        assert response.success is True
        assert len(response.backup_codes) == 2
        assert response.message == "TOTP enabled successfully"

    def test_custom_message(self):
        """Test custom message."""
        response = TOTPVerifyResponse(
            success=False,
            message="Invalid code",
            backup_codes=[],
        )
        assert response.message == "Invalid code"

    def test_required_fields(self):
        """Test required fields."""
        with pytest.raises(ValidationError) as exc_info:
            TOTPVerifyResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        assert "success" in errors
        assert "backup_codes" in errors


class TestTOTPDisableRequest:
    """Tests for TOTPDisableRequest."""

    def test_valid_request(self):
        """Test valid disable request."""
        request = TOTPDisableRequest(password="mysecretpassword")
        assert request.password == "mysecretpassword"

    def test_password_required(self):
        """Test password is required."""
        with pytest.raises(ValidationError):
            TOTPDisableRequest()

    def test_password_min_length(self):
        """Test password must be at least 1 character."""
        request = TOTPDisableRequest(password="a")
        assert request.password == "a"


class TestTOTPDisableResponse:
    """Tests for TOTPDisableResponse."""

    def test_valid_response(self):
        """Test valid disable response."""
        response = TOTPDisableResponse(success=True)
        assert response.success is True
        assert response.message == "TOTP disabled successfully"

    def test_custom_message(self):
        """Test custom message."""
        response = TOTPDisableResponse(success=False, message="Disable failed")
        assert response.message == "Disable failed"


class TestSMSSendRequest:
    """Tests for SMSSendRequest."""

    def test_valid_request(self):
        """Test SMS send request accepts empty body."""
        request = SMSSendRequest()
        assert request is not None


class TestSMSVerifyRequest:
    """Tests for SMSVerifyRequest."""

    def test_valid_request(self):
        """Test valid SMS verification request."""
        request = SMSVerifyRequest(code="123456")
        assert request.code == "123456"

    def test_non_digits(self):
        """Test code must contain only digits."""
        with pytest.raises(ValidationError):
            SMSVerifyRequest(code="12345a")

    def test_wrong_length(self):
        """Test code must be exactly 6 digits."""
        with pytest.raises(ValidationError):
            SMSVerifyRequest(code="12345")
        with pytest.raises(ValidationError):
            SMSVerifyRequest(code="1234567")

    def test_required_field(self):
        """Test code field is required."""
        with pytest.raises(ValidationError):
            SMSVerifyRequest()


class TestSMSSendResponse:
    """Tests for SMSSendResponse."""

    def test_defaults(self):
        """Test default values."""
        response = SMSSendResponse(success=True)
        assert response.method == "sms"
        assert response.message == "SMS code sent successfully"
        assert response.expires_in == 300

    def test_custom_values(self):
        """Test custom values."""
        response = SMSSendResponse(
            success=False,
            message="Failed",
            expires_in=60,
        )
        assert response.success is False
        assert response.expires_in == 60


class TestSMSVerifyResponse:
    """Tests for SMSVerifyResponse."""

    def test_valid_response(self):
        """Test valid SMS verify response."""
        response = SMSVerifyResponse(success=True)
        assert response.success is True
        assert response.message == "SMS 2FA enabled successfully"

    def test_custom_message(self):
        """Test custom message."""
        response = SMSVerifyResponse(success=False, message="Invalid code")
        assert response.message == "Invalid code"


class TestEmailSendRequest:
    """Tests for EmailSendRequest."""

    def test_valid_request(self):
        """Test Email send request accepts empty body."""
        request = EmailSendRequest()
        assert request is not None


class TestEmailVerifyRequest:
    """Tests for EmailVerifyRequest."""

    def test_valid_request(self):
        """Test valid Email verification request."""
        request = EmailVerifyRequest(code="654321")
        assert request.code == "654321"

    def test_non_digits(self):
        """Test code must contain only digits."""
        with pytest.raises(ValidationError):
            EmailVerifyRequest(code="abc123")

    def test_wrong_length(self):
        """Test code must be exactly 6 digits."""
        with pytest.raises(ValidationError):
            EmailVerifyRequest(code="12345")
        with pytest.raises(ValidationError):
            EmailVerifyRequest(code="1234567")

    def test_required_field(self):
        """Test code field is required."""
        with pytest.raises(ValidationError):
            EmailVerifyRequest()


class TestEmailSendResponse:
    """Tests for EmailSendResponse."""

    def test_defaults(self):
        """Test default values."""
        response = EmailSendResponse(success=True)
        assert response.method == "email"
        assert response.message == "Email code sent successfully"
        assert response.expires_in == 300

    def test_custom_values(self):
        """Test custom values."""
        response = EmailSendResponse(
            success=False,
            message="Send failed",
            expires_in=120,
        )
        assert response.success is False
        assert response.expires_in == 120


class TestEmailVerifyResponse:
    """Tests for EmailVerifyResponse."""

    def test_valid_response(self):
        """Test valid Email verify response."""
        response = EmailVerifyResponse(success=True)
        assert response.success is True
        assert response.message == "Email 2FA enabled successfully"

    def test_custom_message(self):
        """Test custom message."""
        response = EmailVerifyResponse(success=False, message="Invalid code")
        assert response.message == "Invalid code"


class TestMFAVerifyRequest:
    """Tests for MFAVerifyRequest."""

    def test_valid_request_totp(self):
        """Test valid MFA verify request with TOTP."""
        request = MFAVerifyRequest(
            mfa_session_id="session_abc123",
            code="123456",
            method=MFAMethod.TOTP,
        )
        assert request.mfa_session_id == "session_abc123"
        assert request.code == "123456"
        assert request.method == MFAMethod.TOTP

    def test_valid_request_sms(self):
        """Test valid MFA verify request with SMS."""
        request = MFAVerifyRequest(
            mfa_session_id="session_abc123",
            code="654321",
            method=MFAMethod.SMS,
        )
        assert request.method == MFAMethod.SMS

    def test_valid_request_email(self):
        """Test valid MFA verify request with Email."""
        request = MFAVerifyRequest(
            mfa_session_id="session_abc123",
            code="111222",
            method=MFAMethod.EMAIL,
        )
        assert request.method == MFAMethod.EMAIL

    def test_method_from_string(self):
        """Test method accepts string values."""
        request = MFAVerifyRequest(
            mfa_session_id="session",
            code="123456",
            method="totp",
        )
        assert request.method == MFAMethod.TOTP

    def test_invalid_method(self):
        """Test invalid method raises error."""
        with pytest.raises(ValidationError):
            MFAVerifyRequest(
                mfa_session_id="session",
                code="123456",
                method="invalid",
            )

    def test_code_validation(self):
        """Test code must be 6 digits."""
        with pytest.raises(ValidationError):
            MFAVerifyRequest(
                mfa_session_id="session",
                code="12345",
                method=MFAMethod.TOTP,
            )

    def test_required_fields(self):
        """Test all fields are required."""
        with pytest.raises(ValidationError) as exc_info:
            MFAVerifyRequest()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"mfa_session_id", "code", "method"}
        assert required_fields.issubset(errors)

    def test_mfa_session_id_min_length(self):
        """Test mfa_session_id must be at least 1 character."""
        with pytest.raises(ValidationError):
            MFAVerifyRequest(
                mfa_session_id="",
                code="123456",
                method=MFAMethod.TOTP,
            )


class TestMFAVerifyResponse:
    """Tests for MFAVerifyResponse."""

    def test_valid_response(self):
        """Test valid MFA verify response."""
        response = MFAVerifyResponse(access_token="eyJhbGciOiJSUzI1NiIs...")
        assert response.access_token == "eyJhbGciOiJSUzI1NiIs..."
        assert response.token_type == "bearer"
        assert response.expires_in == 3600

    def test_custom_values(self):
        """Test custom values."""
        response = MFAVerifyResponse(
            access_token="token",
            token_type="custom",
            expires_in=900,
        )
        assert response.token_type == "custom"
        assert response.expires_in == 900

    def test_required_fields(self):
        """Test access_token is required."""
        with pytest.raises(ValidationError) as exc_info:
            MFAVerifyResponse()
        assert "access_token" in str(exc_info.value)


class TestBackupCodesResponse:
    """Tests for BackupCodesResponse."""

    def test_valid_response(self):
        """Test valid backup codes response."""
        codes = ["ABCD-1234", "EFGH-5678"]
        response = BackupCodesResponse(backup_codes=codes)
        assert response.backup_codes == codes

    def test_empty_codes(self):
        """Test empty list."""
        response = BackupCodesResponse(backup_codes=[])
        assert response.backup_codes == []

    def test_required_fields(self):
        """Test backup_codes is required."""
        with pytest.raises(ValidationError):
            BackupCodesResponse()


class TestBackupCodesRenewRequest:
    """Tests for BackupCodesRenewRequest."""

    def test_valid_request(self):
        """Test renew request accepts empty body."""
        request = BackupCodesRenewRequest()
        assert request is not None


class TestBackupCodesRenewResponse:
    """Tests for BackupCodesRenewResponse."""

    def test_valid_response(self):
        """Test valid renew response."""
        codes = ["NEW1-2345", "NEW2-3456"]
        response = BackupCodesRenewResponse(
            success=True,
            backup_codes=codes,
        )
        assert response.success is True
        assert response.backup_codes == codes
        assert response.message == "Backup codes regenerated successfully"

    def test_custom_message(self):
        """Test custom message."""
        response = BackupCodesRenewResponse(
            success=True,
            backup_codes=["CODE1"],
            message="Custom message",
        )
        assert response.message == "Custom message"

    def test_required_fields(self):
        """Test required fields."""
        with pytest.raises(ValidationError) as exc_info:
            BackupCodesRenewResponse()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"success", "backup_codes"}
        assert required_fields.issubset(errors)


class TestErrorResponses:
    """Tests for error response schemas."""

    def test_mfa_error_response(self):
        """Test MFAErrorResponse."""
        response = MFAErrorResponse(detail="Something went wrong")
        assert response.detail == "Something went wrong"
        assert response.error_code is None

    def test_mfa_error_response_with_code(self):
        """Test MFAErrorResponse with error code."""
        response = MFAErrorResponse(detail="Invalid", error_code="INVALID_CODE")
        assert response.error_code == "INVALID_CODE"

    def test_mfa_rate_limit_error_response(self):
        """Test MFARateLimitErrorResponse defaults."""
        response = MFARateLimitErrorResponse()
        assert "Too many requests" in response.detail
        assert response.retry_after is None

    def test_mfa_rate_limit_error_with_retry(self):
        """Test MFARateLimitErrorResponse with retry_after."""
        response = MFARateLimitErrorResponse(retry_after=60)
        assert response.retry_after == 60

    def test_mfa_unauthorized_response(self):
        """Test MFAUnauthorizedResponse defaults."""
        response = MFAUnauthorizedResponse()
        assert response.detail == "Not authenticated"


class TestEdgeCases:
    """Tests for edge cases across MFA schemas."""

    def test_totp_verify_code_with_leading_zeros(self):
        """Test TOTP code with leading zeros."""
        request = TOTPVerifyRequest(code="001234")
        assert request.code == "001234"

    def test_mfa_verify_code_with_spaces_fails(self):
        """Test MFA verify code with spaces fails pattern validation."""
        with pytest.raises(ValidationError):
            MFAVerifyRequest(
                mfa_session_id="session",
                code="  123456  ",
                method=MFAMethod.TOTP,
            )

    def test_totp_setup_response_qr_code_base64(self):
        """Test qr_code_base64 is required."""
        response = TOTPSetupResponse(
            secret_key="SECRET",
            qr_code_url="otpauth://...",
            qr_code_base64="base64string",
        )
        assert response.qr_code_base64 == "base64string"

    def test_sms_send_response_defaults(self):
        """Test SMS send response has correct defaults."""
        response = SMSSendResponse(success=True)
        assert response.method == "sms"
        assert response.expires_in == 300

    def test_email_send_response_defaults(self):
        """Test Email send response has correct defaults."""
        response = EmailSendResponse(success=True)
        assert response.method == "email"
        assert response.expires_in == 300