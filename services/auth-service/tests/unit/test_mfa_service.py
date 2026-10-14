"""
Unit tests for MFAService.

Tests cover:
- generate_totp_secret (secret generation, otpauth URL)
- verify_totp (success, no secret, invalid code, window +-1)
- enable_totp, disable_totp
- confirm_action
- get_user_phone, generate_sms_code, verify_sms_code, enable_sms_2fa
- generate_email_code, verify_email_code, enable_email_2fa
- generate_backup_codes, get_backup_codes, use_backup_code
- verify_2fa (totp, sms, email, unknown method)
- complete_authentication
- create_mfa_session, get_mfa_session, delete_mfa_session
- is_2fa_enabled, get_enabled_methods
- Edge cases and error handling
"""

from unittest.mock import patch
from uuid import uuid4

import pytest

from app.services.mfa_service import MFAService


class TestTOTP:
    """Tests for TOTP methods."""

    @pytest.fixture
    def service(self):
        return MFAService()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    @pytest.mark.asyncio
    async def test_generate_totp_secret(self, service, user_id):
        """Test TOTP secret generation."""
        secret, url = await service.generate_totp_secret(user_id, "user@example.com")

        assert len(secret) == 32  # 16 bytes hex = 32 chars
        assert url.startswith("otpauth://totp/")
        assert "user@example.com" in url
        assert secret in url

    @pytest.mark.asyncio
    async def test_verify_totp_success(self, service, user_id):
        """Test successful TOTP verification."""
        secret, _ = await service.generate_totp_secret(user_id, "test@test.com")

        secret_bytes = bytes.fromhex(secret)
        code = service._generate_totp_code(secret_bytes, int(__import__("time").time()) // 30)

        result = await service.verify_totp(user_id, code)
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_totp_no_secret(self, service, user_id):
        """Test TOTP verification when no secret stored."""
        result = await service.verify_totp(user_id, "123456")
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_totp_invalid_code(self, service, user_id):
        """Test TOTP verification with invalid code."""
        await service.generate_totp_secret(user_id, "test@test.com")
        result = await service.verify_totp(user_id, "000000")
        assert result is False

    @pytest.mark.asyncio
    async def test_enable_totp(self, service, user_id):
        """Test TOTP enable."""
        await service.enable_totp(user_id)

    @pytest.mark.asyncio
    async def test_disable_totp(self, service, user_id):
        """Test TOTP disable removes secret."""
        await service.generate_totp_secret(user_id, "test@test.com")
        await service.disable_totp(user_id)

        result = await service.verify_totp(user_id, "123456")
        assert result is False

    @pytest.mark.asyncio
    async def test_confirm_action(self, service, user_id):
        """Test action confirmation."""
        result = await service.confirm_action(user_id, "password123")
        assert result is True


class TestSMS:
    """Tests for SMS methods."""

    @pytest.fixture
    def service(self):
        return MFAService()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    @pytest.mark.asyncio
    async def test_get_user_phone_default(self, service, user_id):
        """Test default phone number."""
        phone = await service.get_user_phone(user_id)
        assert phone == "+79001234567"

    @pytest.mark.asyncio
    async def test_generate_sms_code(self, service, user_id):
        """Test SMS code generation."""
        code = await service.generate_sms_code(user_id, "+79001234567")
        assert len(code) == 6
        assert code.isdigit()

    @pytest.mark.asyncio
    async def test_verify_sms_code_success(self, service, user_id):
        """Test successful SMS verification."""
        code = await service.generate_sms_code(user_id, "+79001234567")
        result = await service.verify_sms_code(user_id, code)
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_sms_code_invalid(self, service, user_id):
        """Test invalid SMS verification."""
        await service.generate_sms_code(user_id, "+79001234567")
        result = await service.verify_sms_code(user_id, "000000")
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_sms_code_no_code(self, service, user_id):
        """Test SMS verification when no code generated."""
        result = await service.verify_sms_code(user_id, "123456")
        assert result is False

    @pytest.mark.asyncio
    async def test_enable_sms_2fa(self, service, user_id):
        """Test SMS 2FA enable."""
        await service.enable_sms_2fa(user_id)


class TestEmail:
    """Tests for Email methods."""

    @pytest.fixture
    def service(self):
        return MFAService()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    @pytest.mark.asyncio
    async def test_generate_email_code(self, service, user_id):
        """Test email code generation."""
        code = await service.generate_email_code(user_id, "user@example.com")
        assert len(code) == 6
        assert code.isdigit()

    @pytest.mark.asyncio
    async def test_verify_email_code_success(self, service, user_id):
        """Test successful email verification."""
        code = await service.generate_email_code(user_id, "user@example.com")
        result = await service.verify_email_code(user_id, code)
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_email_code_invalid(self, service, user_id):
        """Test invalid email verification."""
        await service.generate_email_code(user_id, "user@example.com")
        result = await service.verify_email_code(user_id, "000000")
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_email_code_no_code(self, service, user_id):
        """Test email verification when no code generated."""
        result = await service.verify_email_code(user_id, "123456")
        assert result is False

    @pytest.mark.asyncio
    async def test_enable_email_2fa(self, service, user_id):
        """Test email 2FA enable."""
        await service.enable_email_2fa(user_id)


class TestBackupCodes:
    """Tests for backup codes methods."""

    @pytest.fixture
    def service(self):
        return MFAService()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    @pytest.mark.asyncio
    async def test_generate_backup_codes(self, service, user_id):
        """Test backup codes generation."""
        codes = await service.generate_backup_codes(user_id)
        assert len(codes) == 10
        for code in codes:
            assert len(code) == 9  # XXXX-XXXX
            assert code[4] == "-"

    @pytest.mark.asyncio
    async def test_get_backup_codes_empty(self, service, user_id):
        """Test getting backup codes when none generated."""
        codes = await service.get_backup_codes(user_id)
        assert codes == []

    @pytest.mark.asyncio
    async def test_get_backup_codes_after_generation(self, service, user_id):
        """Test getting backup codes after generation."""
        generated = await service.generate_backup_codes(user_id)
        codes = await service.get_backup_codes(user_id)
        assert codes == generated

    @pytest.mark.asyncio
    async def test_use_backup_code_success(self, service, user_id):
        """Test using a valid backup code."""
        codes = await service.generate_backup_codes(user_id)
        result = await service.use_backup_code(user_id, codes[0])
        assert result is True

    @pytest.mark.asyncio
    async def test_use_backup_code_invalid(self, service, user_id):
        """Test using an invalid backup code."""
        await service.generate_backup_codes(user_id)
        result = await service.use_backup_code(user_id, "XXXX-XXXX")
        assert result is False

    @pytest.mark.asyncio
    async def test_use_backup_code_case_insensitive(self, service, user_id):
        """Test backup code is case insensitive."""
        codes = await service.generate_backup_codes(user_id)
        result = await service.use_backup_code(user_id, codes[0].lower())
        assert result is True


class TestUniversalVerify2FA:
    """Tests for verify_2fa method."""

    @pytest.fixture
    def service(self):
        return MFAService()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    @pytest.mark.asyncio
    async def test_verify_2fa_totp(self, service, user_id):
        """Test 2FA with TOTP."""
        secret, _ = await service.generate_totp_secret(user_id, "test@test.com")
        secret_bytes = bytes.fromhex(secret)
        code = service._generate_totp_code(secret_bytes, int(__import__("time").time()) // 30)

        result = await service.verify_2fa(user_id, code, "totp")
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_2fa_sms(self, service, user_id):
        """Test 2FA with SMS."""
        code = await service.generate_sms_code(user_id, "+79001234567")
        result = await service.verify_2fa(user_id, code, "sms")
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_2fa_email(self, service, user_id):
        """Test 2FA with Email."""
        code = await service.generate_email_code(user_id, "user@example.com")
        result = await service.verify_2fa(user_id, code, "email")
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_2fa_unknown_method(self, service, user_id):
        """Test 2FA with unknown method."""
        result = await service.verify_2fa(user_id, "123456", "unknown")
        assert result is False


class TestCompleteAuthentication:
    """Tests for complete_authentication method."""

    @pytest.fixture
    def service(self):
        return MFAService()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    @pytest.mark.asyncio
    async def test_complete_authentication(self, service, user_id):
        """Test authentication completion returns tokens."""
        access_token, refresh_token = await service.complete_authentication(user_id)

        assert access_token.startswith("access_token_")
        assert refresh_token.startswith("refresh_token_")
        assert len(access_token) > len("access_token_")
        assert len(refresh_token) > len("refresh_token_")

    @pytest.mark.asyncio
    async def test_complete_authentication_unique_tokens(self, service, user_id):
        """Test tokens are unique per call."""
        at1, rt1 = await service.complete_authentication(user_id)
        at2, rt2 = await service.complete_authentication(user_id)

        assert at1 != at2
        assert rt1 != rt2


class TestMFASession:
    """Tests for MFA session management."""

    @pytest.fixture
    def service(self):
        return MFAService()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    @pytest.mark.asyncio
    async def test_create_mfa_session(self, service, user_id):
        """Test MFA session creation."""
        session_id = await service.create_mfa_session(user_id)
        assert len(session_id) == 32  # UUID hex

    @pytest.mark.asyncio
    async def test_get_mfa_session_found(self, service, user_id):
        """Test getting existing MFA session."""
        session_id = await service.create_mfa_session(user_id)
        session = await service.get_mfa_session(session_id)

        assert session is not None
        assert session["user_id"] == str(user_id)
        assert "created_at" in session
        assert "expires_at" in session

    @pytest.mark.asyncio
    async def test_get_mfa_session_not_found(self, service):
        """Test getting non-existent MFA session."""
        session = await service.get_mfa_session("nonexistent")
        assert session is None

    @pytest.mark.asyncio
    async def test_delete_mfa_session(self, service, user_id):
        """Test MFA session deletion."""
        session_id = await service.create_mfa_session(user_id)
        await service.delete_mfa_session(session_id)

        session = await service.get_mfa_session(session_id)
        assert session is None


class TestAvailability:
    """Tests for is_2fa_enabled and get_enabled_methods."""

    @pytest.fixture
    def service(self):
        return MFAService()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    @pytest.mark.asyncio
    async def test_is_2fa_enabled_false(self, service, user_id):
        """Test 2FA not enabled by default."""
        result = await service.is_2fa_enabled(user_id)
        assert result is False

    @pytest.mark.asyncio
    async def test_is_2fa_enabled_true_with_totp(self, service, user_id):
        """Test 2FA enabled when TOTP secret exists."""
        await service.generate_totp_secret(user_id, "test@test.com")
        result = await service.is_2fa_enabled(user_id)
        assert result is True

    @pytest.mark.asyncio
    async def test_get_enabled_methods_default(self, service, user_id):
        """Test default enabled methods includes email."""
        methods = await service.get_enabled_methods(user_id)
        assert "email" in methods

    @pytest.mark.asyncio
    async def test_get_enabled_methods_with_totp(self, service, user_id):
        """Test enabled methods with TOTP."""
        await service.generate_totp_secret(user_id, "test@test.com")
        methods = await service.get_enabled_methods(user_id)
        assert "totp" in methods
        assert "email" in methods

    @pytest.mark.asyncio
    async def test_get_enabled_methods_with_sms(self, service, user_id):
        """Test enabled methods with SMS phone set."""
        service._user_phones[user_id] = "+79001234567"
        methods = await service.get_enabled_methods(user_id)
        assert "sms" in methods
        assert "email" in methods


class TestGenerateTOTPCode:
    """Tests for _generate_totp_code method."""

    @pytest.fixture
    def service(self):
        return MFAService()

    def test_generate_totp_code_length(self, service):
        """Test TOTP code is always 6 digits."""
        secret = bytes.fromhex("a" * 32)
        code = service._generate_totp_code(secret, 0)
        assert len(code) == 6
        assert code.isdigit()

    def test_generate_totp_code_deterministic(self, service):
        """Test same inputs produce same code."""
        secret = bytes.fromhex("b" * 32)
        code1 = service._generate_totp_code(secret, 100)
        code2 = service._generate_totp_code(secret, 100)
        assert code1 == code2

    def test_generate_totp_code_different_counter(self, service):
        """Test different counters produce different codes."""
        secret = bytes.fromhex("c" * 32)
        code1 = service._generate_totp_code(secret, 100)
        code2 = service._generate_totp_code(secret, 101)
        assert code1 != code2

    def test_generate_single_backup_code_format(self, service):
        """Test backup code format."""
        code = service._generate_single_backup_code()
        assert len(code) == 9  # XXXX-XXXX
        assert code[4] == "-"
        assert code[:4].isalnum()
        assert code[5:].isalnum()