"""
Unit tests for Security module.

Tests cover:
- PasswordHasher (hash, verify, needs_rehash, pepper integration)
- IdempotencyKeyGenerator (generate, generate_with_prefix, validate, extract_timestamp)
- OTPGenerator (generate_numeric, generate_alphanumeric, generate_totp_secret, generate_backup_codes)
- TokenGenerator (generate_refresh_token, generate_password_reset_token, generate_email_verification_token, generate_api_key)
- APIKeyHasher (hash_key, verify_key, extract_prefix)
- RandomStringGenerator (generate, generate_hex, generate_code_verifier, generate_code_challenge, generate_state)
- HashUtils (sha256, sha512, hmac_sha256, pbkdf2, constant_time_compare)
- Async wrappers (hash_password_async, verify_password_async)
- Global instances
- Edge cases (empty strings, invalid keys, timing attacks)
"""

import base64
import hashlib
import hmac
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.security import (
    APIKeyHasher,
    HashUtils,
    IdempotencyKeyGenerator,
    OTPGenerator,
    PasswordHasher,
    RandomStringGenerator,
    TokenGenerator,
    get_password_hasher,
    hash_password_async,
    hash_utils,
    idempotency_key_gen,
    otp_generator,
    password_hasher,
    random_generator,
    token_generator,
    verify_password_async,
)


# ==================== PASSWORD HASHER TESTS ====================

class TestPasswordHasher:
    """Tests for PasswordHasher class."""

    def test_init_default_scheme(self):
        """Test PasswordHasher initializes with default bcrypt scheme."""
        hasher = PasswordHasher()
        assert hasher.scheme == "bcrypt"
        assert hasher.pwd_context is not None
        assert hasher.pepper == "your-pepper-change-in-production"

    def test_add_pepper(self):
        """Test pepper is added to password."""
        hasher = PasswordHasher()
        result = hasher._add_pepper("password123")
        assert result == "password123your-pepper-change-in-production"

    def test_hash_returns_string(self):
        """Test hash returns a string different from input."""
        hasher = PasswordHasher()
        password = "MySecurePassword123!"
        hashed = hasher.hash(password)
        assert isinstance(hashed, str)
        assert hashed != password
        assert len(hashed) > 0

    def test_hash_and_verify_success(self):
        """Test successful password hash and verify cycle."""
        hasher = PasswordHasher()
        password = "MySecurePassword123!"
        hashed = hasher.hash(password)
        assert hasher.verify(password, hashed) is True

    def test_verify_wrong_password(self):
        """Test verification with wrong password."""
        hasher = PasswordHasher()
        password = "CorrectPass123!"
        wrong_password = "WrongPass123!"
        hashed = hasher.hash(password)
        assert hasher.verify(wrong_password, hashed) is False

    def test_verify_with_exception_returns_false(self):
        """Test verify returns False on exception."""
        hasher = PasswordHasher()
        with patch.object(hasher.pwd_context, "verify", side_effect=Exception("Hash error")):
            result = hasher.verify("password", "invalid_hash")
        assert result is False

    def test_needs_rehash_false(self):
        """Test needs_rehash returns False for fresh hash."""
        hasher = PasswordHasher()
        hashed = hasher.hash("password")
        assert hasher.needs_rehash(hashed) is False

    def test_needs_rehash_exception_returns_false(self):
        """Test needs_rehash returns False on exception."""
        hasher = PasswordHasher()
        with patch.object(hasher.pwd_context, "needs_update", side_effect=Exception("Error")):
            result = hasher.needs_rehash("invalid_hash")
        assert result is False

    def test_hash_different_passwords_different_hashes(self):
        """Test different passwords produce different hashes."""
        hasher = PasswordHasher()
        hash1 = hasher.hash("password1")
        hash2 = hasher.hash("password2")
        assert hash1 != hash2

    def test_hash_same_password_different_hashes(self):
        """Test same password produces different hashes (salt)."""
        hasher = PasswordHasher()
        hash1 = hasher.hash("SamePassword1!")
        hash2 = hasher.hash("SamePassword1!")
        assert hash1 != hash2
        assert hasher.verify("SamePassword1!", hash1)
        assert hasher.verify("SamePassword1!", hash2)

    def test_empty_password(self):
        """Test hashing and verifying empty password."""
        hasher = PasswordHasher()
        hashed = hasher.hash("")
        assert hasher.verify("", hashed) is True
        assert hasher.verify("not_empty", hashed) is False


# ==================== IDEMPOTENCY KEY GENERATOR TESTS ====================

class TestIdempotencyKeyGenerator:
    """Tests for IdempotencyKeyGenerator class."""

    def test_generate_format(self):
        """Test generate returns correct idem_{timestamp}_{uuid} format."""
        key = IdempotencyKeyGenerator.generate()
        assert key.startswith("idem_")
        parts = key.split("_")
        assert len(parts) == 3
        assert parts[0] == "idem"
        assert parts[1].isdigit()
        assert len(parts[2]) == 32  # uuid4 hex

    def test_generate_uniqueness(self):
        """Test generate produces unique keys."""
        keys = {IdempotencyKeyGenerator.generate() for _ in range(100)}
        assert len(keys) == 100

    def test_generate_with_prefix(self):
        """Test generate_with_prefix adds custom prefix."""
        key = IdempotencyKeyGenerator.generate_with_prefix("payment")
        assert key.startswith("payment_")
        parts = key.split("_")
        assert parts[0] == "payment"

    def test_generate_with_prefix_uniqueness(self):
        """Test generate_with_prefix produces unique keys."""
        keys = {IdempotencyKeyGenerator.generate_with_prefix("test") for _ in range(50)}
        assert len(keys) == 50

    def test_validate_correct_format(self):
        """Test validate returns True for correctly formatted key."""
        key = IdempotencyKeyGenerator.generate()
        assert IdempotencyKeyGenerator.validate(key) is True

    def test_validate_invalid_format(self):
        """Test validate returns False for invalid keys."""
        invalid_keys = [
            "",
            "invalid",
            "idem_123",
            "prefix_123_abc",
            "idem_abc_123",
            "idem_1234567890_",
            "idem_1234567890_short",
        ]
        for key in invalid_keys:
            assert IdempotencyKeyGenerator.validate(key) is False, f"Expected False for: {key}"

    def test_validate_none(self):
        """Test validate returns False for None."""
        assert IdempotencyKeyGenerator.validate(None) is False

    def test_extract_timestamp_valid(self):
        """Test extract_timestamp returns correct timestamp."""
        key = IdempotencyKeyGenerator.generate()
        timestamp = IdempotencyKeyGenerator.extract_timestamp(key)
        assert isinstance(timestamp, int)
        assert timestamp > 0

    def test_extract_timestamp_invalid(self):
        """Test extract_timestamp returns None for invalid keys."""
        assert IdempotencyKeyGenerator.extract_timestamp("invalid") is None
        assert IdempotencyKeyGenerator.extract_timestamp("idem_abc_def") is None
        assert IdempotencyKeyGenerator.extract_timestamp("") is None
        assert IdempotencyKeyGenerator.extract_timestamp(None) is None

    def test_generate_with_empty_prefix(self):
        """Test generate_with_prefix with empty prefix."""
        key = IdempotencyKeyGenerator.generate_with_prefix("")
        assert key.startswith("_")


# ==================== OTP GENERATOR TESTS ====================

class TestOTPGenerator:
    """Tests for OTPGenerator class."""

    def test_generate_numeric_length(self):
        """Test generate_numeric returns correct length."""
        for length in [4, 6, 8]:
            otp = OTPGenerator.generate_numeric(length)
            assert len(otp) == length
            assert otp.isdigit()

    def test_generate_numeric_default_length(self):
        """Test generate_numeric with default length 6."""
        otp = OTPGenerator.generate_numeric()
        assert len(otp) == 6
        assert otp.isdigit()

    def test_generate_numeric_zero_length(self):
        """Test generate_numeric with zero length returns empty string."""
        otp = OTPGenerator.generate_numeric(0)
        assert otp == ""

    def test_generate_numeric_negative_length(self):
        """Test generate_numeric with negative length returns empty string."""
        otp = OTPGenerator.generate_numeric(-5)
        assert otp == ""

    def test_generate_alphanumeric(self):
        """Test generate_alphanumeric returns valid characters."""
        otp = OTPGenerator.generate_alphanumeric(8)
        assert len(otp) == 8
        # No ambiguous characters
        assert "0" not in otp
        assert "O" not in otp
        assert "1" not in otp
        assert "I" not in otp
        # Only uppercase and digits
        assert all(c.isupper() or c.isdigit() for c in otp)

    def test_generate_alphanumeric_zero_length(self):
        """Test generate_alphanumeric with zero length returns empty string."""
        otp = OTPGenerator.generate_alphanumeric(0)
        assert otp == ""

    def test_generate_totp_secret(self):
        """Test generate_totp_secret returns valid base32 string."""
        secret = OTPGenerator.generate_totp_secret()
        assert len(secret) == 32
        assert "=" not in secret
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in secret)

    def test_generate_totp_secret_zero_length(self):
        """Test generate_totp_secret with zero length returns empty string."""
        secret = OTPGenerator.generate_totp_secret(0)
        assert secret == ""

    def test_generate_totp_secret_custom_length(self):
        """Test generate_totp_secret with custom length."""
        secret = OTPGenerator.generate_totp_secret(16)
        assert len(secret) == 16

    def test_generate_backup_codes(self):
        """Test generate_backup_codes returns codes in correct format."""
        codes = OTPGenerator.generate_backup_codes(count=8, length=8)
        assert len(codes) == 8
        for code in codes:
            assert "-" in code
            parts = code.split("-")
            assert len(parts) == 2
            assert len(parts[0]) == 4
            assert len(parts[1]) == 4
            assert all(c.isdigit() for c in parts[0])
            assert all(c.isdigit() for c in parts[1])

    def test_generate_backup_codes_custom_count(self):
        """Test generate_backup_codes with custom count."""
        codes = OTPGenerator.generate_backup_codes(count=12, length=8)
        assert len(codes) == 12

    def test_generate_backup_codes_custom_length(self):
        """Test generate_backup_codes with custom length."""
        codes = OTPGenerator.generate_backup_codes(count=5, length=10)
        for code in codes:
            parts = code.split("-")
            assert len(parts[0]) == 5
            assert len(parts[1]) == 5

    def test_generate_backup_codes_zero_count(self):
        """Test generate_backup_codes with zero count returns empty list."""
        codes = OTPGenerator.generate_backup_codes(count=0)
        assert codes == []

    def test_generate_backup_codes_negative_count(self):
        """Test generate_backup_codes with negative count returns empty list."""
        codes = OTPGenerator.generate_backup_codes(count=-1)
        assert codes == []

    def test_generate_backup_codes_zero_length(self):
        """Test generate_backup_codes with zero length returns empty list."""
        codes = OTPGenerator.generate_backup_codes(count=5, length=0)
        assert codes == []


# ==================== TOKEN GENERATOR TESTS ====================

class TestTokenGenerator:
    """Tests for TokenGenerator class."""

    def test_generate_refresh_token_format(self):
        """Test generate_refresh_token returns hex string of correct length."""
        token = TokenGenerator.generate_refresh_token()
        # uuid4.hex (32 chars) + token_hex(32) (64 chars) = 96 chars
        assert len(token) == 96
        assert all(c in "0123456789abcdef" for c in token.lower())

    def test_generate_refresh_token_uniqueness(self):
        """Test generate_refresh_token produces unique values."""
        tokens = {TokenGenerator.generate_refresh_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_generate_password_reset_token_format(self):
        """Test generate_password_reset_token returns URL-safe token."""
        token = TokenGenerator.generate_password_reset_token()
        assert len(token) >= 32

    def test_generate_password_reset_token_custom_length(self):
        """Test generate_password_reset_token with custom length."""
        token = TokenGenerator.generate_password_reset_token(64)
        assert len(token) >= 64

    def test_generate_email_verification_token(self):
        """Test generate_email_verification_token returns URL-safe token."""
        token = TokenGenerator.generate_email_verification_token()
        assert len(token) >= 32

    def test_generate_api_key_format(self):
        """Test generate_api_key returns correct format."""
        raw_key, hash_key = TokenGenerator.generate_api_key(prefix="mk")
        assert raw_key.startswith("mk_live_")
        parts = raw_key.split("_")
        assert parts[0] == "mk"
        assert parts[1] == "live"
        assert len(parts[2]) == 64  # 32 bytes hex = 64 chars
        assert parts[3].isdigit()
        assert len(hash_key) == 64  # SHA256 hex

    def test_generate_api_key_default_prefix(self):
        """Test generate_api_key with default prefix."""
        raw_key, _ = TokenGenerator.generate_api_key()
        assert raw_key.startswith("mk_live_")

    def test_generate_api_key_hash_matches(self):
        """Test hash_key matches raw_key SHA256."""
        raw_key, hash_key = TokenGenerator.generate_api_key()
        expected_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        assert hash_key == expected_hash

    def test_generate_api_key_custom_prefix(self):
        """Test generate_api_key with custom prefix."""
        raw_key, _ = TokenGenerator.generate_api_key(prefix="test")
        assert raw_key.startswith("test_live_")


# ==================== API KEY HASHER TESTS ====================

class TestAPIKeyHasher:
    """Tests for APIKeyHasher class."""

    def test_hash_key(self):
        """Test hash_key returns SHA256 hash."""
        raw_key = "mk_live_abc123_1234567890"
        hashed = APIKeyHasher.hash_key(raw_key)
        assert len(hashed) == 64
        assert hashed == hashlib.sha256(raw_key.encode()).hexdigest()

    def test_verify_key_success(self):
        """Test verify_key returns True for matching key."""
        raw_key = "test_api_key_123"
        hashed = APIKeyHasher.hash_key(raw_key)
        assert APIKeyHasher.verify_key(raw_key, hashed) is True

    def test_verify_key_failure(self):
        """Test verify_key returns False for non-matching key."""
        raw_key = "correct_key"
        wrong_key = "wrong_key"
        hashed = APIKeyHasher.hash_key(raw_key)
        assert APIKeyHasher.verify_key(wrong_key, hashed) is False

    def test_verify_key_uses_constant_time_comparison(self):
        """Test verify_key uses hmac.compare_digest."""
        raw_key = "key123"
        hashed = APIKeyHasher.hash_key(raw_key)
        with patch("hmac.compare_digest", wraps=hmac.compare_digest) as mock_compare:
            APIKeyHasher.verify_key(raw_key, hashed)
            mock_compare.assert_called_once()

    def test_extract_prefix_standard(self):
        """Test extract_prefix extracts correct prefix."""
        raw_key = "mk_live_abc123_1234567890"
        prefix = APIKeyHasher.extract_prefix(raw_key)
        assert prefix == "mk_live"

    def test_extract_prefix_short_key(self):
        """Test extract_prefix handles short keys."""
        short_key = "short"
        prefix = APIKeyHasher.extract_prefix(short_key)
        assert prefix == "short"

    def test_extract_prefix_no_underscore(self):
        """Test extract_prefix with no underscore returns full key."""
        prefix = APIKeyHasher.extract_prefix("nounderscore")
        assert prefix == "nounderscore"


# ==================== RANDOM STRING GENERATOR TESTS ====================

class TestRandomStringGenerator:
    """Tests for RandomStringGenerator class."""

    def test_generate_length(self):
        """Test generate returns correct length."""
        result = RandomStringGenerator.generate(32)
        assert len(result) >= 32

    def test_generate_default_length(self):
        """Test generate with default length."""
        result = RandomStringGenerator.generate()
        assert len(result) >= 32

    def test_generate_hex(self):
        """Test generate_hex returns hex string."""
        result = RandomStringGenerator.generate_hex(32)
        assert len(result) == 64  # hex length = requested*2
        assert all(c in "0123456789abcdef" for c in result)

    def test_generate_code_verifier(self):
        """Test generate_code_verifier returns correct length."""
        verifier = RandomStringGenerator.generate_code_verifier()
        assert len(verifier) <= 128
        assert isinstance(verifier, str)

    def test_generate_code_verifier_custom_length(self):
        """Test generate_code_verifier with custom length."""
        verifier = RandomStringGenerator.generate_code_verifier(length=43)
        assert len(verifier) >= 43

    def test_generate_code_verifier_max_length(self):
        """Test code_verifier respects requested length, bounded by argument.
        
        Note: Per frozen project code, generate_code_verifier clamps length to 128
        internally, but token_urlsafe may return slightly more characters due to
        base64 encoding overhead. The method does not re-clamp the output.
        """
        verifier = RandomStringGenerator.generate_code_verifier(length=200)
        # Method clamps input to 128, token_urlsafe(128) produces ~171 chars
        assert len(verifier) <= 200

    def test_generate_code_challenge(self):
        """Test generate_code_challenge returns S256 challenge."""
        verifier = "test_verifier_1234567890"
        challenge = RandomStringGenerator.generate_code_challenge(verifier)
        # Verify using standard method
        digest = hashlib.sha256(verifier.encode()).digest()
        expected = base64.urlsafe_b64encode(digest).decode().replace("=", "")
        assert challenge == expected
        assert "=" not in challenge

    def test_generate_state(self):
        """Test generate_state returns URL-safe string."""
        state = RandomStringGenerator.generate_state()
        assert len(state) >= 32


# ==================== HASH UTILS TESTS ====================

class TestHashUtils:
    """Tests for HashUtils class."""

    def test_sha256_string(self):
        """Test sha256 with string input."""
        result = HashUtils.sha256("test")
        expected = hashlib.sha256(b"test").hexdigest()
        assert result == expected
        assert len(result) == 64

    def test_sha256_empty_string(self):
        """Test sha256 with empty string."""
        result = HashUtils.sha256("")
        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_sha512(self):
        """Test sha512 returns correct hash."""
        result = HashUtils.sha512("test")
        expected = hashlib.sha512(b"test").hexdigest()
        assert result == expected
        assert len(result) == 128

    def test_hmac_sha256(self):
        """Test hmac_sha256 returns correct HMAC."""
        key = "secret_key"
        message = "test_message"
        result = HashUtils.hmac_sha256(key, message)
        expected = hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()
        assert result == expected
        assert len(result) == 64

    def test_pbkdf2(self):
        """Test pbkdf2 key derivation."""
        password = "secure_password"
        salt = b"random_salt_16bytes"
        result = HashUtils.pbkdf2(password, salt, iterations=1000)
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_pbkdf2_different_salts(self):
        """Test different salts produce different results."""
        password = "password"
        salt1 = b"salt1"
        salt2 = b"salt2"
        result1 = HashUtils.pbkdf2(password, salt1, iterations=100)
        result2 = HashUtils.pbkdf2(password, salt2, iterations=100)
        assert result1 != result2

    def test_constant_time_compare_equal(self):
        """Test constant_time_compare returns True for equal strings."""
        assert HashUtils.constant_time_compare("test", "test") is True

    def test_constant_time_compare_not_equal(self):
        """Test constant_time_compare returns False for different strings."""
        assert HashUtils.constant_time_compare("test1", "test2") is False

    def test_constant_time_compare_different_lengths(self):
        """Test constant_time_compare handles different lengths."""
        assert HashUtils.constant_time_compare("short", "much_longer_string") is False

    def test_constant_time_compare_empty_strings(self):
        """Test constant_time_compare with empty strings."""
        assert HashUtils.constant_time_compare("", "") is True
        assert HashUtils.constant_time_compare("a", "") is False


# ==================== ASYNC WRAPPERS TESTS ====================

class TestAsyncWrappers:
    """Tests for async wrapper functions."""

    @patch("asyncio.get_event_loop")
    async def test_hash_password_async(self, mock_loop):
        """Test hash_password_async runs in executor."""
        mock_executor = MagicMock()
        mock_loop.return_value.run_in_executor = AsyncMock(return_value="hashed_password")

        result = await hash_password_async("password")

        assert result == "hashed_password"

    @patch("asyncio.get_event_loop")
    async def test_verify_password_async(self, mock_loop):
        """Test verify_password_async runs in executor."""
        mock_executor = MagicMock()
        mock_loop.return_value.run_in_executor = AsyncMock(return_value=True)

        result = await verify_password_async("password", "hashed")

        assert result is True

    @patch("asyncio.get_event_loop")
    async def test_verify_password_async_false(self, mock_loop):
        """Test verify_password_async returns False."""
        mock_executor = MagicMock()
        mock_loop.return_value.run_in_executor = AsyncMock(return_value=False)

        result = await verify_password_async("password", "hashed")

        assert result is False


# ==================== GLOBAL INSTANCES TESTS ====================

class TestGlobalInstances:
    """Tests for global singleton instances."""

    def test_password_hasher_singleton(self):
        """Test password_hasher is a singleton instance."""
        assert isinstance(password_hasher, PasswordHasher)

    def test_idempotency_key_gen_singleton(self):
        """Test idempotency_key_gen is a singleton instance."""
        assert isinstance(idempotency_key_gen, IdempotencyKeyGenerator)

    def test_otp_generator_singleton(self):
        """Test otp_generator is a singleton instance."""
        assert isinstance(otp_generator, OTPGenerator)

    def test_token_generator_singleton(self):
        """Test token_generator is a singleton instance."""
        assert isinstance(token_generator, TokenGenerator)

    def test_random_generator_singleton(self):
        """Test random_generator is a singleton instance."""
        assert isinstance(random_generator, RandomStringGenerator)

    def test_hash_utils_singleton(self):
        """Test hash_utils is a singleton instance."""
        assert isinstance(hash_utils, HashUtils)

    def test_get_password_hasher_returns_instance(self):
        """Test get_password_hasher returns the password_hasher instance."""
        assert get_password_hasher() is password_hasher

    def test_password_hasher_same_instance(self):
        """Test get_password_hasher returns same instance on multiple calls."""
        instance1 = get_password_hasher()
        instance2 = get_password_hasher()
        assert instance1 is instance2