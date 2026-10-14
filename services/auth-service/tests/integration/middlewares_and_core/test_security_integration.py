"""
Интеграционные тесты для Security модуля с реальной логикой.

Тестирует:
- PasswordHasher (хэширование, верификация, pepper)
- IdempotencyKeyGenerator (генерация, валидация, извлечение timestamp)
- OTPGenerator (numeric, alphanumeric, TOTP secret, backup codes)
- TokenGenerator (refresh token, password reset, email verification, API key)
- APIKeyHasher (хэширование, верификация, извлечение префикса)
- RandomStringGenerator (разные типы строк, PKCE)
- HashUtils (SHA256, SHA512, HMAC, PBKDF2, constant-time сравнение)
- Асинхронные обёртки (hash_password_async, verify_password_async)
- Глобальные инстансы
- Граничные случаи

Архитектура:
- Реальная логика: все генераторы, хешеры, утилиты
- Без моков на settings, secrets, datetime
"""

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


class TestPasswordHasher:
    """Тесты для PasswordHasher с реальными настройками."""

    def test_hash_and_verify(self):
        hasher = PasswordHasher()
        password = "SecurePassword123!"
        hashed = hasher.hash(password)
        assert hashed != password
        assert hasher.verify(password, hashed) is True
        assert hasher.verify("WrongPassword", hashed) is False

    def test_pepper_integration(self):
        hasher = PasswordHasher()
        peppered = hasher._add_pepper("test")
        assert peppered == f"test{hasher.pepper}"

    def test_needs_rehash(self):
        hasher = PasswordHasher()
        hashed = hasher.hash("test")
        assert isinstance(hasher.needs_rehash(hashed), bool)

    def test_empty_password(self):
        hasher = PasswordHasher()
        hashed = hasher.hash("")
        assert hasher.verify("", hashed) is True


class TestIdempotencyKeyGenerator:
    """Тесты для IdempotencyKeyGenerator."""

    def test_generate_and_validate(self):
        key = IdempotencyKeyGenerator.generate()
        assert key.startswith("idem_")
        assert IdempotencyKeyGenerator.validate(key) is True

    def test_generate_with_prefix(self):
        key = IdempotencyKeyGenerator.generate_with_prefix("payment")
        assert key.startswith("payment_")
        assert IdempotencyKeyGenerator.validate(key) is True

    def test_validate_invalid(self):
        invalid = ["invalid", "idem_123", "idem_abc_123", "idem_1234567890_short", ""]
        for key in invalid:
            assert IdempotencyKeyGenerator.validate(key) is False

    def test_extract_timestamp(self):
        key = IdempotencyKeyGenerator.generate()
        ts = IdempotencyKeyGenerator.extract_timestamp(key)
        assert ts is not None
        assert isinstance(ts, int)
        assert IdempotencyKeyGenerator.extract_timestamp("invalid") is None


class TestOTPGenerator:
    """Тесты для OTPGenerator."""

    def test_generate_numeric(self):
        otp = OTPGenerator.generate_numeric(6)
        assert len(otp) == 6
        assert otp.isdigit()

    def test_generate_alphanumeric_excludes_ambiguous(self):
        otp = OTPGenerator.generate_alphanumeric(10)
        assert "0" not in otp
        assert "O" not in otp
        assert "1" not in otp
        assert "I" not in otp

    def test_generate_totp_secret(self):
        secret = OTPGenerator.generate_totp_secret()
        assert len(secret) == 32
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in secret)

    def test_generate_backup_codes(self):
        codes = OTPGenerator.generate_backup_codes(count=8, length=8)
        assert len(codes) == 8
        for code in codes:
            parts = code.split("-")
            assert len(parts) == 2 and len(parts[0]) == 4 and len(parts[1]) == 4

    def test_generate_zero_length(self):
        assert OTPGenerator.generate_numeric(0) == ""


class TestTokenGenerator:
    """Тесты для TokenGenerator."""

    def test_generate_refresh_token(self):
        token = TokenGenerator.generate_refresh_token()
        assert len(token) == 96

    def test_generate_password_reset_token(self):
        token = TokenGenerator.generate_password_reset_token()
        assert len(token) >= 32

    def test_generate_api_key_format(self):
        raw_key, hash_key = TokenGenerator.generate_api_key(prefix="mk")
        assert raw_key.startswith("mk_live_")
        parts = raw_key.split("_")
        assert parts[0] == "mk" and parts[1] == "live"
        assert len(hash_key) == 64


class TestAPIKeyHasher:
    """Тесты для APIKeyHasher."""

    def test_hash_and_verify(self):
        raw_key = "test_key_12345"
        hashed = APIKeyHasher.hash_key(raw_key)
        assert len(hashed) == 64
        assert APIKeyHasher.verify_key(raw_key, hashed) is True
        assert APIKeyHasher.verify_key("wrong_key", hashed) is False

    def test_extract_prefix(self):
        assert APIKeyHasher.extract_prefix("mk_live_abc_123") == "mk_live"
        assert APIKeyHasher.extract_prefix("short") == "short"
        assert APIKeyHasher.extract_prefix("") == ""


class TestRandomStringGenerator:
    """Тесты для RandomStringGenerator."""

    def test_generate_length(self):
        result = RandomStringGenerator.generate(32)
        assert len(result) == 43

    def test_generate_hex(self):
        result = RandomStringGenerator.generate_hex(32)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_generate_code_verifier(self):
        verifier = RandomStringGenerator.generate_code_verifier()
        assert len(verifier) <= 128

    def test_generate_code_challenge(self):
        verifier = "test_verifier_123"
        challenge = RandomStringGenerator.generate_code_challenge(verifier)
        assert "=" not in challenge
        assert len(challenge) == 43

    def test_generate_state(self):
        state = RandomStringGenerator.generate_state()
        assert len(state) >= 32


class TestHashUtils:
    """Тесты для HashUtils."""

    def test_sha256(self):
        result = HashUtils.sha256("test")
        assert len(result) == 64

    def test_sha512(self):
        result = HashUtils.sha512("test")
        assert len(result) == 128

    def test_hmac_sha256(self):
        result = HashUtils.hmac_sha256("secret", "message")
        assert len(result) == 64

    def test_pbkdf2(self):
        result = HashUtils.pbkdf2("password", b"salt", iterations=100)
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_constant_time_compare(self):
        assert HashUtils.constant_time_compare("test", "test") is True
        assert HashUtils.constant_time_compare("test1", "test2") is False

    def test_hmac_empty_key(self):
        result = HashUtils.hmac_sha256("", "message")
        assert len(result) == 64


class TestAsyncWrappers:
    """Тесты для асинхронных обёрток с реальным event loop."""

    @pytest.mark.asyncio
    async def test_hash_password_async(self):
        result = await hash_password_async("password")
        assert result.startswith("$2b$")

    @pytest.mark.asyncio
    async def test_verify_password_async(self):
        hashed = password_hasher.hash("password")
        result = await verify_password_async("password", hashed)
        assert result is True


class TestGlobalInstances:
    """Тесты для глобальных инстансов."""

    def test_password_hasher_singleton(self):
        assert isinstance(password_hasher, PasswordHasher)
        assert get_password_hasher() is password_hasher

    def test_singletons_exist(self):
        assert isinstance(idempotency_key_gen, IdempotencyKeyGenerator)
        assert isinstance(otp_generator, OTPGenerator)
        assert isinstance(token_generator, TokenGenerator)
        assert isinstance(hash_utils, HashUtils)