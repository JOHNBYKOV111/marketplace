"""
Модуль безопасности.

Реализует:
- Хеширование и верификацию паролей (bcrypt + pepper)
- Создание и валидацию JWT токенов
- Генерацию безопасных случайных значений (OTP, токены, ключи)
- Защиту от timing attacks
- Security headers
- Асинхронные обёртки для хеширования
"""

import asyncio
import base64
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple, List

import bcrypt
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import Response
from fastapi.security import HTTPBearer
from passlib.context import CryptContext

from app.core.config import settings
from app.core.exceptions import SecurityError, InvalidTokenError
from app.core.logging import get_logger

logger = get_logger(__name__)

security_scheme = HTTPBearer(
    scheme_name="Bearer",
    description="JWT Bearer токен для аутентификации",
    auto_error=False,
)


# ==================== PASSWORD HASHER ====================

class PasswordHasher:
    """Хеширование и верификация паролей с pepper."""

    def __init__(self):
        self.scheme = getattr(settings, "PASSWORD_HASH_SCHEME", "bcrypt")
        self.bcrypt_rounds = getattr(settings, "BCRYPT_ROUNDS", 12)
        self.argon2_time_cost = getattr(settings, "ARGON2ID_TIME_COST", 2)
        self.argon2_memory_cost = getattr(settings, "ARGON2ID_MEMORY_COST", 19456)
        self.argon2_parallelism = getattr(settings, "ARGON2ID_PARALLELISM", 1)
        self.argon2_hash_len = getattr(settings, "ARGON2ID_HASH_LEN", 32)
        self.pepper = getattr(settings, "SECRET_PEPPER", "default_pepper")

        if self.scheme == "argon2id":
            self.pwd_context = CryptContext(
                schemes=["argon2"],
                default="argon2",
                argon2__time_cost=self.argon2_time_cost,
                argon2__memory_cost=self.argon2_memory_cost,
                argon2__parallelism=self.argon2_parallelism,
                argon2__hash_len=self.argon2_hash_len,
            )
        else:
            self.pwd_context = CryptContext(
                schemes=["bcrypt"], default="bcrypt", bcrypt__rounds=self.bcrypt_rounds,
            )

    def hash(self, password: str) -> str:
        try:
            return self.pwd_context.hash(self._add_pepper(password))
        except Exception as e:
            logger.error(f"Failed to hash password: {e}")
            raise SecurityError(f"Failed to hash password: {str(e)}")

    def verify(self, password: str, hashed: str) -> bool:
        try:
            return self.pwd_context.verify(self._add_pepper(password), hashed)
        except Exception as e:
            logger.error(f"Failed to verify password: {e}")
            return False

    def needs_rehash(self, hashed: str) -> bool:
        try:
            return self.pwd_context.needs_update(hashed)
        except Exception:
            return False

    def _add_pepper(self, password: str) -> str:
        return f"{password}{self.pepper}"


_password_hasher_instance = None


def get_password_hasher() -> PasswordHasher:
    global _password_hasher_instance
    if _password_hasher_instance is None:
        _password_hasher_instance = PasswordHasher()
    return _password_hasher_instance


password_hasher = get_password_hasher()


async def hash_password_async(password: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, password_hasher.hash, password)


async def verify_password_async(password: str, hashed: str) -> bool:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, password_hasher.verify, password, hashed)


# ==================== OTP GENERATOR ====================

class OTPGenerator:
    NUMERIC_CHARS = "0123456789"
    ALPHANUMERIC_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    TOTP_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    @classmethod
    def generate_numeric(cls, length: int = 6) -> str:
        if length <= 0:
            return ""
        return "".join(secrets.choice(cls.NUMERIC_CHARS) for _ in range(length))

    @classmethod
    def generate_alphanumeric(cls, length: int = 8) -> str:
        if length <= 0:
            return ""
        return "".join(secrets.choice(cls.ALPHANUMERIC_CHARS) for _ in range(length))

    @classmethod
    def generate_totp_secret(cls, length: int = 32) -> str:
        if length <= 0:
            return ""
        return "".join(secrets.choice(cls.TOTP_CHARS) for _ in range(length))

    @classmethod
    def generate_backup_codes(cls, count: int = 8, length: int = 8) -> List[str]:
        if count <= 0 or length <= 0:
            return []
        codes = []
        for _ in range(count):
            part1 = "".join(secrets.choice(cls.NUMERIC_CHARS) for _ in range(length // 2))
            part2 = "".join(secrets.choice(cls.NUMERIC_CHARS) for _ in range(length // 2))
            codes.append(f"{part1}-{part2}")
        return codes


otp_generator = OTPGenerator()


# ==================== TOKEN GENERATOR ====================

class TokenGenerator:
    @staticmethod
    def generate_refresh_token() -> str:
        import uuid
        return f"{uuid.uuid4().hex}{secrets.token_hex(32)}"

    @staticmethod
    def generate_password_reset_token(length: int = 32) -> str:
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_email_verification_token(length: int = 32) -> str:
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_api_key(prefix: str = "mk") -> Tuple[str, str]:
        raw_key = f"{prefix}_live_{secrets.token_hex(32)}_{int(datetime.now().timestamp())}"
        hashed_key = hashlib.sha256(raw_key.encode()).hexdigest()
        return raw_key, hashed_key


token_generator = TokenGenerator()


# ==================== API KEY HASHER ====================

class APIKeyHasher:
    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()

    @staticmethod
    def verify_key(raw_key: str, hashed_key: str) -> bool:
        return hmac.compare_digest(APIKeyHasher.hash_key(raw_key), hashed_key)

    @staticmethod
    def extract_prefix(raw_key: str) -> str:
        if "_" in raw_key:
            parts = raw_key.split("_")
            if len(parts) >= 2:
                return f"{parts[0]}_{parts[1]}"
        return raw_key


# ==================== RANDOM STRING GENERATOR ====================

class RandomStringGenerator:
    @staticmethod
    def generate(length: int = 32) -> str:
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_hex(length: int = 32) -> str:
        return secrets.token_hex(length)

    @staticmethod
    def generate_code_verifier(length: int = 64) -> str:
        if length > 128:
            length = 128
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_code_challenge(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().replace("=", "")

    @staticmethod
    def generate_state(length: int = 32) -> str:
        return secrets.token_urlsafe(length)


random_generator = RandomStringGenerator()


# ==================== IDEMPOTENCY KEY GENERATOR ====================

class IdempotencyKeyGenerator:
    @staticmethod
    def generate() -> str:
        import uuid
        timestamp = int(datetime.now().timestamp())
        unique_id = uuid.uuid4().hex
        return f"idem_{timestamp}_{unique_id}"

    @staticmethod
    def generate_with_prefix(prefix: str) -> str:
        import uuid
        timestamp = int(datetime.now().timestamp())
        unique_id = uuid.uuid4().hex
        return f"{prefix}_{timestamp}_{unique_id}"

    @staticmethod
    def validate(key: str) -> bool:
        if not key:
            return False
        parts = key.split("_")
        if len(parts) != 3 or not parts[1].isdigit() or len(parts[2]) < 16:
            return False
        return True

    @staticmethod
    def extract_timestamp(key: str) -> Optional[int]:
        if not IdempotencyKeyGenerator.validate(key):
            return None
        try:
            return int(key.split("_")[1])
        except (ValueError, IndexError):
            return None


idempotency_key_gen = IdempotencyKeyGenerator()


# ==================== HASH UTILS ====================

class HashUtils:
    @staticmethod
    def sha256(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def sha512(data: str) -> str:
        return hashlib.sha512(data.encode()).hexdigest()

    @staticmethod
    def hmac_sha256(key: str, message: str) -> str:
        return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def pbkdf2(password: str, salt: bytes, iterations: int = 100000) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
        return kdf.derive(password.encode())

    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        return hmac.compare_digest(a.encode(), b.encode())


hash_utils = HashUtils()


# ==================== SECURITY HEADERS ====================

class SecurityHeaders:
    @staticmethod
    def apply(response: Response) -> None:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"


# ==================== JWT FUNCTIONS ====================

def create_access_token(
    data: Dict[str, Any],
    expires_delta: timedelta,
    secret_key: Optional[str] = None,
) -> str:
    try:
        to_encode = data.copy()
        if "type" not in to_encode:
            to_encode["type"] = "access"
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode.update({
            "exp": int(expire.timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "jti": secrets.token_hex(16),
        })
        key = secret_key or settings.JWT_SECRET_KEY
        return jwt.encode(to_encode, key, algorithm=settings.JWT_ALGORITHM)
    except Exception as e:
        logger.error(f"Failed to create access token: {e}")
        raise SecurityError(f"Failed to create access token: {str(e)}")


def create_refresh_token(
    data: Dict[str, Any],
    expires_delta: timedelta,
    secret_key: Optional[str] = None,
) -> str:
    try:
        data_copy = data.copy()
        data_copy["type"] = "refresh"
        return create_access_token(data_copy, expires_delta, secret_key)
    except Exception as e:
        logger.error(f"Failed to create refresh token: {e}")
        raise SecurityError(f"Failed to create refresh token: {str(e)}")


def decode_token(
    token: str,
    secret_key: Optional[str] = None,
    verify_type: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        key = secret_key or settings.JWT_SECRET_KEY
        payload = jwt.decode(
            token, key,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "iat", "jti"]},
        )
        if verify_type and payload.get("type") != verify_type:
            raise InvalidTokenError(
                f"Invalid token type: expected {verify_type}, got {payload.get('type')}"
            )
        if "sub" not in payload:
            raise InvalidTokenError("Token missing 'sub' claim")
        return payload
    except jwt.ExpiredSignatureError:
        raise InvalidTokenError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise InvalidTokenError(f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to decode token: {e}")
        raise InvalidTokenError(f"Failed to decode token: {str(e)}")


def extract_jwt_from_header(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


# ==================== СОВМЕСТИМОСТЬ ====================

def get_password_hash(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return password_hasher.verify(password, hashed)


def hash_password_bcrypt(password: str, rounds: int = 12) -> str:
    if password_hasher.scheme != "bcrypt":
        temp_hasher = PasswordHasher()
        temp_hasher.scheme = "bcrypt"
        temp_hasher.bcrypt_rounds = rounds
        temp_hasher.pwd_context = CryptContext(schemes=["bcrypt"], default="bcrypt", bcrypt__rounds=rounds)
        return temp_hasher.hash(password)
    return password_hasher.hash(password)


def generate_mfa_secret(length: int = 32) -> str:
    return otp_generator.generate_totp_secret(length)


def generate_mfa_backup_codes(count: int = 10, length: int = 8) -> List[str]:
    return otp_generator.generate_backup_codes(count, length)


def generate_salt(length: int = 32) -> str:
    return secrets.token_hex(length // 2)


def generate_token_id(length: int = 32) -> str:
    return secrets.token_urlsafe(length // 2)


def generate_verification_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def generate_reset_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


__all__ = [
    "PasswordHasher", "get_password_hasher", "password_hasher",
    "hash_password_async", "verify_password_async",
    "OTPGenerator", "otp_generator",
    "TokenGenerator", "token_generator",
    "APIKeyHasher",
    "RandomStringGenerator", "random_generator",
    "IdempotencyKeyGenerator", "idempotency_key_gen",
    "HashUtils", "hash_utils",
    "SecurityHeaders",
    "create_access_token", "create_refresh_token", "decode_token", "extract_jwt_from_header",
    "get_password_hash", "verify_password", "hash_password_bcrypt",
    "generate_mfa_secret", "generate_mfa_backup_codes",
    "generate_salt", "generate_token_id", "generate_verification_token", "generate_reset_token",
    "security_scheme",
]