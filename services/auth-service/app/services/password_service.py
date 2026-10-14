"""
Сервис для работы с паролями.

Реализует:
- Хеширование паролей с использованием bcrypt + pepper (стандарт security.py)
- Валидацию паролей (сложность, длина, словари)
- Проверку утечек паролей (Have I Been Pwned API)
- Политику смены паролей (история, срок действия)
- Управление токенами сброса пароля через Redis
- Защиту от атак перебором (задержка при неудачных попытках)
"""

import asyncio
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import bcrypt
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.exceptions import PasswordValidationError, ValidationError
from app.core.logging import get_logger
from app.core.redis_client import redis_client

logger = get_logger(__name__)


class PasswordStrength:
    """Оценка сложности пароля."""

    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"
    VERY_STRONG = "very_strong"

    @classmethod
    def get_score(cls, password: str) -> tuple[str, int]:
        score = 0

        if len(password) >= 12:
            score += 25
        elif len(password) >= 10:
            score += 15
        elif len(password) >= 8:
            score += 5

        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 20
        if len(password) >= 16 and score >= 60:
            score += 15
        if re.search(r'(.)\1{3,}', password):
            score -= 10
        if re.search(r'^[a-zA-Z]+$', password):
            score -= 10
        if re.search(r'^\d+$', password):
            score -= 10

        score = max(0, min(100, score))

        if score < 30:
            return cls.WEAK, score
        elif score < 50:
            return cls.MEDIUM, score
        elif score < 75:
            return cls.STRONG, score
        else:
            return cls.VERY_STRONG, score


class PasswordService:
    """
    Сервис для работы с паролями.

    Использует bcrypt + pepper (стандарт security.py) для совместимости
    с AuthService.authenticate и Password роутером.
    """

    RESET_TOKEN_PREFIX = "pwd:reset:"

    def __init__(
        self,
        bcrypt_rounds: int = None,
        breach_check_enabled: bool = False,
    ):
        self.bcrypt_rounds = bcrypt_rounds or settings.PASSWORD_BCRYPT_ROUNDS
        self.pepper = getattr(settings, "SECRET_PEPPER", "")
        self.breach_check_enabled = breach_check_enabled
        self._breach_cache: set[str] = set()
        self._cache_ttl = timedelta(hours=1)
        self._last_cache_update = datetime.min

    def _add_pepper(self, password: str) -> str:
        return f"{password}{self.pepper}"

    # ==================== ХЕШИРОВАНИЕ И ПРОВЕРКА ПАРОЛЕЙ ====================

    async def hash_password(self, password: str) -> str:
        """
        Хеширование пароля с bcrypt + pepper (стандарт security.py).

        Выполняется в отдельном потоке.
        """
        loop = asyncio.get_event_loop()
        peppered = self._add_pepper(password)
        salt = await loop.run_in_executor(None, bcrypt.gensalt, self.bcrypt_rounds)
        hashed = await loop.run_in_executor(None, bcrypt.hashpw, peppered.encode('utf-8'), salt)
        logger.debug("Password hashed successfully")
        return hashed.decode('utf-8')

    async def verify_password(self, password: str, hashed: str) -> bool:
        """
        Проверка пароля с bcrypt + pepper (стандарт security.py).

        Выполняется в отдельном потоке.
        """
        loop = asyncio.get_event_loop()
        peppered = self._add_pepper(password)
        is_valid = await loop.run_in_executor(
            None, bcrypt.checkpw, peppered.encode('utf-8'), hashed.encode('utf-8')
        )
        if not is_valid:
            await asyncio.sleep(0.05)
        return is_valid

    async def hash_password_sync(self, password: str) -> str:
        """Синхронное хеширование (для фоновых задач)."""
        peppered = self._add_pepper(password)
        salt = bcrypt.gensalt(self.bcrypt_rounds)
        return bcrypt.hashpw(peppered.encode('utf-8'), salt).decode('utf-8')

    # ==================== ТОКЕНЫ СБРОСА ПАРОЛЯ (REDIS) ====================

    def _reset_key(self, token: str) -> str:
        hashed = hashlib.sha256(token.encode('utf-8')).hexdigest()
        return f"{self.RESET_TOKEN_PREFIX}{hashed}"

    async def save_reset_token(
        self,
        user_id: UUID,
        token: str,
        ttl_minutes: int = None,
    ) -> None:
        ttl = ttl_minutes or settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
        key = self._reset_key(token)
        await redis_client.setex(key, ttl * 60, str(user_id))
        logger.info(f"Reset token saved for user {user_id}, TTL: {ttl}min")

    async def get_user_by_reset_token(self, token: str) -> Optional[UUID]:
        key = self._reset_key(token)
        value = await redis_client.get(key)
        if value:
            user_id = UUID(value)
            logger.debug(f"Reset token found for user {user_id}")
            return user_id
        logger.warning("Reset token not found")
        return None

    async def delete_reset_token(self, token: str) -> None:
        key = self._reset_key(token)
        await redis_client.delete(key)
        logger.debug("Reset token deleted")

    # ==================== ВАЛИДАЦИЯ ПАРОЛЕЙ ====================

    async def validate_password(
        self,
        password: str,
        user_id: Optional[UUID] = None,
        check_history: bool = True,
    ) -> None:
        errors = []

        if len(password) < settings.PASSWORD_MIN_LENGTH:
            errors.append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
        if len(password) > settings.PASSWORD_MAX_LENGTH:
            errors.append(f"Password must not exceed {settings.PASSWORD_MAX_LENGTH} characters")
        if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        if settings.PASSWORD_REQUIRE_DIGITS and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        if settings.PASSWORD_REQUIRE_SPECIAL_CHARS and not re.search(
            r'[!@#$%^&*(),.?":{}|<>]', password
        ):
            errors.append("Password must contain at least one special character")

        strength, score = PasswordStrength.get_score(password)
        if strength in (PasswordStrength.WEAK,):
            errors.append(
                f"Password is too weak (score: {score}/100). "
                "Use a mix of uppercase, lowercase, numbers, and special characters"
            )

        if self._is_common_password(password):
            errors.append("Password is too common or easily guessable")

        if self.breach_check_enabled and await self._is_password_breached(password):
            errors.append(
                "This password has been exposed in a data breach. "
                "Please choose a different password"
            )

        if errors:
            raise PasswordValidationError("; ".join(errors))

        logger.debug("Password validation passed")

    def _is_common_password(self, password: str) -> bool:
        common_passwords = {
            "password", "password123", "123456", "12345678", "123456789",
            "qwerty", "qwerty123", "abc123", "password1", "12345",
            "1234567", "1q2w3e", "1234567890", "admin", "admin123",
            "letmein", "letmein123", "welcome", "welcome123",
            "monkey", "monkey123", "dragon", "master", "hello",
            "freedom", "whatever", "trustno1", "princess", "sunshine",
            "iloveyou", "lovely", "goodluck", "football", "baseball",
            "soccer", "fuckyou", "asshole", "computer", "internet",
            "starwars", "summer", "spring", "winter", "autumn",
            "qwertyuiop", "123123", "123321", "111111", "000000",
            "7777777", "changeme", "changeme123", "secret", "secret123",
            "P@ssw0rd", "Qwerty123!", "Password123!",
        }
        return password.lower() in common_passwords

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=0.5, min=0.5, max=2))
    async def _is_password_breached(self, password: str) -> bool:
        if self._is_cache_valid():
            return False

        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    headers={
                        "User-Agent": "Marketplace-Auth-Service/1.0",
                        "Accept": "text/plain",
                    },
                )
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line.startswith(suffix):
                        count = int(line.split(':')[1])
                        logger.warning(f"Password found in breach ({count} occurrences)")
                        return True
        except httpx.RequestError as e:
            logger.warning(f"Failed to check password breach: {e}")
            return False

        return False

    def _is_cache_valid(self) -> bool:
        return datetime.now(timezone.utc) - self._last_cache_update < self._cache_ttl

    # ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================

    def generate_reset_token(self) -> str:
        nbytes = int(settings.PASSWORD_RESET_TOKEN_LENGTH * 0.75) + 1
        return secrets.token_urlsafe(nbytes)[:settings.PASSWORD_RESET_TOKEN_LENGTH]

    async def is_password_expired(self, password_updated_at: datetime) -> bool:
        return False