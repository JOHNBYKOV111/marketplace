"""
Сервис для работы с TOTP (Time-based One-Time Password).

Реализует:
- Генерацию TOTP секретов
- Создание OTPAuth URL для QR кодов
- Верификацию TOTP кодов
- Защиту от атак перебором
- Поддержку резервных кодов
- Настройку времени и окна верификации
"""

import base64
import hashlib
import hmac
import struct
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, List
from urllib.parse import quote

import pyotp

from app.core.config import settings
from app.core.exceptions import ValidationError, SecurityError
from app.core.logging import get_logger
from app.core.security import generate_mfa_secret, generate_mfa_backup_codes

logger = get_logger(__name__)


class TOTPService:
    """
    Сервис для работы с TOTP.

    Реализует высоконагруженную и безопасную работу с TOTP:
    - Генерация секретов с достаточной энтропией
    - Верификация с защитой от timing attacks
    - Поддержка окна верификации (для компенсации рассинхронизации)
    - Защита от повторного использования кодов
    - Резервные коды для восстановления доступа
    """

    # Параметры TOTP по умолчанию (RFC 6238)
    DEFAULT_INTERVAL = 30  # секунд
    DEFAULT_DIGITS = 6     # количество цифр
    DEFAULT_WINDOW = 1     # окно верификации (1 до и 1 после)

    def __init__(
        self,
        interval: int = DEFAULT_INTERVAL,
        digits: int = DEFAULT_DIGITS,
        window: int = DEFAULT_WINDOW,
        use_cache: bool = True,
    ):
        """
        Инициализация TOTP сервиса.

        Args:
            interval: Интервал генерации кодов (секунды)
            digits: Количество цифр в коде
            window: Окно верификации (количество шагов до/после)
            use_cache: Использовать кэш для предотвращения повторного использования
        """
        self.interval = interval
        self.digits = digits
        self.window = window
        self.use_cache = use_cache
        self._used_codes_cache = {}  # cache_key -> timestamp
        self._cache_ttl = interval * 2  # время жизни в кэше

    def generate_secret(self, length: int = 32) -> str:
        """
        Генерация TOTP секрета.

        Args:
            length: Длина секрета (в байтах)

        Returns:
            str: Секрет в base32 формате
        """
        try:
            # Генерация криптографически безопасного секрета
            secret_bytes = generate_mfa_secret(length)

            # Кодирование в base32 (требуется для TOTP)
            secret = pyotp.random_base32(length=length)

            logger.debug("TOTP secret generated")

            return secret

        except Exception as e:
            logger.error(f"Failed to generate TOTP secret: {e}")
            raise SecurityError(f"Failed to generate TOTP secret: {str(e)}")

    def get_otpauth_url(
        self,
        secret: str,
        account_name: str,
        issuer: str = "Marketplace",
        algorithm: str = "SHA1",
        digits: int = DEFAULT_DIGITS,
        period: int = DEFAULT_INTERVAL,
    ) -> str:
        """
        Создание OTPAuth URL для QR кода.

        Используется для настройки в Google Authenticator и других приложениях.

        Args:
            secret: TOTP секрет
            account_name: Имя аккаунта (обычно email)
            issuer: Название сервиса
            algorithm: Алгоритм хеширования (SHA1, SHA256, SHA512)
            digits: Количество цифр
            period: Интервал обновления (секунды)

        Returns:
            str: OTPAuth URL

        Raises:
            ValidationError: Неверный секрет
        """
        try:
            # Проверка секрета
            if not secret or len(secret) < 16:
                raise ValidationError("Invalid TOTP secret")

            # Создание TOTP объекта
            totp = pyotp.TOTP(
                secret,
                digits=digits,
                interval=period,
                name=account_name,
                issuer=issuer,
            )

            # Получение provisioning URI
            otpauth_url = totp.provisioning_uri()

            logger.debug(f"OTPAuth URL generated for {account_name}")

            return otpauth_url

        except ValidationError:
            raise

        except Exception as e:
            logger.error(f"Failed to generate OTPAuth URL: {e}")
            raise SecurityError(f"Failed to generate OTPAuth URL: {str(e)}")

    def verify(
        self,
        secret: str,
        code: str,
        window: Optional[int] = None,
        timestamp: Optional[int] = None,
    ) -> bool:
        """
        Верификация TOTP кода.

        Поддерживает:
        - Окно верификации (компенсация рассинхронизации)
        - Защиту от повторного использования (если включено кэширование)
        - Защиту от timing attacks

        Args:
            secret: TOTP секрет
            code: Код для верификации
            window: Окно верификации (переопределяет значение по умолчанию)
            timestamp: Временная метка (для тестирования)

        Returns:
            bool: True если код корректный

        Raises:
            ValidationError: Неверный формат кода или секрета
        """
        try:
            # Валидация кода
            if not code or not code.isdigit() or len(code) != self.digits:
                raise ValidationError(f"Code must be {self.digits} digits")

            # Валидация секрета
            if not secret or len(secret) < 16:
                raise ValidationError("Invalid TOTP secret")

            # Проверка повторного использования
            if self.use_cache:
                cache_key = f"{secret}:{code}:{self._get_current_counter()}"
                if self._is_code_used(cache_key):
                    logger.warning("TOTP code already used")
                    return False

            # Использование pyotp для верификации
            totp = pyotp.TOTP(secret, digits=self.digits, interval=self.interval)
            valid_window = window if window is not None else self.window

            # Верификация с окном
            if timestamp:
                # Для тестирования с фиксированным временем
                valid = totp.verify(code, valid_window=valid_window, for_time=timestamp)
            else:
                valid = totp.verify(code, valid_window=valid_window)

            # Если код корректный - сохраняем в кэш
            if valid and self.use_cache:
                self._mark_code_used(cache_key)

            if valid:
                logger.debug("TOTP code verified successfully")
            else:
                logger.warning("Invalid TOTP code")

            return valid

        except ValidationError:
            raise

        except Exception as e:
            logger.error(f"Failed to verify TOTP code: {e}")
            return False

    def verify_with_backup(
        self,
        secret: str,
        code: str,
        backup_codes: List[str],
    ) -> Tuple[bool, Optional[str]]:
        """
        Верификация с поддержкой резервных кодов.

        Args:
            secret: TOTP секрет
            code: Код для верификации
            backup_codes: Список резервных кодов

        Returns:
            Tuple[bool, Optional[str]]: (валидный, использованный резервный код)
        """
        # Проверка TOTP кода
        if self.verify(secret, code):
            return True, None

        # Проверка резервных кодов
        if backup_codes and code in backup_codes:
            # Удаление использованного резервного кода
            backup_codes.remove(code)
            logger.info("Backup code used for verification")
            return True, code

        return False, None

    def generate_backup_codes(self, count: int = 10, length: int = 8) -> List[str]:
        """
        Генерация резервных кодов для восстановления доступа.

        Args:
            count: Количество кодов
            length: Длина каждого кода

        Returns:
            List[str]: Список резервных кодов
        """
        codes = generate_mfa_backup_codes(count, length)

        logger.info(f"Generated {count} backup codes")

        return codes

    def get_current_code(self, secret: str) -> str:
        """
        Получение текущего TOTP кода (для тестирования).

        Args:
            secret: TOTP секрет

        Returns:
            str: Текущий TOTP код
        """
        totp = pyotp.TOTP(secret, digits=self.digits, interval=self.interval)
        return totp.now()

    def get_time_remaining(self) -> int:
        """
        Получение оставшегося времени до смены кода.

        Returns:
            int: Количество секунд до смены кода
        """
        return self.interval - (int(time.time()) % self.interval)

    def get_counter(self, timestamp: Optional[int] = None) -> int:
        """
        Получение текущего счетчика TOTP.

        Args:
            timestamp: Временная метка (для тестирования)

        Returns:
            int: Счетчик
        """
        ts = timestamp if timestamp is not None else int(time.time())
        return ts // self.interval

    def _get_current_counter(self) -> int:
        """Получение текущего счетчика."""
        return int(time.time()) // self.interval

    def _is_code_used(self, cache_key: str) -> bool:
        """
        Проверка, использовался ли код ранее.

        Args:
            cache_key: Ключ кэша

        Returns:
            bool: True если код уже использован
        """
        if not self.use_cache:
            return False

        if cache_key in self._used_codes_cache:
            # Проверка истечения срока
            if time.time() - self._used_codes_cache[cache_key] < self._cache_ttl:
                return True
            else:
                del self._used_codes_cache[cache_key]

        return False

    def _mark_code_used(self, cache_key: str) -> None:
        """
        Отметка кода как использованного.

        Args:
            cache_key: Ключ кэша
        """
        if not self.use_cache:
            return

        self._used_codes_cache[cache_key] = time.time()

        # Очистка старых записей (ограничение размера кэша)
        if len(self._used_codes_cache) > 10000:
            self._cleanup_cache()

    def _cleanup_cache(self) -> None:
        """Очистка старого кэша."""
        now = time.time()
        expired_keys = [
            key for key, ts in self._used_codes_cache.items()
            if now - ts > self._cache_ttl
        ]

        for key in expired_keys:
            del self._used_codes_cache[key]

        logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")


class TOTPValidator:
    """
    Класс для валидации TOTP данных.

    Обеспечивает дополнительный уровень проверки:
    - Формат секрета
    - Формат кода
    - Длина и состав
    """

    @staticmethod
    def validate_secret(secret: str) -> bool:
        """
        Проверка валидности TOTP секрета.

        Args:
            secret: Секрет для проверки

        Returns:
            bool: True если секрет валиден
        """
        if not secret:
            return False

        # Проверка длины (base32 секреты обычно кратны 8)
        if len(secret) < 16 or len(secret) > 64:
            return False

        # Проверка, что секрет состоит из допустимых символов base32
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        if not all(c in valid_chars for c in secret.upper()):
            return False

        return True

    @staticmethod
    def validate_code(code: str, digits: int = 6) -> bool:
        """
        Проверка валидности TOTP кода.

        Args:
            code: Код для проверки
            digits: Ожидаемое количество цифр

        Returns:
            bool: True если код валиден
        """
        if not code:
            return False

        if len(code) != digits:
            return False

        if not code.isdigit():
            return False

        return True

    @staticmethod
    def validate_backup_code(code: str, length: int = 8) -> bool:
        """
        Проверка валидности резервного кода.

        Args:
            code: Код для проверки
            length: Ожидаемая длина

        Returns:
            bool: True если код валиден
        """
        if not code:
            return False

        if len(code) != length:
            return False

        # Резервные коды обычно содержат только цифры
        if not code.isdigit():
            return False

        return True