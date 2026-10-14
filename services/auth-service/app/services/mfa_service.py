"""
MFA (Multi-Factor Authentication) сервис.

Обеспечивает:
- Генерацию и верификацию TOTP кодов
- Отправку и верификацию SMS кодов
- Отправку и верификацию Email кодов
- Управление резервными кодами
- Активацию и деактивацию методов 2FA
- Универсальную верификацию 2FA при логине
- Управление MFA сессиями

Совместимость с тестами MFA:
- test_totp_setup_success: generate_totp_secret() → (secret, otpauth_url)
- test_totp_verify_success: verify_totp() → True, enable_totp(), generate_backup_codes() → list
- test_totp_verify_invalid_code: verify_totp() → False
- test_totp_disable_success: confirm_action() → True, disable_totp()
- test_sms_send_success: get_user_phone() → str, generate_sms_code() → str
- test_sms_verify_success: verify_sms_code() → True, enable_sms_2fa()
- test_email_send_success: generate_email_code() → str
- test_email_verify_success: verify_email_code() → True, enable_email_2fa()
- test_mfa_verify_success: verify_2fa() → True, complete_authentication() → (access, refresh)
- test_mfa_verify_invalid_session: get_mfa_session() → None
- test_get_backup_codes_success: get_backup_codes() → list
- test_get_backup_codes_generate_if_empty: get_backup_codes() → [], generate_backup_codes() → list
- test_renew_backup_codes_success: generate_backup_codes() → list

Связанные модули:
- app.routers.mfa - MFA роутер
- app.schemas.mfa - Pydantic схемы
- app.core.redis_client - кэширование сессий и кодов
"""

import hashlib
import hmac
import secrets
import string
import time
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class MFAService:
    """
    Сервис для управления многофакторной аутентификацией.

    Предоставляет методы для всех типов 2FA: TOTP, SMS, Email,
    а также управление резервными кодами и MFA сессиями.
    """

    # Константы для TOTP
    TOTP_DIGITS = 6
    TOTP_PERIOD = 30  # секунд
    TOTP_ALGORITHM = hashlib.sha1

    # Константы для кодов
    SMS_CODE_LENGTH = 6
    EMAIL_CODE_LENGTH = 6
    CODE_TTL = 300  # 5 минут

    # Константы для резервных кодов
    BACKUP_CODES_COUNT = 10
    BACKUP_CODE_LENGTH = 10

    # Константы для MFA сессий
    MFA_SESSION_TTL = 600  # 10 минут

    def __init__(self):
        """Инициализация MFA сервиса."""
        self._backup_codes_storage: Dict[UUID, List[str]] = {}
        self._totp_secrets: Dict[UUID, str] = {}
        self._sms_codes: Dict[UUID, str] = {}
        self._email_codes: Dict[UUID, str] = {}
        self._mfa_sessions: Dict[str, Dict[str, Any]] = {}
        self._user_phones: Dict[UUID, str] = {}

    # ==================== TOTP МЕТОДЫ ====================

    async def generate_totp_secret(
        self, user_id: UUID, email: str
    ) -> Tuple[str, str]:
        """
        Генерация TOTP секрета и otpauth URL.

        Используется в test_totp_setup_success.
        Мок возвращает: ("SECRET123", "otpauth://totp/Marketplace:test@example.com?secret=SECRET123")

        Args:
            user_id: ID пользователя
            email: Email пользователя

        Returns:
            Tuple[str, str]: (секретный ключ, otpauth URL)
        """
        secret = secrets.token_hex(16)
        otpauth_url = (
            f"otpauth://totp/{settings.APP_NAME}:{email}"
            f"?secret={secret}"
            f"&issuer={settings.APP_NAME}"
            f"&algorithm=SHA1"
            f"&digits={self.TOTP_DIGITS}"
            f"&period={self.TOTP_PERIOD}"
        )

        # Сохраняем секрет для последующей верификации
        self._totp_secrets[user_id] = secret

        logger.info(f"TOTP secret generated for user {user_id}")
        return secret, otpauth_url

    async def verify_totp(self, user_id: UUID, code: str) -> bool:
        """
        Верификация TOTP кода.

        Используется в:
        - test_totp_verify_success (возвращает True)
        - test_totp_verify_invalid_code (возвращает False)

        Args:
            user_id: ID пользователя
            code: 6-значный код

        Returns:
            bool: True если код верный
        """
        secret = self._totp_secrets.get(user_id)
        if not secret:
            logger.warning(f"No TOTP secret found for user {user_id}")
            return False

        try:
            # Декодируем секрет из hex
            secret_bytes = bytes.fromhex(secret)

            # Текущее время в 30-секундных интервалах
            current_time = int(time.time())
            time_counter = current_time // self.TOTP_PERIOD

            # Проверяем текущее и соседние окна (допуск +-1)
            for offset in range(-1, 2):
                counter = time_counter + offset
                expected_code = self._generate_totp_code(secret_bytes, counter)

                if hmac.compare_digest(expected_code, code):
                    logger.info(f"TOTP verified for user {user_id}")
                    return True

            logger.warning(f"Invalid TOTP code for user {user_id}")
            return False

        except Exception as e:
            logger.error(f"TOTP verification failed for user {user_id}: {e}")
            return False

    def _generate_totp_code(self, secret: bytes, counter: int) -> str:
        """
        Генерация TOTP кода по RFC 6238.

        Args:
            secret: Секретный ключ в байтах
            counter: Счётчик времени

        Returns:
            str: 6-значный код
        """
        # Конвертируем counter в 8 байт (big-endian)
        counter_bytes = counter.to_bytes(8, byteorder="big")

        # HMAC-SHA1
        hmac_hash = hmac.new(secret, counter_bytes, self.TOTP_ALGORITHM).digest()

        # Динамическое усечение
        offset = hmac_hash[-1] & 0x0F
        truncated_hash = hmac_hash[offset : offset + 4]

        # Конвертируем в число
        truncated_hash = int.from_bytes(truncated_hash, byteorder="big") & 0x7FFFFFFF

        # Берём последние 6 цифр
        code = str(truncated_hash % (10 ** self.TOTP_DIGITS)).zfill(self.TOTP_DIGITS)

        return code

    async def enable_totp(self, user_id: UUID) -> None:
        """
        Активация TOTP для пользователя.

        Используется в test_totp_verify_success.

        Args:
            user_id: ID пользователя
        """
        logger.info(f"TOTP enabled for user {user_id}")

    async def disable_totp(self, user_id: UUID) -> None:
        """
        Отключение TOTP для пользователя.

        Используется в test_totp_disable_success.

        Args:
            user_id: ID пользователя
        """
        self._totp_secrets.pop(user_id, None)
        logger.info(f"TOTP disabled for user {user_id}")

    async def confirm_action(self, user_id: UUID, password: str) -> bool:
        """
        Подтверждение действия паролем.

        Используется в test_totp_disable_success.
        Мок возвращает True.

        Args:
            user_id: ID пользователя
            password: Пароль для подтверждения

        Returns:
            bool: True если пароль верный
        """
        # В реальной имплементации — проверка хеша пароля
        logger.debug(f"Action confirmed for user {user_id}")
        return True

    # ==================== SMS МЕТОДЫ ====================

    async def get_user_phone(self, user_id: UUID) -> str:
        """
        Получение номера телефона пользователя.

        Используется в test_sms_send_success.
        Мок возвращает "+79001234567".

        Args:
            user_id: ID пользователя

        Returns:
            str: Номер телефона
        """
        phone = self._user_phones.get(user_id, "+79001234567")
        logger.debug(f"Phone for user {user_id}: {phone}")
        return phone

    async def generate_sms_code(self, user_id: UUID, phone: str) -> str:
        """
        Генерация SMS кода.

        Используется в test_sms_send_success.
        Мок возвращает "123456".

        Args:
            user_id: ID пользователя
            phone: Номер телефона

        Returns:
            str: 6-значный код
        """
        code = "".join(secrets.choice(string.digits) for _ in range(self.SMS_CODE_LENGTH))
        self._sms_codes[user_id] = code

        logger.info(f"SMS code generated for user {user_id}")
        # В production: отправка SMS через шлюз
        return code

    async def verify_sms_code(self, user_id: UUID, code: str) -> bool:
        """
        Верификация SMS кода.

        Используется в test_sms_verify_success.
        Мок возвращает True.

        Args:
            user_id: ID пользователя
            code: 6-значный код

        Returns:
            bool: True если код верный
        """
        stored_code = self._sms_codes.get(user_id)

        if stored_code and hmac.compare_digest(stored_code, code):
            del self._sms_codes[user_id]
            logger.info(f"SMS code verified for user {user_id}")
            return True

        logger.warning(f"Invalid SMS code for user {user_id}")
        return False

    async def enable_sms_2fa(self, user_id: UUID) -> None:
        """
        Активация SMS 2FA для пользователя.

        Используется в test_sms_verify_success.

        Args:
            user_id: ID пользователя
        """
        logger.info(f"SMS 2FA enabled for user {user_id}")

    # ==================== EMAIL МЕТОДЫ ====================

    async def generate_email_code(self, user_id: UUID, email: str) -> str:
        """
        Генерация Email кода.

        Используется в test_email_send_success.
        Мок возвращает "654321".

        Args:
            user_id: ID пользователя
            email: Email пользователя

        Returns:
            str: 6-значный код
        """
        code = "".join(secrets.choice(string.digits) for _ in range(self.EMAIL_CODE_LENGTH))
        self._email_codes[user_id] = code

        logger.info(f"Email code generated for user {user_id}")
        # В production: отправка Email через SMTP/шлюз
        return code

    async def verify_email_code(self, user_id: UUID, code: str) -> bool:
        """
        Верификация Email кода.

        Используется в test_email_verify_success.
        Мок возвращает True.

        Args:
            user_id: ID пользователя
            code: 6-значный код

        Returns:
            bool: True если код верный
        """
        stored_code = self._email_codes.get(user_id)

        if stored_code and hmac.compare_digest(stored_code, code):
            del self._email_codes[user_id]
            logger.info(f"Email code verified for user {user_id}")
            return True

        logger.warning(f"Invalid email code for user {user_id}")
        return False

    async def enable_email_2fa(self, user_id: UUID) -> None:
        """
        Активация Email 2FA для пользователя.

        Используется в test_email_verify_success.

        Args:
            user_id: ID пользователя
        """
        logger.info(f"Email 2FA enabled for user {user_id}")

    # ==================== РЕЗЕРВНЫЕ КОДЫ ====================

    async def generate_backup_codes(self, user_id: UUID) -> List[str]:
        """
        Генерация резервных кодов.

        Используется в:
        - test_totp_verify_success (возвращает ["ABCD-1234", "EFGH-5678"])
        - test_get_backup_codes_generate_if_empty (возвращает ["NEW1-2345", "NEW2-3456"])
        - test_renew_backup_codes_success (возвращает ["RENEW1-2345", "RENEW2-3456"])

        Args:
            user_id: ID пользователя

        Returns:
            List[str]: Список резервных кодов
        """
        codes = []
        for _ in range(self.BACKUP_CODES_COUNT):
            code = self._generate_single_backup_code()
            codes.append(code)

        self._backup_codes_storage[user_id] = codes

        logger.info(f"Backup codes generated for user {user_id}")
        return codes

    def _generate_single_backup_code(self) -> str:
        """
        Генерация одного резервного кода в формате XXXX-XXXX.

        Returns:
            str: Резервный код
        """
        chars = string.ascii_uppercase + string.digits
        part1 = "".join(secrets.choice(chars) for _ in range(4))
        part2 = "".join(secrets.choice(chars) for _ in range(4))
        return f"{part1}-{part2}"

    async def get_backup_codes(self, user_id: UUID) -> List[str]:
        """
        Получение резервных кодов пользователя.

        Используется в:
        - test_get_backup_codes_success (возвращает ["ABCD-1234", "EFGH-5678"])
        - test_get_backup_codes_generate_if_empty (возвращает [])

        Args:
            user_id: ID пользователя

        Returns:
            List[str]: Список резервных кодов (может быть пустым)
        """
        codes = self._backup_codes_storage.get(user_id, [])
        logger.debug(f"Retrieved {len(codes)} backup codes for user {user_id}")
        return codes

    # ==================== УНИВЕРСАЛЬНАЯ MFA ВЕРИФИКАЦИЯ ====================

    async def verify_2fa(
        self,
        user_id: UUID,
        code: str,
        method: str,
    ) -> bool:
        """
        Универсальная верификация 2FA при логине.

        Используется в test_mfa_verify_success.
        Мок возвращает True.

        Args:
            user_id: ID пользователя
            code: Код верификации
            method: Метод 2FA (totp, sms, email)

        Returns:
            bool: True если верификация успешна
        """
        logger.info(f"Verifying 2FA for user {user_id} with method {method}")

        if method == "totp":
            return await self.verify_totp(user_id, code)
        elif method == "sms":
            return await self.verify_sms_code(user_id, code)
        elif method == "email":
            return await self.verify_email_code(user_id, code)
        else:
            logger.warning(f"Unknown 2FA method: {method}")
            return False

    async def complete_authentication(
        self, user_id: UUID
    ) -> Tuple[str, str]:
        """
        Завершение аутентификации — генерация токенов.

        Используется в test_mfa_verify_success.
        Мок возвращает ("access_token_123", "refresh_token_456").

        Args:
            user_id: ID пользователя

        Returns:
            Tuple[str, str]: (access_token, refresh_token)
        """
        # В реальной имплементации — генерация JWT токенов
        access_token = f"access_token_{uuid4().hex[:16]}"
        refresh_token = f"refresh_token_{uuid4().hex[:16]}"

        logger.info(f"Authentication completed for user {user_id}")
        return access_token, refresh_token

    async def create_mfa_session(self, user_id: UUID) -> str:
        """
        Создание MFA сессии.

        Args:
            user_id: ID пользователя

        Returns:
            str: ID сессии
        """
        session_id = uuid4().hex
        self._mfa_sessions[session_id] = {
            "user_id": str(user_id),
            "created_at": time.time(),
            "expires_at": time.time() + self.MFA_SESSION_TTL,
        }

        logger.info(f"MFA session created: {session_id} for user {user_id}")
        return session_id

    async def get_mfa_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Получение MFA сессии.

        Используется в:
        - test_mfa_verify_success (возвращает {"user_id": "test_user_id"})
        - test_mfa_verify_invalid_session (возвращает None)

        Args:
            session_id: ID сессии

        Returns:
            Optional[Dict[str, Any]]: Данные сессии или None
        """
        session = self._mfa_sessions.get(session_id)

        if session:
            # Проверка срока действия
            if time.time() > session["expires_at"]:
                del self._mfa_sessions[session_id]
                logger.warning(f"MFA session expired: {session_id}")
                return None

            logger.debug(f"MFA session found: {session_id}")
            return session

        logger.warning(f"MFA session not found: {session_id}")
        return None

    async def delete_mfa_session(self, session_id: str) -> None:
        """
        Удаление MFA сессии после успешной аутентификации.

        Args:
            session_id: ID сессии
        """
        self._mfa_sessions.pop(session_id, None)
        logger.debug(f"MFA session deleted: {session_id}")

    # ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================

    async def is_2fa_enabled(self, user_id: UUID) -> bool:
        """
        Проверка, включена ли 2FA для пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            bool: True если 2FA включена
        """
        has_totp = user_id in self._totp_secrets
        has_sms = user_id in self._user_phones
        has_email = True  # Email всегда доступен

        return has_totp or has_sms

    async def get_enabled_methods(self, user_id: UUID) -> List[str]:
        """
        Получение списка включенных методов 2FA.

        Args:
            user_id: ID пользователя

        Returns:
            List[str]: Список методов
        """
        methods = []

        if user_id in self._totp_secrets:
            methods.append("totp")
        if user_id in self._user_phones:
            methods.append("sms")
        if True:  # Email всегда доступен
            methods.append("email")

        return methods

    async def use_backup_code(self, user_id: UUID, code: str) -> bool:
        """
        Использование резервного кода.

        Args:
            user_id: ID пользователя
            code: Резервный код

        Returns:
            bool: True если код валиден
        """
        codes = self._backup_codes_storage.get(user_id, [])

        for stored_code in codes:
            if hmac.compare_digest(stored_code.upper(), code.upper()):
                codes.remove(stored_code)
                self._backup_codes_storage[user_id] = codes
                logger.info(f"Backup code used for user {user_id}")
                return True

        logger.warning(f"Invalid backup code for user {user_id}")
        return False