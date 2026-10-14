"""
Сервис для Rate Limiting.

Обеспечивает:
- Атомарную проверку и инкремент счётчиков через Redis
- Rate limiting для логина (по email и IP)
- Rate limiting для 2FA (по user_id и IP)
- Rate limiting для отправки Email/SMS 2FA
- Временную блокировку после превышения лимита
- Сброс счётчиков после успешной аутентификации
- Получение оставшихся попыток
- Защиту от брутфорс-атак

Совместимость с тестами:
- TestMFARateLimiting::test_totp_verify_rate_limit_exceeded (возврат 5 → 429)
- TestMFARateLimiting::test_sms_send_rate_limit_exceeded (возврат 3 → 429)
- Все эндпоинты MFA роутера используют check_rate_limit() для единообразия

Связанные модули:
- app.routers.mfa - MFA роутер (вызывает check_rate_limit)
- app.core.redis_client - клиент Redis
- app.services.redis_service - Redis сервис
"""

from typing import Tuple, Optional
from datetime import datetime, timedelta

from app.core.logging import get_logger
from app.core.redis_client import redis_client
from app.services.redis_service import RedisService


logger = get_logger(__name__)


class RateLimitService:
    """
    Сервис для Rate Limiting.

    Предоставляет методы для проверки и инкремента счётчиков,
    блокировки после превышения лимита и сброса счётчиков.

    Унифицированный метод check_rate_limit() используется всеми
    MFA эндпоинтами для совместимости с интеграционными тестами.
    """

    # Настройки по умолчанию
    DEFAULT_LOGIN_LIMIT = 5
    DEFAULT_LOGIN_WINDOW = 60  # 1 минута
    DEFAULT_LOGIN_BLOCK_DURATION = 900  # 15 минут

    DEFAULT_2FA_LIMIT = 5
    DEFAULT_2FA_WINDOW = 60  # 1 минута
    DEFAULT_2FA_BLOCK_DURATION = 900  # 15 минут

    DEFAULT_EMAIL_2FA_LIMIT = 3
    DEFAULT_EMAIL_2FA_WINDOW = 600  # 10 минут

    DEFAULT_SMS_2FA_LIMIT = 3
    DEFAULT_SMS_2FA_WINDOW = 600  # 10 минут

    @staticmethod
    async def check_rate_limit(
        key: str,
        limit: int = 5,
        window_seconds: int = 60,
    ) -> int:
        """
        Унифицированный метод проверки rate limit для MFA эндпоинтов.

        Используется всеми MFA эндпоинтами для совместимости с тестами:
        - test_totp_verify_rate_limit_exceeded (limit=5, возврат 5 → 429)
        - test_sms_send_rate_limit_exceeded (limit=3, возврат 3 → 429)

        Args:
            key: Ключ счётчика (например, f"rate:mfa:totp:verify:{user_id}")
            limit: Максимальное количество попыток в окне
            window_seconds: Временное окно в секундах

        Returns:
            int: Текущее количество попыток (1 = первая попытка, limit+1 = превышение)
        """
        try:
            count = await redis_client.incr(key, ttl=window_seconds)
            logger.debug(
                f"Rate limit check: key={key}, count={count}, limit={limit}"
            )
            return count
        except Exception as e:
            logger.error(f"Rate limit check failed for {key}: {e}")
            # В случае ошибки Redis - разрешаем запрос (fail open)
            return 1

    @staticmethod
    async def check_and_increment(
        key: str,
        limit: int,
        window_seconds: int,
    ) -> Tuple[bool, int]:
        """
        Атомарная проверка и инкремент счётчика.

        Args:
            key: Ключ счётчика
            limit: Максимальное количество попыток
            window_seconds: Временное окно в секундах

        Returns:
            Tuple[bool, int]: (разрешено, текущее количество)
        """
        try:
            count = await redis_client.incr(key, ttl=window_seconds)
            allowed = count <= limit
            logger.debug(
                f"Rate limit check: key={key}, count={count}, limit={limit}, allowed={allowed}"
            )
            return allowed, count
        except Exception as e:
            logger.error(f"Rate limit check failed for {key}: {e}")
            # В случае ошибки Redis - разрешаем запрос (fail open)
            return True, 0

    @staticmethod
    async def check_login_attempts(
        email: str,
        ip: str,
        limit: int = DEFAULT_LOGIN_LIMIT,
        window_seconds: int = DEFAULT_LOGIN_WINDOW,
        block_duration: int = DEFAULT_LOGIN_BLOCK_DURATION,
    ) -> Tuple[bool, bool, Optional[int]]:
        """
        Проверка лимита попыток входа.

        Args:
            email: Email пользователя
            ip: IP адрес
            limit: Лимит попыток
            window_seconds: Временное окно
            block_duration: Длительность блокировки в секундах

        Returns:
            Tuple[bool, bool, Optional[int]]:
                (разрешено, заблокирован, время до разблокировки)
        """
        # Проверка блокировки по email
        email_block_key = f"rate:login:block:email:{email}"
        is_blocked, blocked_until = await RateLimitService._is_blocked(email_block_key)

        if is_blocked:
            logger.warning(f"Login blocked for email: {email}, until: {blocked_until}s")
            return False, True, blocked_until

        # Проверка блокировки по IP
        ip_block_key = f"rate:login:block:ip:{ip}"
        is_blocked_ip, _ = await RateLimitService._is_blocked(ip_block_key)
        if is_blocked_ip:
            # Используем тот же таймаут что и для email
            return False, True, blocked_until

        # Проверка количества попыток по email
        email_key = f"rate:login:email:{email}"
        allowed_email, count_email = await RateLimitService.check_and_increment(
            email_key, limit, window_seconds
        )

        # Проверка количества попыток по IP
        ip_key = f"rate:login:ip:{ip}"
        allowed_ip, count_ip = await RateLimitService.check_and_increment(
            ip_key, limit, window_seconds
        )

        # Если превышен лимит по email или IP - блокируем
        if not allowed_email or not allowed_ip:
            # Блокируем email
            await RateLimitService._block_key(email_block_key, block_duration)
            # Блокируем IP
            await RateLimitService._block_key(ip_block_key, block_duration)

            logger.warning(
                f"Login blocked for email: {email}, ip: {ip}, "
                f"email_count: {count_email}, ip_count: {count_ip}"
            )
            return False, True, block_duration

        return True, False, None

    @staticmethod
    async def record_login_attempt(
        email: str,
        ip: str,
        success: bool,
        window_seconds: int = DEFAULT_LOGIN_WINDOW,
    ) -> None:
        """
        Запись попытки входа.

        Args:
            email: Email пользователя
            ip: IP адрес
            success: Успешность попытки
            window_seconds: Временное окно для счётчика
        """
        if success:
            # При успешном входе - сбрасываем все счётчики
            email_key = f"rate:login:email:{email}"
            ip_key = f"rate:login:ip:{ip}"
            email_block_key = f"rate:login:block:email:{email}"
            ip_block_key = f"rate:login:block:ip:{ip}"

            await redis_client.delete(email_key, ip_key, email_block_key, ip_block_key)
            logger.debug(f"Reset login counters for email: {email}")
        else:
            # При неудаче - уже заинкрементили в check_login_attempts
            logger.debug(f"Failed login attempt for email: {email}, ip: {ip}")

    @staticmethod
    async def check_2fa_attempts(
        user_id: str,
        ip: str,
        limit: int = DEFAULT_2FA_LIMIT,
        window_seconds: int = DEFAULT_2FA_WINDOW,
        block_duration: int = DEFAULT_2FA_BLOCK_DURATION,
    ) -> Tuple[bool, bool, Optional[int]]:
        """
        Проверка лимита попыток 2FA.

        Args:
            user_id: ID пользователя
            ip: IP адрес
            limit: Лимит попыток
            window_seconds: Временное окно
            block_duration: Длительность блокировки

        Returns:
            Tuple[bool, bool, Optional[int]]:
                (разрешено, заблокирован, время до разблокировки)
        """
        # Проверка блокировки по user_id
        block_key = f"rate:2fa:block:user:{user_id}"
        is_blocked, blocked_until = await RateLimitService._is_blocked(block_key)

        if is_blocked:
            logger.warning(f"2FA blocked for user: {user_id}, until: {blocked_until}s")
            return False, True, blocked_until

        # Проверка количества попыток
        key = f"rate:2fa:user:{user_id}"
        allowed, count = await RateLimitService.check_and_increment(
            key, limit, window_seconds
        )

        if not allowed:
            await RateLimitService._block_key(block_key, block_duration)
            logger.warning(
                f"2FA blocked for user: {user_id}, count: {count}, limit: {limit}"
            )
            return False, True, block_duration

        return True, False, None

    @staticmethod
    async def record_2fa_attempt(
        user_id: str,
        ip: str,
        success: bool,
        window_seconds: int = DEFAULT_2FA_WINDOW,
    ) -> None:
        """
        Запись попытки 2FA.

        Args:
            user_id: ID пользователя
            ip: IP адрес
            success: Успешность попытки
            window_seconds: Временное окно
        """
        if success:
            key = f"rate:2fa:user:{user_id}"
            block_key = f"rate:2fa:block:user:{user_id}"
            await redis_client.delete(key, block_key)
            logger.debug(f"Reset 2FA counters for user: {user_id}")

    @staticmethod
    async def check_send_email_2fa(
        user_id: str,
        limit: int = DEFAULT_EMAIL_2FA_LIMIT,
        window_seconds: int = DEFAULT_EMAIL_2FA_WINDOW,
    ) -> Tuple[bool, int]:
        """
        Проверка лимита отправки Email 2FA.

        Args:
            user_id: ID пользователя
            limit: Лимит отправок
            window_seconds: Временное окно

        Returns:
            Tuple[bool, int]: (разрешено, текущее количество)
        """
        key = f"rate:email_2fa:user:{user_id}"
        allowed, count = await RateLimitService.check_and_increment(
            key, limit, window_seconds
        )
        return allowed, count

    @staticmethod
    async def record_send_email_2fa(
        user_id: str,
        window_seconds: int = DEFAULT_EMAIL_2FA_WINDOW,
    ) -> int:
        """
        Запись отправки Email 2FA.

        Args:
            user_id: ID пользователя
            window_seconds: Временное окно

        Returns:
            int: Текущее количество отправок
        """
        key = f"rate:email_2fa:user:{user_id}"
        count = await redis_client.incr(key, ttl=window_seconds)
        logger.debug(f"Email 2FA sent for user: {user_id}, count: {count}")
        return count

    @staticmethod
    async def check_send_sms_2fa(
        user_id: str,
        limit: int = DEFAULT_SMS_2FA_LIMIT,
        window_seconds: int = DEFAULT_SMS_2FA_WINDOW,
    ) -> Tuple[bool, int]:
        """
        Проверка лимита отправки SMS 2FA.

        Args:
            user_id: ID пользователя
            limit: Лимит отправок
            window_seconds: Временное окно

        Returns:
            Tuple[bool, int]: (разрешено, текущее количество)
        """
        key = f"rate:sms_2fa:user:{user_id}"
        allowed, count = await RateLimitService.check_and_increment(
            key, limit, window_seconds
        )
        return allowed, count

    @staticmethod
    async def record_send_sms_2fa(
        user_id: str,
        window_seconds: int = DEFAULT_SMS_2FA_WINDOW,
    ) -> int:
        """
        Запись отправки SMS 2FA.

        Args:
            user_id: ID пользователя
            window_seconds: Временное окно

        Returns:
            int: Текущее количество отправок
        """
        key = f"rate:sms_2fa:user:{user_id}"
        count = await redis_client.incr(key, ttl=window_seconds)
        logger.debug(f"SMS 2FA sent for user: {user_id}, count: {count}")
        return count

    @staticmethod
    async def _is_blocked(key: str) -> Tuple[bool, Optional[int]]:
        """
        Проверка, заблокирован ли ключ.

        Args:
            key: Ключ блокировки

        Returns:
            Tuple[bool, Optional[int]]: (заблокирован, время до разблокировки)
        """
        try:
            ttl = await redis_client.ttl(key)
            if ttl > 0:
                return True, ttl
            return False, None
        except Exception as e:
            logger.error(f"Failed to check block for {key}: {e}")
            return False, None

    @staticmethod
    async def _block_key(key: str, duration_seconds: int) -> bool:
        """
        Блокировка ключа на указанное время.

        Args:
            key: Ключ для блокировки
            duration_seconds: Длительность блокировки в секундах

        Returns:
            bool: True если блокировка успешна
        """
        try:
            return await redis_client.set(key, "1", ttl=duration_seconds)
        except Exception as e:
            logger.error(f"Failed to block key {key}: {e}")
            return False

    @staticmethod
    async def get_login_attempts_remaining(
        email: str,
        ip: str,
        limit: int = DEFAULT_LOGIN_LIMIT,
    ) -> Tuple[int, int]:
        """
        Получение оставшихся попыток входа.

        Args:
            email: Email пользователя
            ip: IP адрес
            limit: Лимит попыток

        Returns:
            Tuple[int, int]: (осталось по email, осталось по IP)
        """
        email_key = f"rate:login:email:{email}"
        ip_key = f"rate:login:ip:{ip}"

        email_count = await RedisService.get_rate_limit(email_key)
        ip_count = await RedisService.get_rate_limit(ip_key)

        remaining_email = max(0, limit - email_count)
        remaining_ip = max(0, limit - ip_count)

        return remaining_email, remaining_ip

    @staticmethod
    async def get_2fa_attempts_remaining(
        user_id: str,
        limit: int = DEFAULT_2FA_LIMIT,
    ) -> int:
        """
        Получение оставшихся попыток 2FA.

        Args:
            user_id: ID пользователя
            limit: Лимит попыток

        Returns:
            int: Осталось попыток
        """
        key = f"rate:2fa:user:{user_id}"
        count = await RedisService.get_rate_limit(key)
        return max(0, limit - count)

    @staticmethod
    async def reset_rate_limit(key: str) -> int:
        """
        Сброс rate limit для ключа.

        Args:
            key: Ключ для сброса

        Returns:
            int: Количество удаленных ключей
        """
        try:
            return await redis_client.delete(key)
        except Exception as e:
            logger.error(f"Failed to reset rate limit for {key}: {e}")
            return 0

    @staticmethod
    async def unblock_key(key: str) -> int:
        """
        Снятие блокировки с ключа.

        Args:
            key: Ключ блокировки

        Returns:
            int: Количество удаленных ключей
        """
        try:
            return await redis_client.delete(key)
        except Exception as e:
            logger.error(f"Failed to unblock key {key}: {e}")
            return 0

    @staticmethod
    async def record_failed_attempt_by_key(
        key: str,
        ttl_seconds: int = 60,
    ) -> int:
        """
        Запись неудачной попытки по ключу.

        Args:
            key: Ключ счётчика
            ttl_seconds: TTL в секундах

        Returns:
            int: Текущее количество попыток
        """
        try:
            count = await redis_client.incr(key, ttl=ttl_seconds)
            return count
        except Exception as e:
            logger.error(f"Failed to record attempt for {key}: {e}")
            return 0

    @staticmethod
    async def is_temporarily_blocked(key: str) -> Tuple[bool, Optional[int]]:
        """
        Проверка временной блокировки (асинхронная версия).

        Args:
            key: Ключ блокировки

        Returns:
            Tuple[bool, Optional[int]]: (заблокирован, оставшееся время)
        """
        return await RateLimitService._is_blocked(key)