"""
Интеграционные тесты для Rate Limiting Service с реальным Redis.

Тестирует:
- check_and_increment - атомарная проверка и инкремент
- check_login_attempts - проверка лимита попыток входа
- record_login_attempt - запись попытки входа
- 2FA rate limiting (check_2fa_attempts, record_2fa_attempt)
- Email/SMS 2FA send limiting
- Блокировку после превышения лимита
- Сброс счётчиков после успеха
- Получение оставшихся попыток
- Граничные случаи и TTL

Архитектура:
- Реальная логика: RateLimitService, Redis
- Использует глобальный manage_test_redis из conftest.py
"""

import pytest
import pytest_asyncio

from app.services.rate_limit_service import RateLimitService
from app.core.redis_client import redis_client


@pytest_asyncio.fixture(autouse=True)
async def clean_redis():
    """Очистка Redis перед каждым тестом."""
    if redis_client.is_initialized:
        await redis_client.flushdb()
    yield
    if redis_client.is_initialized:
        await redis_client.flushdb()


class TestCheckAndIncrement:
    """Тесты для метода check_and_increment."""

    @pytest.mark.asyncio
    async def test_check_and_increment_within_limit(self):
        allowed, count = await RateLimitService.check_and_increment(
            key="test:within", limit=5, window_seconds=60,
        )
        assert allowed is True
        assert count == 1

    @pytest.mark.asyncio
    async def test_check_and_increment_exceeds_limit(self):
        for _ in range(5):
            await RateLimitService.check_and_increment(
                key="test:exceed", limit=5, window_seconds=60,
            )
        allowed, count = await RateLimitService.check_and_increment(
            key="test:exceed", limit=5, window_seconds=60,
        )
        assert allowed is False
        assert count == 6


class TestCheckLoginAttempts:
    """Тесты для метода check_login_attempts."""

    @pytest.mark.asyncio
    async def test_check_login_attempts_allowed(self):
        allowed, is_blocked, blocked_until = await RateLimitService.check_login_attempts(
            email="login_ok@example.com", ip="10.0.0.1", limit=5, window_seconds=60,
        )
        assert allowed is True
        assert is_blocked is False

    @pytest.mark.asyncio
    async def test_check_login_attempts_blocked(self):
        for _ in range(6):
            await RateLimitService.check_login_attempts(
                email="login_block@example.com", ip="10.0.0.2", limit=5, window_seconds=60,
            )
        allowed, is_blocked, blocked_until = await RateLimitService.check_login_attempts(
            email="login_block@example.com", ip="10.0.0.2", limit=5, window_seconds=60,
        )
        assert allowed is False
        assert is_blocked is True
        assert blocked_until is not None


class TestRecordLoginAttempt:
    """Тесты для метода record_login_attempt."""

    @pytest.mark.asyncio
    async def test_record_login_attempt_success_resets_counters(self):
        await RateLimitService.check_login_attempts(
            email="reset@example.com", ip="10.0.0.3", limit=5, window_seconds=60,
        )
        await RateLimitService.record_login_attempt(
            email="reset@example.com", ip="10.0.0.3", success=True,
        )
        allowed, _, _ = await RateLimitService.check_login_attempts(
            email="reset@example.com", ip="10.0.0.3", limit=5, window_seconds=60,
        )
        assert allowed is True


class TestCheck2FAAttempts:
    """Тесты для метода check_2fa_attempts."""

    @pytest.mark.asyncio
    async def test_check_2fa_attempts_allowed(self):
        allowed, is_blocked, _ = await RateLimitService.check_2fa_attempts(
            user_id="2fa_ok", ip="10.0.0.4", limit=5, window_seconds=60,
        )
        assert allowed is True
        assert is_blocked is False

    @pytest.mark.asyncio
    async def test_check_2fa_attempts_blocked(self):
        for _ in range(6):
            await RateLimitService.check_2fa_attempts(
                user_id="2fa_block", ip="10.0.0.5", limit=5, window_seconds=60,
            )
        allowed, is_blocked, blocked_until = await RateLimitService.check_2fa_attempts(
            user_id="2fa_block", ip="10.0.0.5", limit=5, window_seconds=60,
        )
        assert allowed is False
        assert is_blocked is True


class TestRecord2FAAttempt:
    """Тесты для метода record_2fa_attempt."""

    @pytest.mark.asyncio
    async def test_record_2fa_attempt_success_resets(self):
        await RateLimitService.check_2fa_attempts(
            user_id="2fa_reset", ip="10.0.0.6", limit=5, window_seconds=60,
        )
        await RateLimitService.record_2fa_attempt(
            user_id="2fa_reset", ip="10.0.0.6", success=True,
        )
        allowed, _, _ = await RateLimitService.check_2fa_attempts(
            user_id="2fa_reset", ip="10.0.0.6", limit=5, window_seconds=60,
        )
        assert allowed is True


class TestEmail2FASendLimiting:
    """Тесты для Email 2FA send limiting."""

    @pytest.mark.asyncio
    async def test_check_send_email_2fa_allowed(self):
        allowed, count = await RateLimitService.check_send_email_2fa(
            user_id="email_2fa", limit=3, window_seconds=600,
        )
        assert allowed is True
        assert count == 1

    @pytest.mark.asyncio
    async def test_check_send_email_2fa_exceeds_limit(self):
        for _ in range(3):
            await RateLimitService.check_send_email_2fa(
                user_id="email_2fa_block", limit=3, window_seconds=600,
            )
        allowed, count = await RateLimitService.check_send_email_2fa(
            user_id="email_2fa_block", limit=3, window_seconds=600,
        )
        assert allowed is False
        assert count == 4

    @pytest.mark.asyncio
    async def test_record_send_email_2fa(self):
        count = await RateLimitService.record_send_email_2fa(
            user_id="email_rec", window_seconds=600,
        )
        assert count == 1


class TestSMS2FASendLimiting:
    """Тесты для SMS 2FA send limiting."""

    @pytest.mark.asyncio
    async def test_check_send_sms_2fa_allowed(self):
        allowed, count = await RateLimitService.check_send_sms_2fa(
            user_id="sms_2fa", limit=3, window_seconds=600,
        )
        assert allowed is True
        assert count == 1

    @pytest.mark.asyncio
    async def test_record_send_sms_2fa(self):
        count = await RateLimitService.record_send_sms_2fa(user_id="sms_rec")
        assert count == 1


class TestBlockMethods:
    """Тесты для методов блокировки."""

    @pytest.mark.asyncio
    async def test_is_temporarily_blocked_true(self):
        await RateLimitService._block_key("block:test", duration_seconds=120)
        is_blocked, remaining = await RateLimitService.is_temporarily_blocked("block:test")
        assert is_blocked is True
        assert remaining is not None and remaining > 0

    @pytest.mark.asyncio
    async def test_is_temporarily_blocked_false(self):
        is_blocked, remaining = await RateLimitService.is_temporarily_blocked("block:none")
        assert is_blocked is False

    @pytest.mark.asyncio
    async def test_unblock_key(self):
        await RateLimitService._block_key("block:unblock", duration_seconds=60)
        deleted = await RateLimitService.unblock_key("block:unblock")
        assert deleted == 1
        is_blocked, _ = await RateLimitService.is_temporarily_blocked("block:unblock")
        assert is_blocked is False


class TestGetRemainingAttempts:
    """Тесты для получения оставшихся попыток."""

    @pytest.mark.asyncio
    async def test_get_login_attempts_remaining(self):
        await RateLimitService.check_login_attempts(
            email="remain@example.com", ip="10.0.0.7", limit=5, window_seconds=60,
        )
        await RateLimitService.check_login_attempts(
            email="remain@example.com", ip="10.0.0.7", limit=5, window_seconds=60,
        )
        rem_email, rem_ip = await RateLimitService.get_login_attempts_remaining(
            email="remain@example.com", ip="10.0.0.7", limit=5,
        )
        assert rem_email >= 0
        assert rem_ip >= 0

    @pytest.mark.asyncio
    async def test_get_2fa_attempts_remaining(self):
        await RateLimitService.check_2fa_attempts(
            user_id="2fa_rem", ip="10.0.0.8", limit=5, window_seconds=60,
        )
        remaining = await RateLimitService.get_2fa_attempts_remaining(
            user_id="2fa_rem", limit=5,
        )
        assert remaining >= 0


class TestEdgeCases:
    """Тесты для граничных случаев."""

    @pytest.mark.asyncio
    async def test_check_and_increment_exact_limit(self):
        for _ in range(5):
            await RateLimitService.check_and_increment(
                key="test:exact", limit=5, window_seconds=60,
            )
        allowed, count = await RateLimitService.check_and_increment(
            key="test:exact", limit=5, window_seconds=60,
        )
        assert allowed is False
        assert count == 6

    @pytest.mark.asyncio
    async def test_reset_rate_limit(self):
        await RateLimitService.check_and_increment(
            key="test:reset", limit=5, window_seconds=60,
        )
        deleted = await RateLimitService.reset_rate_limit(key="test:reset")
        assert deleted == 1

    @pytest.mark.asyncio
    async def test_record_failed_attempt_by_key(self):
        count = await RateLimitService.record_failed_attempt_by_key(
            key="test:failed", ttl_seconds=60,
        )
        assert count == 1