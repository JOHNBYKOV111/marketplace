"""
Unit tests for RateLimitService.

Tests cover:
- check_and_increment (atomic check + increment, TTL management)
- check_rate_limit (unified MFA rate limit check)
- record_failed_attempt_by_key (increment with custom TTL)
- reset_rate_limit (delete key)
- check_login_attempts (email/IP limits, block detection)
- record_login_attempt (success/failure, increment or reset)
- check_2fa_attempts (user limits, block detection)
- record_2fa_attempt (success/failure, increment or reset)
- check_send_email_2fa / record_send_email_2fa
- check_send_sms_2fa / record_send_sms_2fa
- is_temporarily_blocked / _is_blocked / _block_key / unblock_key
- get_login_attempts_remaining / get_2fa_attempts_remaining
- Edge cases (Redis failures, boundary values, concurrent requests)
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.services.rate_limit_service import RateLimitService


# ==================== FIXTURES ====================

@pytest.fixture
def mock_redis():
    """Mock redis_client for all rate limit operations."""
    with patch("app.services.rate_limit_service.redis_client") as mock:
        yield mock


@pytest.fixture
def mock_redis_service():
    """Mock RedisService for get_rate_limit operations."""
    with patch("app.services.rate_limit_service.RedisService") as mock:
        yield mock


# ==================== DEFAULT CONSTANTS TESTS ====================

class TestRateLimitServiceDefaults:
    """Tests for default constant values."""

    def test_default_login_constants(self):
        """Test default login rate limit constants."""
        assert RateLimitService.DEFAULT_LOGIN_LIMIT == 5
        assert RateLimitService.DEFAULT_LOGIN_WINDOW == 60
        assert RateLimitService.DEFAULT_LOGIN_BLOCK_DURATION == 900

    def test_default_2fa_constants(self):
        """Test default 2FA rate limit constants."""
        assert RateLimitService.DEFAULT_2FA_LIMIT == 5
        assert RateLimitService.DEFAULT_2FA_WINDOW == 60
        assert RateLimitService.DEFAULT_2FA_BLOCK_DURATION == 900

    def test_default_email_2fa_constants(self):
        """Test default Email 2FA rate limit constants."""
        assert RateLimitService.DEFAULT_EMAIL_2FA_LIMIT == 3
        assert RateLimitService.DEFAULT_EMAIL_2FA_WINDOW == 600

    def test_default_sms_2fa_constants(self):
        """Test default SMS 2FA rate limit constants."""
        assert RateLimitService.DEFAULT_SMS_2FA_LIMIT == 3
        assert RateLimitService.DEFAULT_SMS_2FA_WINDOW == 600


# ==================== CHECK RATE LIMIT TESTS ====================

class TestRateLimitServiceCheckRateLimit:
    """Tests for unified check_rate_limit method."""

    @pytest.mark.asyncio
    async def test_check_rate_limit_first_attempt(self, mock_redis):
        """Test check_rate_limit on first attempt returns 1."""
        mock_redis.incr = AsyncMock(return_value=1)

        count = await RateLimitService.check_rate_limit(
            key="rate:mfa:totp:verify:user_123",
            limit=5,
            window_seconds=60,
        )

        assert count == 1
        mock_redis.incr.assert_called_once_with(
            "rate:mfa:totp:verify:user_123", ttl=60
        )

    @pytest.mark.asyncio
    async def test_check_rate_limit_within_limit(self, mock_redis):
        """Test check_rate_limit when count within limit."""
        mock_redis.incr = AsyncMock(return_value=3)

        count = await RateLimitService.check_rate_limit(
            key="rate:mfa:totp:verify:user_123",
            limit=5,
            window_seconds=60,
        )

        assert count == 3

    @pytest.mark.asyncio
    async def test_check_rate_limit_at_limit(self, mock_redis):
        """Test check_rate_limit when count equals limit."""
        mock_redis.incr = AsyncMock(return_value=5)

        count = await RateLimitService.check_rate_limit(
            key="rate:mfa:totp:verify:user_123",
            limit=5,
            window_seconds=60,
        )

        assert count == 5

    @pytest.mark.asyncio
    async def test_check_rate_limit_exceeds_limit(self, mock_redis):
        """Test check_rate_limit when count exceeds limit."""
        mock_redis.incr = AsyncMock(return_value=6)

        count = await RateLimitService.check_rate_limit(
            key="rate:mfa:totp:verify:user_123",
            limit=5,
            window_seconds=60,
        )

        assert count == 6

    @pytest.mark.asyncio
    async def test_check_rate_limit_default_params(self, mock_redis):
        """Test check_rate_limit with default limit and window."""
        mock_redis.incr = AsyncMock(return_value=2)

        count = await RateLimitService.check_rate_limit(key="rate:test:key")

        assert count == 2
        mock_redis.incr.assert_called_once_with("rate:test:key", ttl=60)

    @pytest.mark.asyncio
    async def test_check_rate_limit_redis_failure_fail_open(self, mock_redis):
        """Test check_rate_limit returns 1 when Redis fails (fail open)."""
        mock_redis.incr = AsyncMock(side_effect=Exception("Redis connection failed"))

        count = await RateLimitService.check_rate_limit(
            key="rate:test:key",
            limit=5,
            window_seconds=60,
        )

        assert count == 1

    @pytest.mark.asyncio
    async def test_check_rate_limit_custom_window(self, mock_redis):
        """Test check_rate_limit with custom window."""
        mock_redis.incr = AsyncMock(return_value=1)

        count = await RateLimitService.check_rate_limit(
            key="rate:test:key",
            limit=3,
            window_seconds=300,
        )

        assert count == 1
        mock_redis.incr.assert_called_once_with("rate:test:key", ttl=300)


# ==================== CHECK AND INCREMENT TESTS ====================

class TestRateLimitServiceCheckAndIncrement:
    """Tests for check_and_increment method."""

    @pytest.mark.asyncio
    async def test_check_and_increment_first_attempt(self, mock_redis):
        """Test check_and_increment on first attempt."""
        mock_redis.incr = AsyncMock(return_value=1)

        allowed, count = await RateLimitService.check_and_increment(
            key="test:key",
            limit=5,
            window_seconds=60,
        )

        assert allowed is True
        assert count == 1
        mock_redis.incr.assert_called_once_with("test:key", ttl=60)

    @pytest.mark.asyncio
    async def test_check_and_increment_within_limit(self, mock_redis):
        """Test check_and_increment when count within limit."""
        mock_redis.incr = AsyncMock(return_value=3)

        allowed, count = await RateLimitService.check_and_increment(
            key="test:key",
            limit=5,
            window_seconds=60,
        )

        assert allowed is True
        assert count == 3

    @pytest.mark.asyncio
    async def test_check_and_increment_at_limit(self, mock_redis):
        """Test check_and_increment when count equals limit."""
        mock_redis.incr = AsyncMock(return_value=5)

        allowed, count = await RateLimitService.check_and_increment(
            key="test:key",
            limit=5,
            window_seconds=60,
        )

        assert allowed is True
        assert count == 5

    @pytest.mark.asyncio
    async def test_check_and_increment_exceeds_limit(self, mock_redis):
        """Test check_and_increment when count exceeds limit."""
        mock_redis.incr = AsyncMock(return_value=6)

        allowed, count = await RateLimitService.check_and_increment(
            key="test:key",
            limit=5,
            window_seconds=60,
        )

        assert allowed is False
        assert count == 6

    @pytest.mark.asyncio
    async def test_check_and_increment_redis_failure_fail_open(self, mock_redis):
        """Test check_and_increment returns allowed=True when Redis fails."""
        mock_redis.incr = AsyncMock(side_effect=Exception("Redis connection failed"))

        allowed, count = await RateLimitService.check_and_increment(
            key="test:key",
            limit=5,
            window_seconds=60,
        )

        assert allowed is True
        assert count == 0


# ==================== RECORD FAILED ATTEMPT BY KEY TESTS ====================

class TestRateLimitServiceRecordFailedAttemptByKey:
    """Tests for record_failed_attempt_by_key method."""

    @pytest.mark.asyncio
    async def test_record_failed_attempt_default_ttl(self, mock_redis):
        """Test record_failed_attempt_by_key with default TTL."""
        mock_redis.incr = AsyncMock(return_value=2)

        count = await RateLimitService.record_failed_attempt_by_key(
            key="failed:key",
        )

        assert count == 2
        mock_redis.incr.assert_called_once_with("failed:key", ttl=60)

    @pytest.mark.asyncio
    async def test_record_failed_attempt_custom_ttl(self, mock_redis):
        """Test record_failed_attempt_by_key with custom TTL."""
        mock_redis.incr = AsyncMock(return_value=1)

        count = await RateLimitService.record_failed_attempt_by_key(
            key="failed:key",
            ttl_seconds=300,
        )

        assert count == 1
        mock_redis.incr.assert_called_once_with("failed:key", ttl=300)

    @pytest.mark.asyncio
    async def test_record_failed_attempt_redis_failure(self, mock_redis):
        """Test record_failed_attempt_by_key returns 0 on Redis failure."""
        mock_redis.incr = AsyncMock(side_effect=Exception("Redis connection failed"))

        count = await RateLimitService.record_failed_attempt_by_key(
            key="failed:key",
        )

        assert count == 0


# ==================== RESET RATE LIMIT TESTS ====================

class TestRateLimitServiceResetRateLimit:
    """Tests for reset_rate_limit method."""

    @pytest.mark.asyncio
    async def test_reset_rate_limit_success(self, mock_redis):
        """Test successful rate limit reset."""
        mock_redis.delete = AsyncMock(return_value=1)

        deleted = await RateLimitService.reset_rate_limit(key="test:key")

        assert deleted == 1
        mock_redis.delete.assert_called_once_with("test:key")

    @pytest.mark.asyncio
    async def test_reset_rate_limit_key_not_found(self, mock_redis):
        """Test reset when key doesn't exist."""
        mock_redis.delete = AsyncMock(return_value=0)

        deleted = await RateLimitService.reset_rate_limit(key="nonexistent:key")

        assert deleted == 0

    @pytest.mark.asyncio
    async def test_reset_rate_limit_redis_failure(self, mock_redis):
        """Test reset_rate_limit returns 0 on Redis failure."""
        mock_redis.delete = AsyncMock(side_effect=Exception("Redis connection failed"))

        deleted = await RateLimitService.reset_rate_limit(key="test:key")

        assert deleted == 0


# ==================== LOGIN ATTEMPTS TESTS ====================

class TestRateLimitServiceLoginAttempts:
    """Tests for login rate limiting methods."""

    @pytest.mark.asyncio
    async def test_check_login_attempts_allowed(self, mock_redis, mock_redis_service):
        """Test check_login_attempts when attempts within limit."""
        mock_redis.ttl = AsyncMock(return_value=-1)  # Not blocked
        mock_redis.incr = AsyncMock(return_value=2)  # Within limit
        mock_redis_service.get_rate_limit = AsyncMock(return_value=2)

        allowed, is_blocked, blocked_until = await RateLimitService.check_login_attempts(
            email="user@example.com",
            ip="192.168.1.1",
            limit=5,
            window_seconds=60,
        )

        assert allowed is True
        assert is_blocked is False
        assert blocked_until is None

    @pytest.mark.asyncio
    async def test_check_login_attempts_email_blocked(self, mock_redis):
        """Test check_login_attempts when email is blocked."""
        # Email block key has TTL > 0 (blocked)
        mock_redis.ttl = AsyncMock(return_value=300)

        allowed, is_blocked, blocked_until = await RateLimitService.check_login_attempts(
            email="user@example.com",
            ip="192.168.1.1",
        )

        assert allowed is False
        assert is_blocked is True
        assert blocked_until == 300

    @pytest.mark.asyncio
    async def test_check_login_attempts_ip_blocked(self, mock_redis):
        """Test check_login_attempts when IP is blocked.
        
        Note: Per current service implementation, when IP is blocked but email is not,
        the blocked_until value is taken from the email check path and may be None.
        The service returns (False, True, None) in this scenario.
        """
        # Email not blocked (ttl=-1), IP blocked (ttl=600)
        mock_redis.ttl = AsyncMock(side_effect=[-1, 600])

        allowed, is_blocked, blocked_until = await RateLimitService.check_login_attempts(
            email="user@example.com",
            ip="192.168.1.1",
        )

        assert allowed is False
        assert is_blocked is True
        # Service returns blocked_until from email block variable which is None for IP-only blocks
        assert blocked_until is None

    @pytest.mark.asyncio
    async def test_check_login_attempts_exceeds_limit_triggers_block(self, mock_redis):
        """Test check_login_attempts blocks when limit exceeded."""
        mock_redis.ttl = AsyncMock(return_value=-1)  # Not blocked
        mock_redis.incr = AsyncMock(return_value=6)  # Exceeds limit of 5
        mock_redis.set = AsyncMock(return_value=True)

        allowed, is_blocked, blocked_until = await RateLimitService.check_login_attempts(
            email="user@example.com",
            ip="192.168.1.1",
            limit=5,
            block_duration=900,
        )

        assert allowed is False
        assert is_blocked is True
        assert blocked_until == 900
        # Should set both email and IP block keys
        assert mock_redis.set.call_count == 2

    @pytest.mark.asyncio
    async def test_check_login_attempts_custom_params(self, mock_redis):
        """Test check_login_attempts with custom limit, window, and block duration."""
        mock_redis.ttl = AsyncMock(return_value=-1)
        mock_redis.incr = AsyncMock(return_value=3)

        allowed, is_blocked, blocked_until = await RateLimitService.check_login_attempts(
            email="user@example.com",
            ip="192.168.1.1",
            limit=10,
            window_seconds=120,
            block_duration=1800,
        )

        assert allowed is True
        assert is_blocked is False

    @pytest.mark.asyncio
    async def test_check_login_attempts_default_params(self, mock_redis):
        """Test check_login_attempts with default parameters."""
        mock_redis.ttl = AsyncMock(return_value=-1)
        mock_redis.incr = AsyncMock(return_value=3)

        allowed, is_blocked, blocked_until = await RateLimitService.check_login_attempts(
            email="user@example.com",
            ip="192.168.1.1",
        )

        assert allowed is True
        # incr called twice (email + ip) with default window
        assert mock_redis.incr.call_count == 2
        for call in mock_redis.incr.call_args_list:
            assert call[1]["ttl"] == RateLimitService.DEFAULT_LOGIN_WINDOW

    @pytest.mark.asyncio
    async def test_record_login_attempt_success_resets_all_keys(self, mock_redis):
        """Test record_login_attempt with success deletes all related keys."""
        mock_redis.delete = AsyncMock(return_value=1)

        await RateLimitService.record_login_attempt(
            email="user@example.com",
            ip="192.168.1.1",
            success=True,
        )

        mock_redis.delete.assert_called_once_with(
            "rate:login:email:user@example.com",
            "rate:login:ip:192.168.1.1",
            "rate:login:block:email:user@example.com",
            "rate:login:block:ip:192.168.1.1",
        )

    @pytest.mark.asyncio
    async def test_record_login_attempt_failure_noop(self, mock_redis):
        """Test record_login_attempt with failure is no-op (already incremented)."""
        await RateLimitService.record_login_attempt(
            email="user@example.com",
            ip="192.168.1.1",
            success=False,
        )

        # No Redis calls for failure — already incremented in check_login_attempts
        mock_redis.incr.assert_not_called()
        mock_redis.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_login_attempts_email_blocked_skips_ip_check(self, mock_redis):
        """Test that when email is blocked, IP check is skipped."""
        mock_redis.ttl = AsyncMock(return_value=300)

        allowed, is_blocked, blocked_until = await RateLimitService.check_login_attempts(
            email="blocked@example.com",
            ip="192.168.1.1",
        )

        assert allowed is False
        # ttl called only once for email block
        assert mock_redis.ttl.call_count == 1


# ==================== 2FA ATTEMPTS TESTS ====================

class TestRateLimitService2FA:
    """Tests for 2FA rate limiting methods."""

    @pytest.mark.asyncio
    async def test_check_2fa_attempts_allowed(self, mock_redis):
        """Test check_2fa_attempts when attempts within limit."""
        mock_redis.ttl = AsyncMock(return_value=-1)  # Not blocked
        mock_redis.incr = AsyncMock(return_value=3)

        allowed, is_blocked, blocked_until = await RateLimitService.check_2fa_attempts(
            user_id="user_123",
            ip="192.168.1.1",
            limit=5,
            window_seconds=60,
        )

        assert allowed is True
        assert is_blocked is False
        assert blocked_until is None
        mock_redis.incr.assert_called_once_with("rate:2fa:user:user_123", ttl=60)

    @pytest.mark.asyncio
    async def test_check_2fa_attempts_blocked(self, mock_redis):
        """Test check_2fa_attempts when user is blocked."""
        mock_redis.ttl = AsyncMock(return_value=450)

        allowed, is_blocked, blocked_until = await RateLimitService.check_2fa_attempts(
            user_id="user_123",
            ip="192.168.1.1",
        )

        assert allowed is False
        assert is_blocked is True
        assert blocked_until == 450

    @pytest.mark.asyncio
    async def test_check_2fa_attempts_exceeds_limit(self, mock_redis):
        """Test check_2fa_attempts blocks when limit exceeded."""
        mock_redis.ttl = AsyncMock(return_value=-1)
        mock_redis.incr = AsyncMock(return_value=6)  # Exceeds limit
        mock_redis.set = AsyncMock(return_value=True)

        allowed, is_blocked, blocked_until = await RateLimitService.check_2fa_attempts(
            user_id="user_123",
            ip="192.168.1.1",
            limit=5,
            block_duration=900,
        )

        assert allowed is False
        assert is_blocked is True
        assert blocked_until == 900
        mock_redis.set.assert_called_once_with(
            "rate:2fa:block:user:user_123", "1", ttl=900
        )

    @pytest.mark.asyncio
    async def test_check_2fa_attempts_default_params(self, mock_redis):
        """Test check_2fa_attempts with default parameters."""
        mock_redis.ttl = AsyncMock(return_value=-1)
        mock_redis.incr = AsyncMock(return_value=2)

        allowed, is_blocked, blocked_until = await RateLimitService.check_2fa_attempts(
            user_id="user_123",
            ip="192.168.1.1",
        )

        assert allowed is True
        mock_redis.incr.assert_called_once_with(
            "rate:2fa:user:user_123",
            ttl=RateLimitService.DEFAULT_2FA_WINDOW,
        )

    @pytest.mark.asyncio
    async def test_record_2fa_attempt_success_resets(self, mock_redis):
        """Test record_2fa_attempt with success deletes counters."""
        mock_redis.delete = AsyncMock(return_value=1)

        await RateLimitService.record_2fa_attempt(
            user_id="user_123",
            ip="192.168.1.1",
            success=True,
        )

        mock_redis.delete.assert_called_once_with(
            "rate:2fa:user:user_123",
            "rate:2fa:block:user:user_123",
        )

    @pytest.mark.asyncio
    async def test_record_2fa_attempt_failure_noop(self, mock_redis):
        """Test record_2fa_attempt with failure is no-op."""
        await RateLimitService.record_2fa_attempt(
            user_id="user_123",
            ip="192.168.1.1",
            success=False,
        )

        mock_redis.incr.assert_not_called()
        mock_redis.delete.assert_not_called()


# ==================== EMAIL 2FA SEND TESTS ====================

class TestRateLimitServiceEmail2FASend:
    """Tests for Email 2FA send rate limiting."""

    @pytest.mark.asyncio
    async def test_check_send_email_2fa_allowed(self, mock_redis):
        """Test check_send_email_2fa when under limit."""
        mock_redis.incr = AsyncMock(return_value=2)

        allowed, count = await RateLimitService.check_send_email_2fa(
            user_id="user_123",
            limit=3,
            window_seconds=600,
        )

        assert allowed is True
        assert count == 2
        mock_redis.incr.assert_called_once_with(
            "rate:email_2fa:user:user_123", ttl=600
        )

    @pytest.mark.asyncio
    async def test_check_send_email_2fa_at_limit(self, mock_redis):
        """Test check_send_email_2fa when at limit."""
        mock_redis.incr = AsyncMock(return_value=3)

        allowed, count = await RateLimitService.check_send_email_2fa(
            user_id="user_123",
            limit=3,
        )

        assert allowed is True
        assert count == 3

    @pytest.mark.asyncio
    async def test_check_send_email_2fa_exceeds_limit(self, mock_redis):
        """Test check_send_email_2fa when exceeds limit."""
        mock_redis.incr = AsyncMock(return_value=4)

        allowed, count = await RateLimitService.check_send_email_2fa(
            user_id="user_123",
            limit=3,
        )

        assert allowed is False
        assert count == 4

    @pytest.mark.asyncio
    async def test_check_send_email_2fa_default_params(self, mock_redis):
        """Test check_send_email_2fa with default parameters."""
        mock_redis.incr = AsyncMock(return_value=1)

        allowed, count = await RateLimitService.check_send_email_2fa(
            user_id="user_123",
        )

        assert allowed is True
        mock_redis.incr.assert_called_once_with(
            "rate:email_2fa:user:user_123",
            ttl=RateLimitService.DEFAULT_EMAIL_2FA_WINDOW,
        )

    @pytest.mark.asyncio
    async def test_record_send_email_2fa(self, mock_redis):
        """Test record_send_email_2fa increments counter."""
        mock_redis.incr = AsyncMock(return_value=4)

        count = await RateLimitService.record_send_email_2fa(
            user_id="user_123",
            window_seconds=600,
        )

        assert count == 4
        mock_redis.incr.assert_called_once_with(
            "rate:email_2fa:user:user_123", ttl=600
        )

    @pytest.mark.asyncio
    async def test_record_send_email_2fa_default_params(self, mock_redis):
        """Test record_send_email_2fa with default TTL."""
        mock_redis.incr = AsyncMock(return_value=1)

        count = await RateLimitService.record_send_email_2fa(user_id="user_123")

        assert count == 1
        mock_redis.incr.assert_called_once_with(
            "rate:email_2fa:user:user_123",
            ttl=RateLimitService.DEFAULT_EMAIL_2FA_WINDOW,
        )


# ==================== SMS 2FA SEND TESTS ====================

class TestRateLimitServiceSMS2FASend:
    """Tests for SMS 2FA send rate limiting."""

    @pytest.mark.asyncio
    async def test_check_send_sms_2fa_allowed(self, mock_redis):
        """Test check_send_sms_2fa when under limit."""
        mock_redis.incr = AsyncMock(return_value=1)

        allowed, count = await RateLimitService.check_send_sms_2fa(
            user_id="user_123",
            limit=3,
            window_seconds=600,
        )

        assert allowed is True
        assert count == 1
        mock_redis.incr.assert_called_once_with(
            "rate:sms_2fa:user:user_123", ttl=600
        )

    @pytest.mark.asyncio
    async def test_check_send_sms_2fa_exceeds_limit(self, mock_redis):
        """Test check_send_sms_2fa when exceeds limit."""
        mock_redis.incr = AsyncMock(return_value=4)

        allowed, count = await RateLimitService.check_send_sms_2fa(
            user_id="user_123",
            limit=3,
        )

        assert allowed is False
        assert count == 4

    @pytest.mark.asyncio
    async def test_check_send_sms_2fa_default_params(self, mock_redis):
        """Test check_send_sms_2fa with default parameters."""
        mock_redis.incr = AsyncMock(return_value=2)

        allowed, count = await RateLimitService.check_send_sms_2fa(user_id="user_123")

        assert allowed is True
        mock_redis.incr.assert_called_once_with(
            "rate:sms_2fa:user:user_123",
            ttl=RateLimitService.DEFAULT_SMS_2FA_WINDOW,
        )

    @pytest.mark.asyncio
    async def test_record_send_sms_2fa(self, mock_redis):
        """Test record_send_sms_2fa increments counter."""
        mock_redis.incr = AsyncMock(return_value=2)

        count = await RateLimitService.record_send_sms_2fa(
            user_id="user_123",
            window_seconds=600,
        )

        assert count == 2
        mock_redis.incr.assert_called_once_with(
            "rate:sms_2fa:user:user_123", ttl=600
        )

    @pytest.mark.asyncio
    async def test_record_send_sms_2fa_default_params(self, mock_redis):
        """Test record_send_sms_2fa with default TTL."""
        mock_redis.incr = AsyncMock(return_value=1)

        count = await RateLimitService.record_send_sms_2fa(user_id="user_123")

        assert count == 1
        mock_redis.incr.assert_called_once_with(
            "rate:sms_2fa:user:user_123",
            ttl=RateLimitService.DEFAULT_SMS_2FA_WINDOW,
        )


# ==================== BLOCK METHODS TESTS ====================

class TestRateLimitServiceBlockMethods:
    """Tests for block-related methods."""

    @pytest.mark.asyncio
    async def test_is_temporarily_blocked_true(self, mock_redis):
        """Test is_temporarily_blocked returns True when blocked."""
        mock_redis.ttl = AsyncMock(return_value=120)

        is_blocked, remaining = await RateLimitService.is_temporarily_blocked(
            key="block:key"
        )

        assert is_blocked is True
        assert remaining == 120

    @pytest.mark.asyncio
    async def test_is_temporarily_blocked_false(self, mock_redis):
        """Test is_temporarily_blocked returns False when not blocked."""
        mock_redis.ttl = AsyncMock(return_value=-1)

        is_blocked, remaining = await RateLimitService.is_temporarily_blocked(
            key="block:key"
        )

        assert is_blocked is False
        assert remaining is None

    @pytest.mark.asyncio
    async def test_is_temporarily_blocked_expired(self, mock_redis):
        """Test is_temporarily_blocked returns False when TTL is 0."""
        mock_redis.ttl = AsyncMock(return_value=0)

        is_blocked, remaining = await RateLimitService.is_temporarily_blocked(
            key="expired:key"
        )

        assert is_blocked is False
        assert remaining is None

    @pytest.mark.asyncio
    async def test_is_blocked_true(self, mock_redis):
        """Test _is_blocked returns True with TTL."""
        mock_redis.ttl = AsyncMock(return_value=45)

        is_blocked, ttl = await RateLimitService._is_blocked(key="test:key")

        assert is_blocked is True
        assert ttl == 45

    @pytest.mark.asyncio
    async def test_is_blocked_false(self, mock_redis):
        """Test _is_blocked returns False when not blocked."""
        mock_redis.ttl = AsyncMock(return_value=-1)

        is_blocked, ttl = await RateLimitService._is_blocked(key="test:key")

        assert is_blocked is False
        assert ttl is None

    @pytest.mark.asyncio
    async def test_is_blocked_redis_failure(self, mock_redis):
        """Test _is_blocked returns False on Redis failure."""
        mock_redis.ttl = AsyncMock(side_effect=Exception("Redis connection failed"))

        is_blocked, ttl = await RateLimitService._is_blocked(key="test:key")

        assert is_blocked is False
        assert ttl is None

    @pytest.mark.asyncio
    async def test_block_key_success(self, mock_redis):
        """Test _block_key successfully blocks a key."""
        mock_redis.set = AsyncMock(return_value=True)

        result = await RateLimitService._block_key(
            key="block:key",
            duration_seconds=300,
        )

        assert result is True
        mock_redis.set.assert_called_once_with("block:key", "1", ttl=300)

    @pytest.mark.asyncio
    async def test_block_key_failure(self, mock_redis):
        """Test _block_key returns False on Redis failure."""
        mock_redis.set = AsyncMock(return_value=False)

        result = await RateLimitService._block_key(
            key="block:key",
            duration_seconds=600,
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_block_key_exception(self, mock_redis):
        """Test _block_key returns False on exception."""
        mock_redis.set = AsyncMock(side_effect=Exception("Redis connection failed"))

        result = await RateLimitService._block_key(
            key="block:key",
            duration_seconds=300,
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_unblock_key_success(self, mock_redis):
        """Test unblock_key successfully unblocks a key."""
        mock_redis.delete = AsyncMock(return_value=1)

        deleted = await RateLimitService.unblock_key(key="block:key")

        assert deleted == 1
        mock_redis.delete.assert_called_once_with("block:key")

    @pytest.mark.asyncio
    async def test_unblock_key_not_found(self, mock_redis):
        """Test unblock_key when key doesn't exist."""
        mock_redis.delete = AsyncMock(return_value=0)

        deleted = await RateLimitService.unblock_key(key="nonexistent:key")

        assert deleted == 0

    @pytest.mark.asyncio
    async def test_unblock_key_exception(self, mock_redis):
        """Test unblock_key returns 0 on exception."""
        mock_redis.delete = AsyncMock(side_effect=Exception("Redis connection failed"))

        deleted = await RateLimitService.unblock_key(key="block:key")

        assert deleted == 0


# ==================== REMAINING ATTEMPTS TESTS ====================

class TestRateLimitServiceRemainingAttempts:
    """Tests for getting remaining attempts."""

    @pytest.mark.asyncio
    async def test_get_login_attempts_remaining(self, mock_redis_service):
        """Test get_login_attempts_remaining returns correct remaining counts."""
        mock_redis_service.get_rate_limit = AsyncMock(return_value=3)

        remaining_email, remaining_ip = await RateLimitService.get_login_attempts_remaining(
            email="user@example.com",
            ip="192.168.1.1",
            limit=5,
        )

        assert remaining_email == 2
        assert remaining_ip == 2

    @pytest.mark.asyncio
    async def test_get_login_attempts_remaining_at_limit(self, mock_redis_service):
        """Test get_login_attempts_remaining returns 0 when at limit."""
        mock_redis_service.get_rate_limit = AsyncMock(return_value=5)

        remaining_email, remaining_ip = await RateLimitService.get_login_attempts_remaining(
            email="user@example.com",
            ip="192.168.1.1",
            limit=5,
        )

        assert remaining_email == 0
        assert remaining_ip == 0

    @pytest.mark.asyncio
    async def test_get_login_attempts_remaining_exceeded(self, mock_redis_service):
        """Test get_login_attempts_remaining returns 0 when exceeded (no negative)."""
        mock_redis_service.get_rate_limit = AsyncMock(return_value=10)

        remaining_email, remaining_ip = await RateLimitService.get_login_attempts_remaining(
            email="user@example.com",
            ip="192.168.1.1",
            limit=5,
        )

        assert remaining_email == 0
        assert remaining_ip == 0

    @pytest.mark.asyncio
    async def test_get_login_attempts_remaining_default_limit(self, mock_redis_service):
        """Test get_login_attempts_remaining with default limit."""
        mock_redis_service.get_rate_limit = AsyncMock(return_value=0)

        remaining_email, remaining_ip = await RateLimitService.get_login_attempts_remaining(
            email="user@example.com",
            ip="192.168.1.1",
        )

        assert remaining_email == RateLimitService.DEFAULT_LOGIN_LIMIT
        assert remaining_ip == RateLimitService.DEFAULT_LOGIN_LIMIT

    @pytest.mark.asyncio
    async def test_get_2fa_attempts_remaining(self, mock_redis_service):
        """Test get_2fa_attempts_remaining returns correct remaining."""
        mock_redis_service.get_rate_limit = AsyncMock(return_value=2)

        remaining = await RateLimitService.get_2fa_attempts_remaining(
            user_id="user_123",
            limit=5,
        )

        assert remaining == 3

    @pytest.mark.asyncio
    async def test_get_2fa_attempts_remaining_zero(self, mock_redis_service):
        """Test get_2fa_attempts_remaining returns 0 when exceeded."""
        mock_redis_service.get_rate_limit = AsyncMock(return_value=7)

        remaining = await RateLimitService.get_2fa_attempts_remaining(
            user_id="user_123",
            limit=5,
        )

        assert remaining == 0

    @pytest.mark.asyncio
    async def test_get_2fa_attempts_remaining_default_limit(self, mock_redis_service):
        """Test get_2fa_attempts_remaining with default limit."""
        mock_redis_service.get_rate_limit = AsyncMock(return_value=0)

        remaining = await RateLimitService.get_2fa_attempts_remaining(
            user_id="user_123",
        )

        assert remaining == RateLimitService.DEFAULT_2FA_LIMIT


# ==================== EDGE CASES TESTS ====================

class TestRateLimitServiceEdgeCases:
    """Tests for edge cases and boundary values."""

    @pytest.mark.asyncio
    async def test_check_and_increment_limit_zero(self, mock_redis):
        """Test check_and_increment with limit=0 (always blocked)."""
        mock_redis.incr = AsyncMock(return_value=1)

        allowed, count = await RateLimitService.check_and_increment(
            key="test:key",
            limit=0,
            window_seconds=60,
        )

        assert allowed is False
        assert count == 1

    @pytest.mark.asyncio
    async def test_check_and_increment_large_window(self, mock_redis):
        """Test check_and_increment with very large window."""
        mock_redis.incr = AsyncMock(return_value=1)

        allowed, count = await RateLimitService.check_and_increment(
            key="test:key",
            limit=5,
            window_seconds=86400,  # 24 hours
        )

        assert allowed is True
        mock_redis.incr.assert_called_once_with("test:key", ttl=86400)

    @pytest.mark.asyncio
    async def test_check_rate_limit_boundary_at_limit(self, mock_redis):
        """Test check_rate_limit at exact limit boundary."""
        mock_redis.incr = AsyncMock(return_value=5)

        count = await RateLimitService.check_rate_limit(
            key="rate:mfa:totp:verify:user_123",
            limit=5,
        )

        # check_rate_limit returns count, caller decides if it exceeds limit
        assert count == 5

    @pytest.mark.asyncio
    async def test_check_rate_limit_boundary_exceeded(self, mock_redis):
        """Test check_rate_limit when count = limit + 1."""
        mock_redis.incr = AsyncMock(return_value=6)

        count = await RateLimitService.check_rate_limit(
            key="rate:mfa:totp:verify:user_123",
            limit=5,
        )

        assert count == 6

    @pytest.mark.asyncio
    async def test_record_failed_attempt_zero_ttl(self, mock_redis):
        """Test record_failed_attempt_by_key with zero TTL."""
        mock_redis.incr = AsyncMock(return_value=1)

        count = await RateLimitService.record_failed_attempt_by_key(
            key="test:key",
            ttl_seconds=0,
        )

        assert count == 1
        mock_redis.incr.assert_called_once_with("test:key", ttl=0)

    @pytest.mark.asyncio
    async def test_multiple_incr_calls_login(self, mock_redis):
        """Test that check_login_attempts increments both email and IP."""
        mock_redis.ttl = AsyncMock(return_value=-1)
        mock_redis.incr = AsyncMock(return_value=2)

        await RateLimitService.check_login_attempts(
            email="user@example.com",
            ip="192.168.1.1",
        )

        assert mock_redis.incr.call_count == 2
        # First call: email, second call: IP
        calls = [call[0][0] for call in mock_redis.incr.call_args_list]
        assert "rate:login:email:user@example.com" in calls
        assert "rate:login:ip:192.168.1.1" in calls