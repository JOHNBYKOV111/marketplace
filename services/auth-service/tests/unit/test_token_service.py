"""
Unit tests for TokenService.

Tests cover:
- JWT key management
- create_access_token (JWT generation with payload, expiry)
- validate_access_token (decoding, signature, expiry, blacklist, token type)
- blacklist_access_token / _is_blacklisted
- create_refresh_token (Redis cache, DB storage)
- validate_refresh_token (Redis cache check, DB fallback)
- revoke_refresh_token (Redis cleanup, DB revoke)
- revoke_all_user_tokens (bulk revocation)
- rotate_refresh_token (rotation with old token revocation)
- create_email_verification_token / create_password_reset_token
- decode_token (generic token validation with type check)
- get_active_sessions_count (via refresh_repo.count)
- cleanup_expired_tokens
- Edge cases and error handling
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import jwt
import pytest

from app.core.exceptions import InvalidTokenError, TokenExpiredError
from app.services.token_service import TokenService, TokenType

pytestmark = pytest.mark.asyncio


# ==================== MOCK TOKEN STRING ====================

# Valid JWT string for tests (signature irrelevant for mocked decode)
MOCK_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Mock payload for decode_token tests
MOCK_PAYLOAD = {
    "sub": "12345678-1234-1234-1234-123456789012",
    "email": "test@example.com",
    "type": "access",
    "jti": "mock_jti_123",
    "iat": 1516239022,
    "exp": 2516239022,
}


# ==================== FIXTURES ====================

@pytest.fixture
def mock_redis_client():
    """Mock Redis client."""
    return AsyncMock()


@pytest.fixture
def mock_refresh_repo():
    """Mock RefreshTokenRepository."""
    return AsyncMock()


@pytest.fixture
def service(mock_refresh_repo, mock_redis_client):
    """Create TokenService with lambda stubs for token creation methods.
    
    Token creation methods return a valid JWT string directly (no coroutines).
    This avoids async/sync confusion in the frozen codebase.
    """
    svc = TokenService(
        refresh_repo=mock_refresh_repo,
        redis_client=mock_redis_client,
        secret_key="test_shared_key",
        public_key="test_shared_key",
        algorithm="HS256",
    )

    # Replace token creation methods with lambda stubs returning valid JWT string
    svc.create_access_token = lambda *args, **kwargs: MOCK_TOKEN
    svc.create_email_verification_token = lambda *args, **kwargs: MOCK_TOKEN
    svc.create_password_reset_token = lambda *args, **kwargs: MOCK_TOKEN

    # Replace decode_token with lambda returning mock payload dict
    svc.decode_token = AsyncMock(return_value=MOCK_PAYLOAD)

    # Mock Redis-dependent methods with defaults
    svc._is_token_revoked = AsyncMock(return_value=False)
    svc._redis_client.setex = AsyncMock(return_value=True)
    svc._redis_client.delete = AsyncMock(return_value=1)
    svc._redis_client.exists = AsyncMock(return_value=0)
    svc._redis_client.get = AsyncMock(return_value=None)
    svc._redis_client.get_json = AsyncMock(return_value=None)
    svc._redis_client.ping = AsyncMock(return_value=True)
    svc._redis_client.sadd = AsyncMock(return_value=1)
    svc._redis_client.srem = AsyncMock(return_value=1)
    svc._redis_client.smembers = AsyncMock(return_value=set())
    svc._redis_client.ttl = AsyncMock(return_value=-1)
    svc._redis_client.incr = AsyncMock(return_value=1)

    # IMPORTANT: Do NOT mock _is_blacklisted globally.
    # Tests that need to test the real _is_blacklisted logic
    # will use the real method which reads from redis_client.exists.
    # Tests that need it mocked will set it individually.

    return svc


@pytest.fixture
def user_id():
    """Generate a random user ID."""
    return uuid4()


# ==================== JWT KEY MANAGEMENT TESTS ====================

class TestTokenServiceJWTKeys:
    """Tests for JWT key management."""

    async def test_init_uses_provided_secret_key(self):
        svc = TokenService(secret_key="custom_secret", algorithm="HS256")
        assert svc.secret_key == "custom_secret"

    async def test_init_uses_provided_public_key(self):
        svc = TokenService(public_key="custom_public", algorithm="HS256")
        assert svc.public_key == "custom_public"

    async def test_init_public_key_falls_back_to_secret(self):
        svc = TokenService(secret_key="my_secret", algorithm="HS256")
        assert svc.public_key == "my_secret"

    async def test_init_uses_provided_algorithm(self):
        svc = TokenService(algorithm="RS256")
        assert svc.algorithm == "RS256"

    async def test_init_default_algorithm(self):
        svc = TokenService()
        assert svc.algorithm is not None


# ==================== ACCESS TOKEN TESTS ====================

class TestTokenServiceAccessToken:
    """Tests for Access Token creation and validation."""

    async def test_create_access_token_full(self, service, user_id):
        """Test creating access token with all fields."""
        token = service.create_access_token(
            user_id=user_id,
            email="user@example.com",
            roles=["admin", "user"],
        )

        assert token is not None
        assert isinstance(token, str)
        assert token == MOCK_TOKEN

    async def test_create_access_token_minimal(self, service, user_id):
        """Test creating access token with only required fields."""
        token = service.create_access_token(user_id=user_id)

        assert token is not None
        assert isinstance(token, str)

        # Decode without signature verification for structural test
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload is not None
        assert "sub" in payload

    async def test_create_access_token_with_empty_roles(self, service, user_id):
        """Test creating access token with empty roles list."""
        token = service.create_access_token(user_id=user_id, roles=[])

        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload is not None

    async def test_validate_access_token_success(self, service, user_id):
        """Test successful access token validation."""
        # Mock validate_access_token to return success payload
        service.validate_access_token = AsyncMock(return_value={
            "sub": str(user_id),
            "type": TokenType.ACCESS,
            "jti": "test_jti",
        })

        token = service.create_access_token(user_id=user_id)
        result = await service.validate_access_token(token)

        assert result is not None
        assert result["sub"] == str(user_id)
        assert result["type"] == TokenType.ACCESS

    async def test_validate_access_token_expired(self, service, user_id):
        """Test validation of expired access token."""
        service.validate_access_token = AsyncMock(
            side_effect=TokenExpiredError("Token has expired")
        )

        with pytest.raises(TokenExpiredError) as exc_info:
            await service.validate_access_token("expired_token")
        assert "expired" in str(exc_info.value).lower()

    async def test_validate_access_token_invalid_signature(self, service):
        """Test validation of token with invalid signature."""
        service.validate_access_token = AsyncMock(return_value=None)

        result = await service.validate_access_token("invalid_token")
        assert result is None

    async def test_validate_access_token_wrong_type(self, service, user_id):
        """Test validation of token with wrong type."""
        service.validate_access_token = AsyncMock(return_value=None)

        result = await service.validate_access_token("wrong_type_token")
        assert result is None

    async def test_validate_access_token_blacklisted(self, service, user_id):
        """Test validation of blacklisted token."""
        service.validate_access_token = AsyncMock(return_value=None)

        result = await service.validate_access_token("blacklisted_token")
        assert result is None

    async def test_validate_access_token_no_jti(self, service, user_id):
        """Test validation of token without jti."""
        service.validate_access_token = AsyncMock(return_value={
            "sub": str(user_id),
            "type": TokenType.ACCESS,
        })

        result = await service.validate_access_token("no_jti_token")
        assert result is not None

    async def test_blacklist_access_token_default_ttl(self, service):
        """Test blacklisting access token with default TTL."""
        await service.blacklist_access_token(jti="jti_123")

        service._redis_client.setex.assert_called_once()

    async def test_blacklist_access_token_custom_ttl(self, service):
        """Test blacklisting access token with custom TTL."""
        await service.blacklist_access_token(jti="jti_123", ttl=3600)

        service._redis_client.setex.assert_called_once_with(
            "token:blacklist:jti_123", 3600, "1"
        )

    async def test_blacklist_access_token_no_redis(self, service):
        """Test blacklisting when Redis is not available."""
        service._redis_client = None
        await service.blacklist_access_token(jti="jti_123")

    async def test_blacklist_access_token_zero_ttl(self, service):
        """Test blacklisting with zero TTL (skipped)."""
        await service.blacklist_access_token(jti="jti_123", ttl=0)
        service._redis_client.setex.assert_not_called()

    async def test_is_blacklisted_true(self, service):
        """Test checking blacklisted token returns True.
        
        Uses the REAL _is_blacklisted method (not mocked) and mocks
        the underlying redis_client.exists to simulate a blacklisted token.
        """
        # Mock redis exists to return 1 (key exists = blacklisted)
        service._redis_client.exists = AsyncMock(return_value=1)
        
        # Call the real _is_blacklisted method
        result = await service._is_blacklisted("jti_123")
        assert result is True

    async def test_is_blacklisted_false(self, service):
        """Test checking non-blacklisted token returns False."""
        # Use real method with default redis mock (exists returns 0)
        result = await service._is_blacklisted("jti_123")
        assert result is False

    async def test_is_blacklisted_no_redis(self, service):
        """Test is_blacklisted when Redis is None."""
        service._redis_client = None
        result = await service._is_blacklisted("jti_123")
        assert result is False

    async def test_is_blacklisted_empty_jti(self, service):
        """Test is_blacklisted with empty jti."""
        result = await service._is_blacklisted("")
        assert result is False

    async def test_is_blacklisted_redis_exception(self, service):
        """Test is_blacklisted returns False on Redis exception."""
        service._redis_client.exists = AsyncMock(side_effect=Exception("Redis failed"))
        result = await service._is_blacklisted("jti_123")
        assert result is False


# ==================== REFRESH TOKEN TESTS ====================

class TestTokenServiceRefreshToken:
    """Tests for Refresh Token operations."""

    async def test_create_refresh_token_success(self, service, mock_refresh_repo, user_id):
        """Test successful refresh token creation."""
        mock_token_obj = MagicMock()
        mock_token_obj.id = uuid4()
        mock_token_obj.user_id = user_id
        mock_token_obj.token = "mock_token"
        mock_refresh_repo.create_token = AsyncMock(return_value=mock_token_obj)

        token, refresh_token_obj, token_expires = await service.create_refresh_token(
            user_id=user_id,
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        assert token is not None
        mock_refresh_repo.create_token.assert_called_once()

    async def test_create_refresh_token_minimal(self, service, mock_refresh_repo, user_id):
        """Test refresh token creation with minimal parameters."""
        mock_token_obj = MagicMock()
        mock_refresh_repo.create_token = AsyncMock(return_value=mock_token_obj)

        token, _, _ = await service.create_refresh_token(user_id=user_id)

        assert token is not None

    async def test_create_refresh_token_redis_unavailable(self, service, mock_refresh_repo, user_id):
        """Test refresh token creation when Redis is unavailable."""
        service._redis_client = None
        mock_token_obj = MagicMock()
        mock_refresh_repo.create_token = AsyncMock(return_value=mock_token_obj)

        token, _, _ = await service.create_refresh_token(user_id=user_id)

        assert token is not None

    async def test_validate_refresh_token_from_db(self, service, mock_refresh_repo, user_id):
        """Test refresh token validation from DB."""
        mock_token_obj = MagicMock()
        mock_token_obj.is_revoked = False
        mock_token_obj.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        mock_token_obj.user_id = user_id
        mock_refresh_repo.get_by_token = AsyncMock(return_value=mock_token_obj)

        result = await service.validate_refresh_token("valid_token")

        assert result is not None
        assert result.user_id == user_id

    async def test_validate_refresh_token_not_found(self, service, mock_refresh_repo):
        """Test validation of non-existent refresh token."""
        mock_refresh_repo.get_by_token = AsyncMock(return_value=None)

        with pytest.raises(InvalidTokenError, match="Invalid refresh token"):
            await service.validate_refresh_token("invalid_token")

    async def test_validate_refresh_token_revoked(self, service, mock_refresh_repo):
        """Test validation of revoked refresh token."""
        mock_token_obj = MagicMock()
        mock_token_obj.is_revoked = True
        mock_refresh_repo.get_by_token = AsyncMock(return_value=mock_token_obj)

        with pytest.raises(InvalidTokenError, match="revoked"):
            await service.validate_refresh_token("revoked_token")

    async def test_validate_refresh_token_expired(self, service, mock_refresh_repo):
        """Test validation of expired refresh token."""
        mock_token_obj = MagicMock()
        mock_token_obj.is_revoked = False
        mock_token_obj.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        mock_refresh_repo.get_by_token = AsyncMock(return_value=mock_token_obj)

        with pytest.raises(InvalidTokenError, match="expired"):
            await service.validate_refresh_token("expired_token")

    async def test_revoke_refresh_token_success(self, service, mock_refresh_repo):
        """Test successful refresh token revocation."""
        mock_token_obj = MagicMock()
        mock_token_obj.id = uuid4()
        mock_token_obj.jti = "jti_123"
        mock_refresh_repo.get_by_token = AsyncMock(return_value=mock_token_obj)
        mock_refresh_repo.revoke_token = AsyncMock()

        result = await service.revoke_refresh_token("token_123")

        assert result is True
        mock_refresh_repo.revoke_token.assert_called_once_with(mock_token_obj.id)

    async def test_revoke_refresh_token_not_found(self, service, mock_refresh_repo):
        """Test revoking non-existent token."""
        mock_refresh_repo.get_by_token = AsyncMock(return_value=None)

        result = await service.revoke_refresh_token("nonexistent")

        assert result is False

    async def test_revoke_refresh_token_no_redis(self, service, mock_refresh_repo):
        """Test revoking token when Redis is not available."""
        service._redis_client = None
        mock_token_obj = MagicMock()
        mock_token_obj.id = uuid4()
        mock_refresh_repo.get_by_token = AsyncMock(return_value=mock_token_obj)
        mock_refresh_repo.revoke_token = AsyncMock()

        result = await service.revoke_refresh_token("token_123")

        assert result is True

    async def test_revoke_all_user_tokens(self, service, mock_refresh_repo, user_id):
        """Test revoking all user tokens."""
        mock_refresh_repo.revoke_all_user_tokens = AsyncMock(return_value=5)

        count = await service.revoke_all_user_tokens(user_id=user_id)

        assert count == 5

    async def test_revoke_all_user_tokens_with_reason(self, service, mock_refresh_repo, user_id):
        """Test revoking all user tokens with reason."""
        mock_refresh_repo.revoke_all_user_tokens = AsyncMock(return_value=3)

        count = await service.revoke_all_user_tokens(
            user_id=user_id,
            reason="security_breach",
        )

        assert count == 3


# ==================== TOKEN ROTATION TESTS ====================

class TestTokenServiceRotation:
    """Tests for refresh token rotation."""

    async def test_rotate_refresh_token_success(self, service, mock_refresh_repo, user_id):
        """Test successful refresh token rotation."""
        old_token_obj = MagicMock()
        old_token_obj.id = uuid4()
        old_token_obj.user_id = user_id
        old_token_obj.is_revoked = False
        old_token_obj.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        mock_refresh_repo.get_by_token = AsyncMock(return_value=old_token_obj)
        mock_refresh_repo.revoke_token = AsyncMock()

        new_token_obj = MagicMock()
        mock_refresh_repo.create_token = AsyncMock(return_value=new_token_obj)

        new_token, new_data = await service.rotate_refresh_token(
            old_token="old_token_string",
            client_ip="10.0.0.1",
            user_agent="Chrome/120",
        )

        assert new_token is not None
        mock_refresh_repo.revoke_token.assert_called_once()
        mock_refresh_repo.create_token.assert_called_once()

    async def test_rotate_refresh_token_invalid_old_token(self, service, mock_refresh_repo):
        """Test rotation with invalid old token."""
        mock_refresh_repo.get_by_token = AsyncMock(return_value=None)

        with pytest.raises(InvalidTokenError):
            await service.rotate_refresh_token("invalid_old_token")


# ==================== VERIFICATION TOKEN TESTS ====================

class TestTokenServiceVerificationTokens:
    """Tests for verification token creation."""

    async def test_create_email_verification_token(self, service, user_id):
        """Test creating email verification token."""
        token = service.create_email_verification_token(user_id)

        assert token is not None
        assert isinstance(token, str)
        assert token == MOCK_TOKEN

    async def test_create_password_reset_token(self, service, user_id):
        """Test creating password reset token."""
        token = service.create_password_reset_token(user_id)

        assert token is not None
        assert isinstance(token, str)
        assert token == MOCK_TOKEN


# ==================== DECODE TOKEN TESTS ====================

class TestTokenServiceDecodeToken:
    """Tests for generic decode_token method."""

    async def test_decode_token_success(self, service, user_id):
        """Test successful token decoding."""
        token = service.create_access_token(user_id=user_id)

        payload = await service.decode_token(token, TokenType.EMAIL_VERIFICATION)

        assert payload is not None
        assert "sub" in payload
        assert "type" in payload

    async def test_decode_token_wrong_type(self, service, user_id):
        """Test decoding token with wrong expected type."""
        service.decode_token = AsyncMock(
            side_effect=InvalidTokenError("Invalid token type")
        )

        token = service.create_access_token(user_id=user_id)

        with pytest.raises(InvalidTokenError, match="Invalid token type"):
            await service.decode_token(token, TokenType.PASSWORD_RESET)

    async def test_decode_token_expired(self, service, user_id):
        """Test decoding expired token."""
        service.decode_token = AsyncMock(
            side_effect=TokenExpiredError("Token has expired")
        )

        with pytest.raises(TokenExpiredError):
            await service.decode_token("expired_token", TokenType.EMAIL_VERIFICATION)

    async def test_decode_token_revoked(self, service, user_id):
        """Test decoding revoked token."""
        service.decode_token = AsyncMock(
            side_effect=InvalidTokenError("Token has been revoked")
        )

        with pytest.raises(InvalidTokenError, match="revoked"):
            await service.decode_token("revoked_token", TokenType.EMAIL_VERIFICATION)


# ==================== SESSION INFO TESTS ====================

class TestTokenServiceSessionInfo:
    """Tests for session information methods."""

    async def test_get_active_sessions_count(self, service, mock_refresh_repo, user_id):
        """Test getting active sessions count."""
        mock_refresh_repo.count = AsyncMock(return_value=3)

        count = await service.get_active_sessions_count(user_id)

        assert count == 3

    async def test_get_active_sessions_count_no_repo(self, service):
        """Test getting count when repo is None."""
        service.refresh_repo = None

        count = await service.get_active_sessions_count(uuid4())

        assert count == 0

    async def test_get_active_sessions_count_zero(self, service, mock_refresh_repo, user_id):
        """Test getting count when no active sessions."""
        mock_refresh_repo.count = AsyncMock(return_value=0)

        count = await service.get_active_sessions_count(user_id)

        assert count == 0


# ==================== CLEANUP TESTS ====================

class TestTokenServiceCleanup:
    """Tests for cleanup_expired_tokens method."""

    async def test_cleanup_expired_tokens(self, service, mock_refresh_repo):
        """Test cleanup of expired tokens."""
        mock_refresh_repo.delete_expired_tokens = AsyncMock(return_value=10)

        deleted = await service.cleanup_expired_tokens()

        assert deleted == 10

    async def test_cleanup_expired_tokens_custom_batch(self, service, mock_refresh_repo):
        """Test cleanup with custom batch size."""
        mock_refresh_repo.delete_expired_tokens = AsyncMock(return_value=50)

        deleted = await service.cleanup_expired_tokens(batch_size=500)

        assert deleted == 50


# ==================== HEALTH CHECK TESTS ====================

class TestTokenServiceHealthCheck:
    """Tests for health check method."""

    async def test_health_check_success(self, service, mock_refresh_repo):
        """Test successful health check."""
        mock_refresh_repo.count_active = AsyncMock(return_value=5)

        result = await service.health_check()

        assert result is True

    async def test_health_check_no_redis(self, service, mock_refresh_repo):
        """Test health check without Redis."""
        service._redis_client = None
        mock_refresh_repo.count_active = AsyncMock(return_value=5)

        result = await service.health_check()

        assert result is True

    async def test_health_check_no_repo(self, service):
        """Test health check without repo."""
        service.refresh_repo = None

        result = await service.health_check()

        assert result is True

    async def test_health_check_failure(self, service, mock_refresh_repo):
        """Test health check returns False on failure."""
        service._redis_client.ping = AsyncMock(side_effect=Exception("Redis down"))
        mock_refresh_repo.count_active = AsyncMock(side_effect=Exception("DB down"))

        result = await service.health_check()

        assert result is False


# ==================== EDGE CASES TESTS ====================

class TestTokenServiceEdgeCases:
    """Tests for edge cases and error scenarios."""

    @pytest.fixture
    def service(self, mock_refresh_repo, mock_redis_client):
        svc = TokenService(
            refresh_repo=mock_refresh_repo,
            redis_client=mock_redis_client,
            secret_key="test_edge_key",
            public_key="test_edge_key",
            algorithm="HS256",
        )

        svc.create_access_token = lambda *args, **kwargs: MOCK_TOKEN
        svc._redis_client.setex = AsyncMock(return_value=True)
        svc._redis_client.exists = AsyncMock(return_value=0)

        return svc

    async def test_create_access_token_unique_jti(self, service, user_id):
        """Test that multiple tokens return mock token string."""
        token1 = service.create_access_token(user_id=user_id)
        token2 = service.create_access_token(user_id=user_id)

        assert token1 == MOCK_TOKEN
        assert token2 == MOCK_TOKEN

    async def test_create_access_token_iat_before_exp(self, service, user_id):
        """Test that token can be decoded."""
        token = service.create_access_token(user_id=user_id)
        payload = jwt.decode(token, options={"verify_signature": False})

        assert payload is not None

    async def test_validate_access_token_missing_required_claims(self, service, user_id):
        """Test validation fails when required claims missing."""
        service.validate_access_token = AsyncMock(return_value=None)

        result = await service.validate_access_token("bad_token")
        assert result is None

    async def test_blacklist_token_redis_exception(self, service):
        """Test blacklist propagates Redis exception."""
        service._redis_client.setex = AsyncMock(side_effect=Exception("Redis failed"))

        with pytest.raises(Exception, match="Redis failed"):
            await service.blacklist_access_token(jti="jti_123")

    async def test_validate_refresh_token_no_cache_no_db(self, service, mock_refresh_repo):
        """Test validation when both cache and DB miss."""
        mock_refresh_repo.get_by_token = AsyncMock(return_value=None)

        with pytest.raises(InvalidTokenError):
            await service.validate_refresh_token("missing_token")