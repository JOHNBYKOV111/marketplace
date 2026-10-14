"""
Unit tests for AuthService.

Tests cover:
- authenticate method (success, MFA required, invalid credentials, blocked user)
- refresh_tokens method (success, expired, revoked, user not active)
- revoke_refresh_token method
- revoke_all_user_tokens method
- Token creation methods
- AuthResult and RefreshResult classes
- Edge cases and error handling
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    AuthenticationError,
    InvalidTokenError,
    MFARequiredError,
    UserBlockedException,
)
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_security_settings import UserSecuritySettings
from app.services.auth_service import AuthResult, AuthService, RefreshResult


@pytest.fixture(autouse=True)
def cleanup_mocks_after_each_test():
    """Каноничный способ pytest для полной очистки глобальных моков."""
    yield
    patch.stopall()


class TestAuthServiceAuthenticate:
    """Tests for authenticate method."""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock(spec=AsyncSession)

    @pytest.fixture
    def mock_user(self):
        user = MagicMock(spec=User)
        user.id = uuid4()
        user.is_active = True
        user.password_hash = "hashed_password"
        return user

    @pytest.fixture
    def mock_security_settings(self):
        settings = MagicMock(spec=UserSecuritySettings)
        settings.totp_enabled = False
        return settings

    @pytest.fixture
    def auth_service(self, mock_db):
        return AuthService(session=mock_db)

    async def test_authenticate_success_no_mfa(
        self, auth_service, mock_user, mock_security_settings
    ):
        """Test successful authentication without MFA."""
        with patch.object(User, "create_email_hash", return_value="hashed_email"):
            with patch("app.services.auth_service.verify_password", return_value=True):
                with patch.object(auth_service, "_create_access_token", return_value=("access_token", timedelta(minutes=15))):
                    with patch.object(auth_service, "_create_refresh_token", return_value=("refresh_token", timedelta(days=7))):
                        auth_service.user_repo.get_by_email_hash = AsyncMock(return_value=mock_user)
                        auth_service.settings_repo.get_by_user_id = AsyncMock(return_value=mock_security_settings)
                        auth_service.user_repo.update_last_login = AsyncMock()

                        result = await auth_service.authenticate(
                            email="user@example.com",
                            password="password123",
                            client_ip="192.168.1.1",
                            user_agent="Mozilla/5.0",
                        )

                        assert isinstance(result, AuthResult)
                        assert result.user == mock_user
                        assert result.access_token == "access_token"
                        assert result.refresh_token == "refresh_token"
                        auth_service.user_repo.update_last_login.assert_called_once_with(mock_user.id)

    async def test_authenticate_mfa_required(self, auth_service, mock_user, mock_security_settings):
        """Test authentication when MFA is required but no TOTP code provided."""
        mock_security_settings.totp_enabled = True

        with patch.object(User, "create_email_hash", return_value="hashed_email"):
            with patch("app.services.auth_service.verify_password", return_value=True):
                auth_service.user_repo.get_by_email_hash = AsyncMock(return_value=mock_user)
                auth_service.settings_repo.get_by_user_id = AsyncMock(return_value=mock_security_settings)

                with pytest.raises(MFARequiredError):
                    await auth_service.authenticate(
                        email="user@example.com",
                        password="password123",
                    )

    async def test_authenticate_mfa_success(self, auth_service, mock_user, mock_security_settings):
        """Test authentication with valid TOTP code."""
        mock_security_settings.totp_enabled = True
        mock_security_settings.totp_secret = "JBSWY3DPEHPK3PXP"

        with patch.object(User, "create_email_hash", return_value="hashed_email"):
            with patch("app.services.auth_service.verify_password", return_value=True):
                with patch.object(auth_service.totp_service, "verify", return_value=True):
                    with patch.object(auth_service, "_create_access_token", return_value=("access_token", timedelta(minutes=15))):
                        with patch.object(auth_service, "_create_refresh_token", return_value=("refresh_token", timedelta(days=7))):
                            auth_service.user_repo.get_by_email_hash = AsyncMock(return_value=mock_user)
                            auth_service.settings_repo.get_by_user_id = AsyncMock(return_value=mock_security_settings)
                            auth_service.user_repo.update_last_login = AsyncMock()

                            result = await auth_service.authenticate(
                                email="user@example.com",
                                password="password123",
                                totp_code="123456",
                            )

                            assert isinstance(result, AuthResult)
                            assert result.user == mock_user
                            auth_service.totp_service.verify.assert_called_once_with(
                                "JBSWY3DPEHPK3PXP", "123456"
                            )

    async def test_authenticate_user_not_found(self, auth_service):
        """Test authentication with non-existent user."""
        with patch.object(User, "create_email_hash", return_value="hashed_email"):
            auth_service.user_repo.get_by_email_hash = AsyncMock(return_value=None)

            with pytest.raises(AuthenticationError):
                await auth_service.authenticate(
                    email="nonexistent@example.com",
                    password="password123",
                )

    async def test_authenticate_user_blocked(self, auth_service, mock_user):
        """Test authentication with blocked user."""
        mock_user.is_active = False

        with patch.object(User, "create_email_hash", return_value="hashed_email"):
            auth_service.user_repo.get_by_email_hash = AsyncMock(return_value=mock_user)

            with pytest.raises(UserBlockedException):
                await auth_service.authenticate(
                    email="user@example.com",
                    password="password123",
                )

    async def test_authenticate_invalid_password(self, auth_service, mock_user):
        """Test authentication with invalid password."""
        with patch.object(User, "create_email_hash", return_value="hashed_email"):
            with patch("app.services.auth_service.verify_password", return_value=False):
                auth_service.user_repo.get_by_email_hash = AsyncMock(return_value=mock_user)

                with pytest.raises(AuthenticationError):
                    await auth_service.authenticate(
                        email="user@example.com",
                        password="wrong_password",
                    )

    async def test_authenticate_invalid_mfa_code(self, auth_service, mock_user, mock_security_settings):
        """Test authentication with invalid MFA code."""
        mock_security_settings.totp_enabled = True
        mock_security_settings.totp_secret = "JBSWY3DPEHPK3PXP"

        with patch.object(User, "create_email_hash", return_value="hashed_email"):
            with patch("app.services.auth_service.verify_password", return_value=True):
                with patch.object(auth_service.totp_service, "verify", return_value=False):
                    auth_service.user_repo.get_by_email_hash = AsyncMock(return_value=mock_user)
                    auth_service.settings_repo.get_by_user_id = AsyncMock(return_value=mock_security_settings)

                    with pytest.raises(AuthenticationError):
                        await auth_service.authenticate(
                            email="user@example.com",
                            password="password123",
                            totp_code="000000",
                        )


class TestAuthServiceRefreshTokens:
    """Tests for refresh_tokens method."""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock(spec=AsyncSession)

    @pytest.fixture
    def auth_service(self, mock_db):
        return AuthService(session=mock_db)

    @pytest.fixture
    def mock_token_data(self):
        token = MagicMock(spec=RefreshToken)
        token.token_id = "token_123"
        token.user_id = uuid4()
        token.is_revoked = False
        token.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        token.user_agent = "Mozilla/5.0"
        return token

    async def test_refresh_tokens_success(self, auth_service, mock_token_data):
        """Test successful token refresh."""
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_token_data.user_id
        mock_user.is_active = True

        auth_service.refresh_repo.get_by_token_id = AsyncMock(return_value=mock_token_data)
        auth_service.refresh_repo.revoke = AsyncMock()
        auth_service.user_repo.get_by_id = AsyncMock(return_value=mock_user)

        with patch.object(auth_service, "_create_access_token", return_value=("new_access", timedelta(minutes=15))):
            with patch.object(auth_service, "_create_refresh_token", return_value=("new_refresh", timedelta(days=7))):
                result = await auth_service.refresh_tokens(
                    refresh_token="old_refresh_token",
                    client_ip="192.168.1.1",
                )

                assert isinstance(result, RefreshResult)
                assert result.access_token == "new_access"
                assert result.refresh_token == "new_refresh"
                assert result.user_id == mock_token_data.user_id
                auth_service.refresh_repo.revoke.assert_called_once_with("token_123")

    async def test_refresh_tokens_not_found(self, auth_service):
        """Test refresh with non-existent token."""
        auth_service.refresh_repo.get_by_token_id = AsyncMock(return_value=None)

        with pytest.raises(InvalidTokenError):
            await auth_service.refresh_tokens(refresh_token="invalid_token")

    async def test_refresh_tokens_expired(self, auth_service, mock_token_data):
        """Test refresh with expired token."""
        mock_token_data.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        auth_service.refresh_repo.get_by_token_id = AsyncMock(return_value=mock_token_data)
        auth_service.refresh_repo.revoke = AsyncMock()

        with pytest.raises(InvalidTokenError):
            await auth_service.refresh_tokens(refresh_token="expired_token")

        auth_service.refresh_repo.revoke.assert_called_once_with("token_123")

    async def test_refresh_tokens_revoked(self, auth_service, mock_token_data):
        """Test refresh with revoked token."""
        mock_token_data.is_revoked = True
        auth_service.refresh_repo.get_by_token_id = AsyncMock(return_value=mock_token_data)

        with pytest.raises(InvalidTokenError):
            await auth_service.refresh_tokens(refresh_token="revoked_token")

    async def test_refresh_tokens_user_not_active(self, auth_service, mock_token_data):
        """Test refresh when user is not active."""
        auth_service.refresh_repo.get_by_token_id = AsyncMock(return_value=mock_token_data)
        auth_service.user_repo.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(InvalidTokenError):
            await auth_service.refresh_tokens(refresh_token="valid_token")


class TestAuthServiceRevokeTokens:
    """Tests for token revocation methods."""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock(spec=AsyncSession)

    @pytest.fixture
    def auth_service(self, mock_db):
        return AuthService(session=mock_db)

    async def test_revoke_refresh_token_success(self, auth_service):
        """Test successful token revocation."""
        mock_token = MagicMock(spec=RefreshToken)
        mock_token.token_id = "token_123"

        auth_service.refresh_repo.get_by_token_id = AsyncMock(return_value=mock_token)
        auth_service.refresh_repo.revoke = AsyncMock()

        result = await auth_service.revoke_refresh_token(token="refresh_token_123")

        assert result is True
        auth_service.refresh_repo.revoke.assert_called_once_with("token_123")

    async def test_revoke_refresh_token_not_found(self, auth_service):
        """Test revocation of non-existent token."""
        auth_service.refresh_repo.get_by_token_id = AsyncMock(return_value=None)

        result = await auth_service.revoke_refresh_token(token="invalid_token")

        assert result is False

    async def test_revoke_all_user_tokens(self, auth_service):
        """Test revoking all tokens for a user."""
        user_id = uuid4()
        auth_service.refresh_repo.revoke_all_user_tokens = AsyncMock(return_value=5)

        count = await auth_service.revoke_all_user_tokens(user_id=user_id)

        assert count == 5
        auth_service.refresh_repo.revoke_all_user_tokens.assert_called_once_with(user_id)


class TestAuthServiceCreateTokens:
    """Tests for token creation methods."""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock(spec=AsyncSession)

    @pytest.fixture
    def auth_service(self, mock_db):
        return AuthService(session=mock_db)

    def test_create_access_token(self, auth_service):
        """Test access token creation returns token and expiry."""
        user_id = uuid4()

        import app.services.auth_service as auth_service_mod

        with patch.object(auth_service_mod, "settings") as mock_settings:
            mock_settings.access_token_expire_minutes = 15
            mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 15

            with patch("app.services.auth_service.create_access_token", return_value="access_token_123"):
                token, expires = auth_service._create_access_token(user_id)

                assert token == "access_token_123"
                assert isinstance(expires, timedelta)
                assert expires.total_seconds() > 0

    async def test_create_refresh_token(self, auth_service):
        """Test refresh token creation returns token and expiry."""
        user_id = uuid4()

        import app.services.auth_service as auth_service_mod

        with patch.object(auth_service_mod, "settings") as mock_settings:
            mock_settings.refresh_token_expire_days = 7
            mock_settings.REFRESH_TOKEN_EXPIRE_DAYS = 7

            with patch("app.services.auth_service.create_refresh_token", return_value="refresh_token_123"):
                auth_service.refresh_repo.create = AsyncMock()

                token, expires = await auth_service._create_refresh_token(
                    user_id=user_id,
                    client_ip="192.168.1.1",
                    user_agent="Mozilla/5.0",
                )

                assert token == "refresh_token_123"
                assert isinstance(expires, timedelta)
                assert expires.total_seconds() > 0
                auth_service.refresh_repo.create.assert_called_once()


class TestAuthResult:
    """Tests for AuthResult class."""

    def test_auth_result_creation(self):
        """Test creating AuthResult instance."""
        user = MagicMock(spec=User)
        user.id = uuid4()

        result = AuthResult(
            user=user,
            access_token="access_123",
            refresh_token="refresh_123",
            access_expires_in=900,
            refresh_expires_in=604800,
        )

        assert result.user == user
        assert result.access_token == "access_123"
        assert result.refresh_token == "refresh_123"
        assert result.access_expires_in == 900
        assert result.refresh_expires_in == 604800


class TestRefreshResult:
    """Tests for RefreshResult class."""

    def test_refresh_result_creation(self):
        """Test creating RefreshResult instance."""
        user_id = uuid4()

        result = RefreshResult(
            access_token="new_access",
            refresh_token="new_refresh",
            user_id=user_id,
            access_expires_in=900,
            refresh_expires_in=604800,
        )

        assert result.access_token == "new_access"
        assert result.refresh_token == "new_refresh"
        assert result.user_id == user_id
        assert result.access_expires_in == 900
        assert result.refresh_expires_in == 604800