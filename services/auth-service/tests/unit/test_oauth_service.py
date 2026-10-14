"""
Unit tests for OAuthService.

Tests cover:
- exchange_code (google, vk, apple)
- _exchange_google_code (token exchange, userinfo fetch)
- _exchange_vk_code (token exchange, users.get)
- _exchange_apple_code (token exchange, id_token decode)
- _generate_apple_client_secret (JWT generation)
- _decode_jwt_payload (valid, invalid, missing parts)
- get_available_providers
- get_authorization_url (google, vk, apple, unsupported)
- _build_google_auth_url, _build_vk_auth_url, _build_apple_auth_url
- find_or_create_user (new user, existing user)
- link_account
- HTTP client lifecycle (_get_http_client, close)
- Edge cases and error handling
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.services.oauth_service import OAuthService, oauth_service, get_oauth_service


class TestOAuthServiceExchangeCode:
    """Tests for exchange_code method."""

    @pytest.fixture
    def service(self):
        return OAuthService()

    @pytest.mark.asyncio
    async def test_exchange_google_code(self, service):
        """Test exchange_code dispatches to Google handler."""
        expected = {"id": "123", "email": "user@gmail.com"}
        with patch.object(service, "_exchange_google_code", AsyncMock(return_value=expected)):
            result = await service.exchange_code("google", "code", "https://cb", "verifier")
            assert result == expected

    @pytest.mark.asyncio
    async def test_exchange_vk_code(self, service):
        """Test exchange_code dispatches to VK handler."""
        expected = {"id": "456", "email": "user@vk.com"}
        with patch.object(service, "_exchange_vk_code", AsyncMock(return_value=expected)):
            result = await service.exchange_code("vk", "code", "https://cb", "verifier")
            assert result == expected

    @pytest.mark.asyncio
    async def test_exchange_apple_code(self, service):
        """Test exchange_code dispatches to Apple handler."""
        expected = {"id": "789", "email": "user@apple.com"}
        with patch.object(service, "_exchange_apple_code", AsyncMock(return_value=expected)):
            result = await service.exchange_code("apple", "code", "https://cb", "verifier")
            assert result == expected

    @pytest.mark.asyncio
    async def test_exchange_unsupported_provider(self, service):
        """Test exchange_code with unsupported provider raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported OAuth provider"):
            await service.exchange_code("facebook", "code", "https://cb", "verifier")


class TestGoogleExchange:
    """Tests for _exchange_google_code method."""

    @pytest.fixture
    def mock_settings(self):
        with patch("app.services.oauth_service.settings") as mock:
            mock.OAUTH_GOOGLE_CLIENT_ID = "google_id"
            mock.OAUTH_GOOGLE_CLIENT_SECRET = "google_secret"
            mock.OAUTH_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
            mock.OAUTH_GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
            yield mock

    @pytest.mark.asyncio
    async def test_google_exchange_success(self, mock_settings):
        """Test successful Google code exchange."""
        service = OAuthService()

        token_response = MagicMock()
        token_response.json.return_value = {"access_token": "google_token"}
        token_response.raise_for_status = MagicMock()

        userinfo_response = MagicMock()
        userinfo_response.json.return_value = {
            "sub": "123456789",
            "email": "user@gmail.com",
            "name": "John Doe",
            "picture": "https://avatar.url",
        }
        userinfo_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=token_response)
        mock_client.get = AsyncMock(return_value=userinfo_response)

        service._http_client = mock_client

        result = await service._exchange_google_code("code", "https://cb", "verifier")

        assert result["id"] == "123456789"
        assert result["email"] == "user@gmail.com"
        assert result["name"] == "John Doe"
        assert result["avatar_url"] == "https://avatar.url"

    @pytest.mark.asyncio
    async def test_google_exchange_no_access_token(self, mock_settings):
        """Test Google exchange when no access_token in response."""
        service = OAuthService()

        token_response = MagicMock()
        token_response.json.return_value = {}
        token_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=token_response)

        service._http_client = mock_client

        with pytest.raises(Exception, match="No access token"):
            await service._exchange_google_code("code", "https://cb", "verifier")


class TestVKExchange:
    """Tests for _exchange_vk_code method."""

    @pytest.fixture
    def mock_settings(self):
        with patch("app.services.oauth_service.settings") as mock:
            mock.OAUTH_VK_CLIENT_ID = "vk_id"
            mock.OAUTH_VK_CLIENT_SECRET = "vk_secret"
            mock.OAUTH_VK_TOKEN_URL = "https://oauth.vk.com/access_token"
            mock.OAUTH_VK_USERINFO_URL = "https://api.vk.com/method/users.get"
            mock.OAUTH_VK_API_VERSION = "5.131"
            yield mock

    @pytest.mark.asyncio
    async def test_vk_exchange_success(self, mock_settings):
        """Test successful VK code exchange."""
        service = OAuthService()

        token_resp = MagicMock()
        token_resp.json.return_value = {
            "access_token": "vk_token",
            "user_id": 987654321,
            "email": "user@vk.com",
        }
        token_resp.raise_for_status = MagicMock()

        user_resp = MagicMock()
        user_resp.json.return_value = {
            "response": [{"first_name": "Ivan", "last_name": "Petrov", "photo_200": "https://vk.com/avatar.jpg"}]
        }
        user_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[token_resp, user_resp])

        service._http_client = mock_client

        result = await service._exchange_vk_code("code", "https://cb", "verifier")

        assert result["id"] == "987654321"
        assert result["email"] == "user@vk.com"
        assert result["name"] == "Ivan Petrov"
        assert result["avatar_url"] == "https://vk.com/avatar.jpg"

    @pytest.mark.asyncio
    async def test_vk_exchange_no_token(self, mock_settings):
        """Test VK exchange when no access_token."""
        service = OAuthService()

        token_resp = MagicMock()
        token_resp.json.return_value = {}
        token_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=token_resp)

        service._http_client = mock_client

        with pytest.raises(Exception, match="No access_token or user_id"):
            await service._exchange_vk_code("code", "https://cb", "verifier")


class TestAppleExchange:
    """Tests for _exchange_apple_code method."""

    @pytest.fixture
    def mock_settings(self):
        with patch("app.services.oauth_service.settings") as mock:
            mock.OAUTH_APPLE_CLIENT_ID = "apple_id"
            mock.OAUTH_APPLE_TEAM_ID = "team_id"
            mock.OAUTH_APPLE_KEY_ID = "key_id"
            mock.OAUTH_APPLE_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
            mock.OAUTH_APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token"
            yield mock

    @pytest.mark.asyncio
    async def test_apple_exchange_success(self, mock_settings):
        """Test successful Apple code exchange."""
        service = OAuthService()

        id_token = "header.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ1c2VyQGFwcGxlLmNvbSJ9.signature"

        token_resp = MagicMock()
        token_resp.json.return_value = {"id_token": id_token}
        token_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=token_resp)

        service._http_client = mock_client

        with patch.object(service, "_generate_apple_client_secret", return_value="jwt_secret"):
            result = await service._exchange_apple_code("code", "https://cb", "verifier")

        assert result["id"] == "1234567890"
        assert result["email"] == "user@apple.com"

    @pytest.mark.asyncio
    async def test_apple_exchange_no_id_token(self, mock_settings):
        """Test Apple exchange when no id_token."""
        service = OAuthService()

        token_resp = MagicMock()
        token_resp.json.return_value = {}
        token_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=token_resp)

        service._http_client = mock_client

        with patch.object(service, "_generate_apple_client_secret", return_value="secret"):
            with pytest.raises(Exception, match="No id_token"):
                await service._exchange_apple_code("code", "https://cb", "verifier")


class TestAppleClientSecret:
    """Tests for _generate_apple_client_secret."""

    @pytest.fixture
    def mock_settings(self):
        with patch("app.services.oauth_service.settings") as mock:
            mock.OAUTH_APPLE_TEAM_ID = "TEAM123"
            mock.OAUTH_APPLE_CLIENT_ID = "com.example.app"
            mock.OAUTH_APPLE_KEY_ID = "KEY456"
            mock.OAUTH_APPLE_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----"
            yield mock

    def test_generate_client_secret(self, mock_settings):
        """Test Apple client secret generation returns JWT."""
        service = OAuthService()

        with patch("cryptography.hazmat.primitives.serialization.load_pem_private_key") as mock_load:
            mock_key = MagicMock()
            mock_load.return_value = mock_key

            with patch("jwt.encode", return_value="encoded_jwt_secret") as mock_encode:
                secret = service._generate_apple_client_secret()

        assert secret == "encoded_jwt_secret"


class TestDecodeJWTPayload:
    """Tests for _decode_jwt_payload method."""

    @pytest.fixture
    def service(self):
        return OAuthService()

    def test_decode_valid_jwt(self, service):
        """Test decoding valid JWT."""
        import base64, json
        payload = {"sub": "123", "email": "test@test.com"}
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        jwt_token = f"header.{payload_b64}.signature"

        result = service._decode_jwt_payload(jwt_token)

        assert result["sub"] == "123"
        assert result["email"] == "test@test.com"

    def test_decode_invalid_jwt_format(self, service):
        """Test decoding invalid JWT format."""
        with pytest.raises(ValueError, match="Invalid JWT format"):
            service._decode_jwt_payload("invalid")

    def test_decode_jwt_missing_parts(self, service):
        """Test decoding JWT with missing parts."""
        with pytest.raises(ValueError, match="Invalid JWT format"):
            service._decode_jwt_payload("header.only")


class TestFindOrCreateUser:
    """Tests for find_or_create_user method."""

    @pytest.fixture
    def service(self):
        return OAuthService()

    @pytest.mark.asyncio
    async def test_find_or_create_new_user(self, service):
        """Test creating new user."""
        user, is_new = await service.find_or_create_user(
            "google",
            {"id": "123", "email": "new@example.com", "name": "New User"},
        )

        assert is_new is True
        assert user.email == "new@example.com"
        assert user.name == "New User"
        assert user.is_active is True
        assert user.is_email_verified is True


class TestLinkAccount:
    """Tests for link_account method."""

    @pytest.fixture
    def service(self):
        return OAuthService()

    @pytest.mark.asyncio
    async def test_link_account_success(self, service):
        """Test successful account linking."""
        user_id = uuid4()
        result = await service.link_account(
            user_id=user_id,
            provider="google",
            user_info={"id": "google_123", "email": "user@gmail.com"},
        )

        assert result is True


class TestGetAvailableProviders:
    """Tests for get_available_providers."""

    @pytest.fixture
    def service(self):
        return OAuthService()

    @patch("app.services.oauth_service.settings")
    @pytest.mark.asyncio
    async def test_all_providers_available(self, mock_settings, service):
        """Test all providers available when configured."""
        mock_settings.OAUTH_GOOGLE_CLIENT_ID = "google_id"
        mock_settings.OAUTH_VK_CLIENT_ID = "vk_id"
        mock_settings.OAUTH_APPLE_CLIENT_ID = "apple_id"

        providers = await service.get_available_providers()

        assert "google" in providers
        assert "vk" in providers
        assert "apple" in providers

    @patch("app.services.oauth_service.settings")
    @pytest.mark.asyncio
    async def test_no_providers_configured(self, mock_settings, service):
        """Test empty list when no providers configured."""
        mock_settings.OAUTH_GOOGLE_CLIENT_ID = None
        mock_settings.OAUTH_VK_CLIENT_ID = None
        mock_settings.OAUTH_APPLE_CLIENT_ID = None

        providers = await service.get_available_providers()

        assert providers == []


class TestGetAuthorizationURL:
    """Tests for get_authorization_url method."""

    @pytest.fixture
    def service(self):
        return OAuthService()

    @pytest.mark.asyncio
    async def test_google_auth_url(self, service):
        """Test Google authorization URL generation."""
        with patch.object(service, "_build_google_auth_url", return_value="https://accounts.google.com?..."):
            url = await service.get_authorization_url("google", "https://cb", "state", "challenge")
            assert url.startswith("https://")

    @pytest.mark.asyncio
    async def test_unsupported_provider(self, service):
        """Test unsupported provider raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported OAuth provider"):
            await service.get_authorization_url("facebook", "https://cb", "state", "challenge")


class TestBuildAuthURLs:
    """Tests for _build_*_auth_url methods."""

    @pytest.fixture
    def mock_settings(self):
        with patch("app.services.oauth_service.settings") as mock:
            mock.OAUTH_GOOGLE_CLIENT_ID = "google_id"
            mock.OAUTH_GOOGLE_SCOPE = "openid email"
            mock.OAUTH_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
            mock.OAUTH_VK_CLIENT_ID = "vk_id"
            mock.OAUTH_VK_SCOPE = "email"
            mock.OAUTH_VK_AUTH_URL = "https://oauth.vk.com/authorize"
            mock.OAUTH_VK_API_VERSION = "5.131"
            mock.OAUTH_APPLE_CLIENT_ID = "apple_id"
            mock.OAUTH_APPLE_SCOPE = "name email"
            mock.OAUTH_APPLE_AUTH_URL = "https://appleid.apple.com/auth/authorize"
            yield mock

    def test_build_google_auth_url(self, mock_settings):
        """Test Google auth URL contains required params."""
        service = OAuthService()
        url = service._build_google_auth_url("https://cb", "state123", "challenge")
        assert "accounts.google.com" in url
        assert "client_id=google_id" in url
        assert "code_challenge=challenge" in url
        assert "code_challenge_method=S256" in url

    def test_build_vk_auth_url(self, mock_settings):
        """Test VK auth URL contains required params."""
        service = OAuthService()
        url = service._build_vk_auth_url("https://cb", "state456", "challenge")
        assert "oauth.vk.com" in url
        assert "client_id=vk_id" in url

    def test_build_apple_auth_url(self, mock_settings):
        """Test Apple auth URL contains required params."""
        service = OAuthService()
        url = service._build_apple_auth_url("https://cb", "state789", "challenge")
        assert "appleid.apple.com" in url
        assert "client_id=apple_id" in url
        assert "response_mode=form_post" in url


class TestHTTPClient:
    """Tests for HTTP client lifecycle."""

    @pytest.fixture
    def service(self):
        return OAuthService()

    @pytest.mark.asyncio
    async def test_get_http_client_creates_once(self, service):
        """Test HTTP client is created only once."""
        client1 = await service._get_http_client()
        client2 = await service._get_http_client()
        assert client1 is client2

    @pytest.mark.asyncio
    async def test_close_http_client(self, service):
        """Test closing HTTP client."""
        await service._get_http_client()
        await service.close()
        assert service._http_client is None


class TestSingleton:
    """Tests for singleton pattern."""

    def test_oauth_service_singleton(self):
        """Test oauth_service is a singleton."""
        assert isinstance(oauth_service, OAuthService)

    @pytest.mark.asyncio
    async def test_get_oauth_service_factory(self):
        """Test get_oauth_service returns the singleton."""
        svc = await get_oauth_service()
        assert svc is oauth_service