"""
Unit tests for OAuth Pydantic schemas.

Tests cover:
- OAuthProvider enum
- OAuthLoginRequest (redirect_uri validation, HTTPS required)
- OAuthCallbackRequest (code, state, error, error_description)
- OAuthCallbackResponse (success, access_token, is_new_user, is_linked)
- OAuthRedirectResponse
- OAuthLinkAccountResponse
- OAuthProvidersResponse
- OAuthStateData (provider, redirect_uri, code_verifier, is_linked, user_id)
- OAuthProviderConfig, OAuthProvidersConfigResponse
- OAuthUserInfo (provider, provider_user_id via alias "id")
- Error response schemas
- Field validators and edge cases
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.oauth import (
    OAuthCallbackRequest,
    OAuthCallbackResponse,
    OAuthErrorResponse,
    OAuthLinkAccountResponse,
    OAuthLoginRequest,
    OAuthProvider,
    OAuthProviderConfig,
    OAuthProvidersConfigResponse,
    OAuthProvidersResponse,
    OAuthRedirectResponse,
    OAuthStateData,
    OAuthStateNotFoundResponse,
    OAuthUserBlockedResponse,
    OAuthUserInfo,
    OAuthProviderMismatchResponse,
)


class TestOAuthProvider:
    """Tests for OAuthProvider enum."""

    def test_provider_values(self):
        """Test enum values."""
        assert OAuthProvider.GOOGLE.value == "google"
        assert OAuthProvider.VK.value == "vk"
        assert OAuthProvider.APPLE.value == "apple"

    def test_provider_from_string(self):
        """Test creating from string."""
        assert OAuthProvider("google") == OAuthProvider.GOOGLE
        assert OAuthProvider("vk") == OAuthProvider.VK
        assert OAuthProvider("apple") == OAuthProvider.APPLE

    def test_invalid_provider(self):
        """Test invalid provider raises error."""
        with pytest.raises(ValueError):
            OAuthProvider("facebook")


class TestOAuthLoginRequest:
    """Tests for OAuthLoginRequest schema."""

    def test_valid_https_redirect_uri(self):
        """Test valid HTTPS redirect_uri."""
        request = OAuthLoginRequest(
            redirect_uri="https://api.example.com/oauth/callback"
        )
        assert request.redirect_uri == "https://api.example.com/oauth/callback"

    def test_valid_localhost_redirect_uri(self):
        """Test valid localhost redirect_uri."""
        request = OAuthLoginRequest(redirect_uri="http://localhost:3000/callback")
        assert request.redirect_uri == "http://localhost:3000/callback"

    def test_valid_127001_redirect_uri(self):
        """Test valid 127.0.0.1 redirect_uri."""
        request = OAuthLoginRequest(redirect_uri="http://127.0.0.1:8000/callback")
        assert request.redirect_uri == "http://127.0.0.1:8000/callback"

    def test_invalid_http_redirect_uri(self):
        """Test non-HTTPS non-localhost URL raises error."""
        with pytest.raises(ValidationError) as exc_info:
            OAuthLoginRequest(redirect_uri="http://example.com/callback")
        assert "must use HTTPS or be localhost" in str(exc_info.value)

    def test_required_fields(self):
        """Test redirect_uri is required."""
        with pytest.raises(ValidationError) as exc_info:
            OAuthLoginRequest()
        assert "redirect_uri" in str(exc_info.value)

    def test_min_length(self):
        """Test redirect_uri must be at least 1 character."""
        with pytest.raises(ValidationError):
            OAuthLoginRequest(redirect_uri="")

    def test_max_length(self):
        """Test redirect_uri max 2048 characters."""
        long_url = "https://example.com/" + "a" * 2048
        with pytest.raises(ValidationError):
            OAuthLoginRequest(redirect_uri=long_url)


class TestOAuthCallbackRequest:
    """Tests for OAuthCallbackRequest schema."""

    def test_success_callback(self):
        """Test callback with authorization code."""
        request = OAuthCallbackRequest(
            code="4/0AY0e-g7abc",
            state="abc123xyz",
        )
        assert request.code == "4/0AY0e-g7abc"
        assert request.state == "abc123xyz"
        assert request.error is None

    def test_error_callback(self):
        """Test callback with error."""
        request = OAuthCallbackRequest(
            error="access_denied",
            error_description="User denied access",
            state="abc123xyz",
        )
        assert request.error == "access_denied"
        assert request.error_description == "User denied access"
        assert request.code is None

    def test_empty_callback(self):
        """Test callback with no parameters."""
        request = OAuthCallbackRequest()
        assert request.code is None
        assert request.state is None
        assert request.error is None
        assert request.error_description is None


class TestOAuthRedirectResponse:
    """Tests for OAuthRedirectResponse schema."""

    def test_valid_response(self):
        """Test valid redirect response."""
        response = OAuthRedirectResponse(
            redirect_url="https://accounts.google.com/o/oauth2/v2/auth?..."
        )
        assert response.redirect_url.startswith("https://")

    def test_required_fields(self):
        """Test redirect_url is required."""
        with pytest.raises(ValidationError):
            OAuthRedirectResponse()


class TestOAuthCallbackResponse:
    """Tests for OAuthCallbackResponse schema."""

    def test_login_success(self):
        """Test callback response for successful login."""
        response = OAuthCallbackResponse(
            success=True,
            access_token="eyJhbGciOiJSUzI1NiIs...",
            expires_in=900,
            is_new_user=False,
            message="Login successful",
        )
        assert response.success is True
        assert response.access_token == "eyJhbGciOiJSUzI1NiIs..."
        assert response.token_type == "bearer"
        assert response.expires_in == 900
        assert response.is_new_user is False
        assert response.is_linked is False

    def test_new_user(self):
        """Test callback response for new user."""
        response = OAuthCallbackResponse(
            success=True,
            access_token="new_user_token",
            is_new_user=True,
        )
        assert response.is_new_user is True

    def test_linked_account(self):
        """Test callback response for linked account."""
        response = OAuthCallbackResponse(
            success=True,
            is_linked=True,
            message="Account linked successfully",
        )
        assert response.is_linked is True
        assert response.access_token is None

    def test_defaults(self):
        """Test default values."""
        response = OAuthCallbackResponse(success=True)
        assert response.token_type == "bearer"
        assert response.expires_in == 3600
        assert response.is_new_user is False
        assert response.is_linked is False
        assert response.message == "OAuth authentication successful"

    def test_required_fields(self):
        """Test success is required."""
        with pytest.raises(ValidationError) as exc_info:
            OAuthCallbackResponse()
        assert "success" in str(exc_info.value)


class TestOAuthLinkAccountResponse:
    """Tests for OAuthLinkAccountResponse schema."""

    def test_valid_response(self):
        """Test valid link response."""
        response = OAuthLinkAccountResponse()
        assert response.success is True
        assert response.is_linked is True
        assert response.message == "OAuth account linked successfully"

    def test_custom_message(self):
        """Test custom message."""
        response = OAuthLinkAccountResponse(
            success=True,
            message="Google account linked",
        )
        assert response.message == "Google account linked"


class TestOAuthProvidersResponse:
    """Tests for OAuthProvidersResponse schema."""

    def test_valid_response(self):
        """Test valid providers response."""
        response = OAuthProvidersResponse(providers=["google", "vk", "apple"])
        assert response.providers == ["google", "vk", "apple"]

    def test_empty_providers(self):
        """Test empty providers list."""
        response = OAuthProvidersResponse(providers=[])
        assert response.providers == []

    def test_default_providers(self):
        """Test default empty list."""
        response = OAuthProvidersResponse()
        assert response.providers == []


class TestOAuthStateData:
    """Tests for OAuthStateData schema."""

    def test_valid_state_data(self):
        """Test valid OAuth state data."""
        state = OAuthStateData(
            provider="google",
            redirect_uri="https://example.com/callback",
            code_verifier="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            scope="openid email profile",
            created_at=1700000000.0,
        )
        assert state.provider == "google"
        assert state.redirect_uri == "https://example.com/callback"
        assert state.code_verifier == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        assert state.is_linked is False
        assert state.user_id is None

    def test_state_for_linking(self):
        """Test state data for account linking."""
        state = OAuthStateData(
            provider="vk",
            redirect_uri="https://example.com/callback",
            code_verifier="verifier123",
            is_linked=True,
            user_id="550e8400-e29b-41d4-a716-446655440000",
        )
        assert state.is_linked is True
        assert state.user_id == "550e8400-e29b-41d4-a716-446655440000"

    def test_required_fields(self):
        """Test required fields."""
        with pytest.raises(ValidationError) as exc_info:
            OAuthStateData()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"provider", "redirect_uri", "code_verifier"}
        assert required_fields.issubset(errors)


class TestOAuthProviderConfig:
    """Tests for OAuthProviderConfig schema."""

    def test_valid_config(self):
        """Test valid provider config."""
        config = OAuthProviderConfig(
            provider=OAuthProvider.GOOGLE,
            client_id="google_client_id",
            auth_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
            scope="openid email profile",
            is_configured=True,
        )
        assert config.provider == OAuthProvider.GOOGLE
        assert config.is_configured is True

    def test_not_configured(self):
        """Test provider without client_id."""
        config = OAuthProviderConfig(
            provider=OAuthProvider.APPLE,
            auth_url="https://appleid.apple.com/auth/authorize",
            token_url="https://appleid.apple.com/auth/token",
            userinfo_url="https://appleid.apple.com/auth/userinfo",
        )
        assert config.is_configured is False
        assert config.client_id is None

    def test_required_fields(self):
        """Test required fields."""
        with pytest.raises(ValidationError) as exc_info:
            OAuthProviderConfig()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"provider", "auth_url", "token_url", "userinfo_url"}
        assert required_fields.issubset(errors)


class TestOAuthProvidersConfigResponse:
    """Tests for OAuthProvidersConfigResponse schema."""

    def test_valid_response(self):
        """Test valid config response."""
        config = OAuthProviderConfig(
            provider=OAuthProvider.GOOGLE,
            auth_url="https://auth.url",
            token_url="https://token.url",
            userinfo_url="https://userinfo.url",
        )
        response = OAuthProvidersConfigResponse(providers={"google": config})
        assert "google" in response.providers

    def test_empty_providers(self):
        """Test empty providers dict."""
        response = OAuthProvidersConfigResponse()
        assert response.providers == {}


class TestOAuthUserInfo:
    """Tests for OAuthUserInfo schema."""

    def test_valid_user_info(self):
        """Test valid user info with alias 'id'."""
        user_info = OAuthUserInfo(
            provider=OAuthProvider.GOOGLE,
            id="123456789",
            email="user@gmail.com",
            name="John Doe",
            avatar_url="https://avatars.google.com/123",
        )
        assert user_info.provider == OAuthProvider.GOOGLE
        assert user_info.provider_user_id == "123456789"
        assert user_info.email == "user@gmail.com"
        assert user_info.name == "John Doe"

    def test_minimal_user_info(self):
        """Test user info with only required fields."""
        user_info = OAuthUserInfo(
            provider=OAuthProvider.VK,
            id="987654321",
        )
        assert user_info.email is None
        assert user_info.name is None
        assert user_info.avatar_url is None

    def test_raw_data(self):
        """Test raw_data field."""
        raw = {"sub": "123", "given_name": "John"}
        user_info = OAuthUserInfo(
            provider=OAuthProvider.GOOGLE,
            id="123",
            raw_data=raw,
        )
        assert user_info.raw_data == raw

    def test_required_fields(self):
        """Test required fields."""
        with pytest.raises(ValidationError) as exc_info:
            OAuthUserInfo()
        errors = {err["loc"][0] for err in exc_info.value.errors()}
        required_fields = {"provider", "id"}
        assert required_fields.issubset(errors)


class TestErrorResponses:
    """Tests for error response schemas."""

    def test_oauth_error_response(self):
        """Test OAuthErrorResponse."""
        response = OAuthErrorResponse(detail="Something went wrong")
        assert response.detail == "Something went wrong"
        assert response.error_code is None
        assert response.provider is None

    def test_oauth_error_with_provider(self):
        """Test error response with provider."""
        response = OAuthErrorResponse(
            detail="Access denied",
            error_code="ACCESS_DENIED",
            provider="google",
        )
        assert response.provider == "google"

    def test_state_not_found_response(self):
        """Test OAuthStateNotFoundResponse defaults."""
        response = OAuthStateNotFoundResponse()
        assert "Invalid or expired" in response.detail

    def test_provider_mismatch_response(self):
        """Test OAuthProviderMismatchResponse defaults."""
        response = OAuthProviderMismatchResponse()
        assert "Provider mismatch" in response.detail

    def test_user_blocked_response(self):
        """Test OAuthUserBlockedResponse defaults."""
        response = OAuthUserBlockedResponse()
        assert response.detail == "User account is blocked"


class TestEdgeCases:
    """Tests for edge cases."""

    def test_callback_request_with_empty_strings(self):
        """Test callback with empty strings."""
        request = OAuthCallbackRequest(code="", state="")
        assert request.code == ""
        assert request.state == ""

    def test_state_data_without_optional_fields(self):
        """Test state data with only required fields."""
        state = OAuthStateData(
            provider="google",
            redirect_uri="https://example.com/callback",
            code_verifier="verifier",
        )
        assert state.scope is None
        assert state.is_linked is False
        assert state.user_id is None
        assert state.created_at is None

    def test_user_info_with_alias_id(self):
        """Test user info accepts 'id' field via alias."""
        user_info = OAuthUserInfo(provider="google", id="test_id_123")
        assert user_info.provider_user_id == "test_id_123"

    def test_callback_response_without_access_token(self):
        """Test callback response without access token (linking)."""
        response = OAuthCallbackResponse(success=True, is_linked=True)
        assert response.access_token is None
        assert response.is_linked is True