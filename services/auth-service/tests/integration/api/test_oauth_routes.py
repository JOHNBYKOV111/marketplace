"""
Интеграционные тесты для OAuth роутера с реальной логикой.

Реальная логика: Redis (state), PKCE, БД (find_or_create_user).
Моки: exchange_code (внешний API Google), create_tokens (JWT).
"""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import status
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.routers.oauth import get_oauth_service, get_auth_service_for_oauth


@pytest_asyncio.fixture
async def oauth_client(db_session, oauth_service):
    """Клиент для OAuth тестов с реальной БД и Redis."""
    mock_auth = MagicMock()
    mock_auth.create_tokens = AsyncMock(return_value=("access_token", "refresh_token"))

    app.dependency_overrides[get_oauth_service] = lambda: oauth_service
    app.dependency_overrides[get_auth_service_for_oauth] = lambda: mock_auth

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        yield client

    for dep in [get_oauth_service, get_auth_service_for_oauth]:
        app.dependency_overrides.pop(dep, None)


class TestOAuthProvidersEndpoint:

    @pytest.mark.asyncio
    async def test_get_providers_all_configured(self, oauth_client, monkeypatch):
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_GOOGLE_CLIENT_ID", "google_id")
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_VK_CLIENT_ID", "vk_id")
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_APPLE_CLIENT_ID", "apple_id")
        response = await oauth_client.get("/oauth/providers")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "google" in data
        assert "vk" in data
        assert "apple" in data

    @pytest.mark.asyncio
    async def test_get_providers_only_google(self, oauth_client, monkeypatch):
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_GOOGLE_CLIENT_ID", "google_id")
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_VK_CLIENT_ID", None)
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_APPLE_CLIENT_ID", None)
        response = await oauth_client.get("/oauth/providers")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == ["google"]


class TestOAuthLoginRedirects:

    @pytest.mark.asyncio
    async def test_google_login_redirect(self, oauth_client, monkeypatch):
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_GOOGLE_CLIENT_ID", "test_google_id")
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_GOOGLE_AUTH_URL", "https://accounts.google.com/o/oauth2/v2/auth")
        response = await oauth_client.get("/oauth/google/login?redirect_uri=https://example.com/callback")
        assert response.status_code == status.HTTP_302_FOUND
        assert "accounts.google.com" in response.headers["location"]

    @pytest.mark.asyncio
    async def test_vk_login_redirect(self, oauth_client, monkeypatch):
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_VK_CLIENT_ID", "test_vk_id")
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_VK_AUTH_URL", "https://oauth.vk.com/authorize")
        response = await oauth_client.get("/oauth/vk/login?redirect_uri=https://example.com/callback")
        assert response.status_code == status.HTTP_302_FOUND
        assert "oauth.vk.com" in response.headers["location"]

    @pytest.mark.asyncio
    async def test_apple_login_redirect(self, oauth_client, monkeypatch):
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_APPLE_CLIENT_ID", "test_apple_id")
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_APPLE_AUTH_URL", "https://appleid.apple.com/auth/authorize")
        response = await oauth_client.get("/oauth/apple/login?redirect_uri=https://example.com/callback")
        assert response.status_code == status.HTTP_302_FOUND
        assert "appleid.apple.com" in response.headers["location"]


class TestOAuthCallback:

    @pytest.mark.asyncio
    async def test_google_callback_success_login(self, oauth_client, oauth_service):
        from app.routers.oauth import create_oauth_state
        state, verifier = await create_oauth_state("google", "https://example.com/callback")

        oauth_service.exchange_code = AsyncMock(return_value={
            "id": "google_123", "email": "oauth_test@example.com", "name": "Test User"
        })

        response = await oauth_client.get(f"/oauth/google/callback?code=test_code&state={state}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["access_token"] == "access_token"
        assert "refresh_token" in response.cookies

    @pytest.mark.asyncio
    async def test_google_callback_new_user(self, oauth_client, oauth_service):
        from app.routers.oauth import create_oauth_state
        state, _ = await create_oauth_state("google", "https://example.com/callback")

        oauth_service.exchange_code = AsyncMock(return_value={
            "id": "google_new", "email": "new_oauth@example.com", "name": "New User"
        })

        response = await oauth_client.get(f"/oauth/google/callback?code=test_code&state={state}")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["is_new_user"] is True

    @pytest.mark.asyncio
    async def test_google_callback_invalid_state(self, oauth_client):
        response = await oauth_client.get("/oauth/google/callback?code=test&state=invalid")
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_google_callback_with_error(self, oauth_client):
        response = await oauth_client.get("/oauth/google/callback?error=access_denied&state=test")
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_callback_user_blocked(self, oauth_client, oauth_service, db_session):
        from app.models.user import User
        from app.routers.oauth import create_oauth_state

        email = "blocked_oauth@example.com"
        email_hash = User.create_email_hash(email)
        user = User(id=uuid4(), email=email, email_hash=email_hash, password_hash="hash", is_active=False, is_email_verified=True)
        db_session.add(user)
        await db_session.commit()

        state, _ = await create_oauth_state("google", "https://example.com/callback")
        oauth_service.exchange_code = AsyncMock(return_value={"id": "g_blocked", "email": email, "name": "Blocked"})

        response = await oauth_client.get(f"/oauth/google/callback?code=test&state={state}")
        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestOAuthStateManagement:

    @pytest.mark.asyncio
    async def test_create_and_validate_oauth_state(self, oauth_client):
        from app.routers.oauth import create_oauth_state, get_oauth_state, delete_oauth_state

        state, verifier = await create_oauth_state("google", "https://example.com/callback")
        assert isinstance(state, str)
        assert len(state) > 0
        assert isinstance(verifier, str)
        assert len(verifier) > 0
        assert state != verifier

        data = await get_oauth_state(state)
        assert data is not None
        assert data["provider"] == "google"

        await delete_oauth_state(state)
        data = await get_oauth_state(state)
        assert data is None

    @pytest.mark.asyncio
    async def test_pkce_code_challenge(self, oauth_client):
        from app.routers.oauth import OAuthState
        verifier = "test_verifier_1234567890"
        challenge = OAuthState.generate_code_challenge(verifier)
        assert isinstance(challenge, str)
        assert len(challenge) > 0
        assert "+" not in challenge
        assert "/" not in challenge
        assert challenge == OAuthState.generate_code_challenge(verifier)


class TestOAuthEdgeCases:

    @pytest.mark.asyncio
    async def test_providers_empty_when_not_configured(self, oauth_client, monkeypatch):
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_GOOGLE_CLIENT_ID", None)
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_VK_CLIENT_ID", None)
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_APPLE_CLIENT_ID", None)
        response = await oauth_client.get("/oauth/providers")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_google_login_missing_redirect_uri(self, oauth_client, monkeypatch):
        monkeypatch.setattr("app.routers.oauth.settings.OAUTH_GOOGLE_CLIENT_ID", "test_id")
        response = await oauth_client.get("/oauth/google/login")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY