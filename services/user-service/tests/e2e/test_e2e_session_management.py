"""
E2E Integration Test: Session Management Flow

Verifies the cross-service contract for session management:
1. User authenticates and receives refresh token in http-only cookie
2. Multiple logins create multiple sessions
3. GET /auth/sessions returns all active sessions
4. POST /auth/sessions/revoke-all revokes ALL sessions including current
5. Revoked sessions cannot be used for token refresh
6. POST /auth/logout revokes current session
7. After logout, refresh token cookie is cleared
8. Unauthorized requests are rejected
"""

import asyncio

import pytest
from httpx import AsyncClient


class TestE2ESessionManagement:

    async def _login(self, auth_client: AsyncClient, email: str, password: str) -> dict:
        """Login and return access_token and refresh_token from cookies."""
        login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login.status_code == 200, f"Login failed: {login.text}"
        return {
            "access_token": login.json()["access_token"],
            "refresh_token": login.cookies.get("refresh_token"),
        }

    @pytest.mark.asyncio
    async def test_multiple_sessions_created(
        self,
        auth_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
    ):
        """Multiple logins create multiple refresh tokens."""
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]

        tokens1 = await self._login(auth_client, email, password)
        tokens2 = await self._login(auth_client, email, password)
        tokens3 = await self._login(auth_client, email, password)

        assert tokens1["refresh_token"] is not None
        assert tokens2["refresh_token"] is not None
        assert tokens3["refresh_token"] is not None

        assert tokens1["refresh_token"] != tokens2["refresh_token"]
        assert tokens2["refresh_token"] != tokens3["refresh_token"]
        assert tokens1["refresh_token"] != tokens3["refresh_token"]

        for tokens in [tokens1, tokens2, tokens3]:
            refresh = await auth_client.post(
                "/api/v1/auth/refresh",
                cookies={"refresh_token": tokens["refresh_token"]},
            )
            assert refresh.status_code == 200, f"Refresh failed: {refresh.text}"

    @pytest.mark.asyncio
    async def test_list_sessions(
        self,
        auth_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
    ):
        """GET /auth/sessions returns all active sessions."""
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]

        await self._login(auth_client, email, password)
        await self._login(auth_client, email, password)
        tokens = await self._login(auth_client, email, password)

        sessions = await auth_client.get(
            "/api/v1/auth/sessions",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert sessions.status_code == 200, f"Sessions failed: {sessions.text}"
        data = sessions.json()
        assert "sessions" in data
        assert "total" in data
        assert data["total"] >= 3, f"Expected at least 3 sessions, got {data['total']}"

        for session in data["sessions"]:
            assert "id" in session
            assert "user_id" in session
            assert "created_at" in session
            assert "expires_at" in session
            assert "is_active" in session

    @pytest.mark.asyncio
    async def test_revoke_all_sessions(
        self,
        auth_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
    ):
        """POST /auth/sessions/revoke-all revokes ALL sessions including current."""
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]

        tokens1 = await self._login(auth_client, email, password)
        tokens2 = await self._login(auth_client, email, password)
        current_tokens = await self._login(auth_client, email, password)

        revoke = await auth_client.post(
            "/api/v1/auth/sessions/revoke-all",
            headers={"Authorization": f"Bearer {current_tokens['access_token']}"},
        )
        assert revoke.status_code == 200, f"Revoke failed: {revoke.text}"

        await asyncio.sleep(0.3)

        # All sessions including current should be revoked
        for old_tokens in [tokens1, tokens2, current_tokens]:
            refresh = await auth_client.post(
                "/api/v1/auth/refresh",
                cookies={"refresh_token": old_tokens["refresh_token"]},
            )
            assert refresh.status_code == 401, (
                f"All sessions should be revoked, got {refresh.status_code}"
            )

        # New login should work
        new_tokens = await self._login(auth_client, email, password)
        assert new_tokens["refresh_token"] is not None
        refresh = await auth_client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": new_tokens["refresh_token"]},
        )
        assert refresh.status_code == 200, "New session should work after revoke all"

    @pytest.mark.asyncio
    async def test_logout_revokes_session(
        self,
        auth_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
    ):
        """POST /auth/logout revokes current session and clears cookie."""
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]

        tokens = await self._login(auth_client, email, password)

        logout = await auth_client.post(
            "/api/v1/auth/logout",
            cookies={"refresh_token": tokens["refresh_token"]},
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert logout.status_code == 200, f"Logout failed: {logout.text}"
        assert logout.json()["success"] is True

        assert "refresh_token" not in logout.cookies or logout.cookies.get("refresh_token") == ""

        await asyncio.sleep(0.3)

        refresh = await auth_client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": tokens["refresh_token"]},
        )
        assert refresh.status_code == 401, (
            f"Revoked token should not work, got {refresh.status_code}"
        )

    @pytest.mark.asyncio
    async def test_sessions_unauthorized(
        self,
        auth_client: AsyncClient,
    ):
        """Session endpoints require authentication."""
        sessions = await auth_client.get("/api/v1/auth/sessions")
        assert sessions.status_code == 401, (
            f"Should require auth, got {sessions.status_code}"
        )

        revoke = await auth_client.post("/api/v1/auth/sessions/revoke-all")
        assert revoke.status_code == 401, (
            f"Should require auth, got {revoke.status_code}"
        )

    @pytest.mark.asyncio
    async def test_refresh_token_rotation(
        self,
        auth_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
    ):
        """Refresh token rotation: old token invalid after refresh."""
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]

        tokens = await self._login(auth_client, email, password)
        old_refresh = tokens["refresh_token"]

        refresh = await auth_client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": old_refresh},
        )
        assert refresh.status_code == 200
        new_refresh = refresh.cookies.get("refresh_token")
        assert new_refresh is not None
        assert new_refresh != old_refresh, "New refresh token should differ from old"

        await asyncio.sleep(0.3)

        old_retry = await auth_client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": old_refresh},
        )
        assert old_retry.status_code == 401, (
            f"Old token should be invalid after rotation, got {old_retry.status_code}"
        )

        new_retry = await auth_client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": new_refresh},
        )
        assert new_retry.status_code == 200, (
            f"New token should work, got {new_retry.status_code}"
        )