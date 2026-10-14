"""
E2E Integration Test: Authorization Flow (auth → JWT → user → profile/roles)

Lead-level E2E test verifying the real cross-service authorization contract:
1. Auth-service registers a new dynamic user (Faker-generated credentials)
2. Auth-service issues a valid JWT on login
3. User-service accepts that JWT and returns the correct user profile
4. User identity (email, user_id) is consistent across both services
5. User-service rejects invalid/expired/malformed tokens with 401
6. UserProfileResponse schema is fully compliant

Design principles:
- Fully isolated: unique user per test, no shared state, parallel-safe
- Real services only: actual HTTP between auth-service and user-service containers
- Pydantic contract enforcement: all responses validated against auth/service schemas
- Full cleanup: user deleted from auth-service after each test
- No hardcoded credentials: Faker generates unique data per run
"""

import asyncio

import pytest
from httpx import AsyncClient

from tests.e2e.schemas.auth_schemas import LoginResponse as AuthLoginResponse
from app.schemas.user import UserProfileResponse


class TestE2EAuthorization:
    """End-to-end authorization contract tests between auth and user services."""

    @pytest.mark.asyncio
    async def test_full_auth_flow_login_to_profile(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        auth_headers: dict,
        user_exists_in_user_service: str,
    ):
        """E2E: Full authorization flow — login → JWT → profile."""
        login_response = await auth_client.post(
            "/api/v1/auth/login",
            json={
                "email": dynamic_user_credentials["email"],
                "password": dynamic_user_credentials["password"],
            },
        )
        assert login_response.status_code == 200

        auth_data = AuthLoginResponse.model_validate(login_response.json())
        assert auth_data.email == dynamic_user_credentials["email"]

        profile_response = await user_client.get("/users/me", headers=auth_headers)
        assert profile_response.status_code == 200

        profile = UserProfileResponse.model_validate(profile_response.json())
        assert profile.email == auth_data.email

    @pytest.mark.asyncio
    async def test_profile_schema_compliance(
        self,
        user_client: AsyncClient,
        auth_headers: dict,
        user_exists_in_user_service: str,
    ):
        """GET /users/me response matches UserProfileResponse schema."""
        response = await user_client.get("/users/me", headers=auth_headers)
        assert response.status_code == 200

        profile = UserProfileResponse.model_validate(response.json())
        assert "@" in profile.email
        assert profile.is_active is not None
        assert profile.is_email_verified is not None
        assert profile.is_superuser is not None

    @pytest.mark.asyncio
    async def test_concurrent_sessions_independent(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        """Multiple JWT tokens work independently for the same user."""
        tokens = []
        for _ in range(3):
            resp = await auth_client.post(
                "/api/v1/auth/login",
                json={
                    "email": dynamic_user_credentials["email"],
                    "password": dynamic_user_credentials["password"],
                },
            )
            assert resp.status_code == 200
            auth_data = AuthLoginResponse.model_validate(resp.json())
            tokens.append(auth_data.access_token)

        for i, token in enumerate(tokens):
            headers = {"Authorization": f"Bearer {token}"}
            resp = await user_client.get("/users/me", headers=headers)
            assert resp.status_code == 200, f"Token {i} rejected: {resp.status_code}"
            profile = UserProfileResponse.model_validate(resp.json())
            assert profile.email == dynamic_user_credentials["email"]

    @pytest.mark.asyncio
    async def test_user_service_rejects_invalid_jwt(
        self,
        user_client: AsyncClient,
    ):
        """User-service returns 401 for invalid JWT."""
        invalid_headers = {"Authorization": "Bearer invalid_token_here"}
        response = await user_client.get("/users/me", headers=invalid_headers)
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_user_service_rejects_missing_auth_header(
        self,
        user_client: AsyncClient,
    ):
        """User-service returns 401 when Authorization header is missing."""
        response = await user_client.get("/users/me")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_user_service_rejects_non_bearer_auth(
        self,
        user_client: AsyncClient,
    ):
        """User-service returns 401 for non-Bearer Authorization scheme."""
        bad_headers = {"Authorization": "Basic dXNlcjpwYXNz"}
        response = await user_client.get("/users/me", headers=bad_headers)
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_auth_service_rejects_invalid_credentials(
        self,
        auth_client: AsyncClient,
    ):
        """Auth-service returns 401 for invalid credentials."""
        response = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent@example.com", "password": "WrongPassword123!"},
        )
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == "UNAUTHORIZED"

    @pytest.mark.asyncio
    async def test_cross_service_token_not_reusable_after_logout(
        self,
        auth_client: AsyncClient,
        dynamic_user_credentials: dict,
        e2e_user: dict,
    ):
        """Refresh token is rejected after logout."""
        login_resp = await auth_client.post(
            "/api/v1/auth/login",
            json={
                "email": dynamic_user_credentials["email"],
                "password": dynamic_user_credentials["password"],
            },
        )
        assert login_resp.status_code == 200
        access_token = login_resp.json()["access_token"]
        refresh_token = login_resp.cookies.get("refresh_token")

        # Verify refresh token works before logout
        refresh_before = await auth_client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": refresh_token},
        )
        assert refresh_before.status_code == 200, "Refresh token should work before logout"

        # Logout
        await auth_client.post(
            "/api/v1/auth/logout",
            cookies={"refresh_token": refresh_token},
            headers={"Authorization": f"Bearer {access_token}"},
        )

        await asyncio.sleep(0.3)

        # Refresh token should be rejected after logout
        refresh_after = await auth_client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": refresh_token},
        )
        assert refresh_after.status_code == 401, (
            f"Refresh token should be rejected after logout, got {refresh_after.status_code}"
        )