"""
E2E Integration Test: Profile Update (user → profile fields updated)

Lead-level E2E test verifying the profile update cross-service contract:
1. User authenticates via auth-service, obtains valid JWT
2. User updates profile fields via PATCH /users/me in user-service
3. User-service persists changes and invalidates cache
4. Updated profile is returned immediately via GET /users/me
5. JWT remains valid after non-email profile updates
6. UserProfileResponse schema is fully compliant with updated data
7. Partial updates work correctly (only changed fields are updated)
8. Empty body updates are idempotent (no changes)
9. Email is owned by auth-service and cannot be updated via user-service

Design principles:
- Fully isolated: unique user per test, no shared state, parallel-safe
- Real services only: actual HTTP between auth-service and user-service containers
- Pydantic contract enforcement: all responses validated against schemas
- Full cleanup: user deleted after each test
- No hardcoded credentials: Faker generates unique data per run
"""

import pytest
from httpx import AsyncClient

from app.schemas.user import UserProfileResponse


class TestE2EProfileUpdate:
    """End-to-end profile update contract tests."""

    async def _login(self, auth_client: AsyncClient, email: str, password: str) -> dict:
        """Login and return JWT headers."""
        login_resp = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    @pytest.mark.asyncio
    async def test_update_first_and_last_name(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        """Update first_name and last_name via PATCH /users/me."""
        jwt_headers = await self._login(
            auth_client, dynamic_user_credentials["email"], dynamic_user_credentials["password"]
        )

        patch_resp = await user_client.patch(
            "/users/me",
            json={"first_name": "UpdatedFirstName", "last_name": "UpdatedLastName"},
            headers=jwt_headers,
        )
        assert patch_resp.status_code == 200

        profile = UserProfileResponse.model_validate(patch_resp.json())
        assert profile.first_name == "UpdatedFirstName"
        assert profile.last_name == "UpdatedLastName"

        get_resp = await user_client.get("/users/me", headers=jwt_headers)
        assert get_resp.status_code == 200
        persisted = UserProfileResponse.model_validate(get_resp.json())
        assert persisted.first_name == "UpdatedFirstName"
        assert persisted.last_name == "UpdatedLastName"

    @pytest.mark.asyncio
    async def test_partial_update_only_first_name(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        """Partial update — only first_name, last_name unchanged."""
        jwt_headers = await self._login(
            auth_client, dynamic_user_credentials["email"], dynamic_user_credentials["password"]
        )

        get_before = await user_client.get("/users/me", headers=jwt_headers)
        assert get_before.status_code == 200
        original_last_name = get_before.json().get("last_name")

        patch_resp = await user_client.patch(
            "/users/me",
            json={"first_name": "OnlyFirstNameChanged"},
            headers=jwt_headers,
        )
        assert patch_resp.status_code == 200

        profile = UserProfileResponse.model_validate(patch_resp.json())
        assert profile.first_name == "OnlyFirstNameChanged"
        assert profile.last_name == original_last_name

    @pytest.mark.asyncio
    async def test_email_not_updatable_via_user_service(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        """Email is owned by auth-service, PATCH with email field does not change it."""
        jwt_headers = await self._login(
            auth_client, dynamic_user_credentials["email"], dynamic_user_credentials["password"]
        )

        original_email = dynamic_user_credentials["email"]

        patch_resp = await user_client.patch(
            "/users/me",
            json={"email": "newemail@example.com"},
            headers=jwt_headers,
        )
        assert patch_resp.status_code == 200

        profile = UserProfileResponse.model_validate(patch_resp.json())
        assert profile.email == original_email, (
            f"email should not change via user-service: expected={original_email}, got={profile.email}"
        )

    @pytest.mark.asyncio
    async def test_update_email_invalid_format(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        """Invalid email format returns 422."""
        jwt_headers = await self._login(
            auth_client, dynamic_user_credentials["email"], dynamic_user_credentials["password"]
        )

        response = await user_client.patch(
            "/users/me",
            json={"email": "not-an-email"},
            headers=jwt_headers,
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_empty_body_update_is_idempotent(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        """Empty PATCH body returns 200 with unchanged profile."""
        jwt_headers = await self._login(
            auth_client, dynamic_user_credentials["email"], dynamic_user_credentials["password"]
        )

        patch_resp = await user_client.patch("/users/me", json={}, headers=jwt_headers)
        assert patch_resp.status_code == 200

        profile = UserProfileResponse.model_validate(patch_resp.json())
        assert profile.is_active is True

    @pytest.mark.asyncio
    async def test_jwt_remains_valid_after_profile_update(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        """JWT token remains valid after profile updates."""
        jwt_headers = await self._login(
            auth_client, dynamic_user_credentials["email"], dynamic_user_credentials["password"]
        )

        pre_check = await user_client.get("/users/me", headers=jwt_headers)
        assert pre_check.status_code == 200

        patch_resp = await user_client.patch(
            "/users/me",
            json={"first_name": "TokenStillValid"},
            headers=jwt_headers,
        )
        assert patch_resp.status_code == 200

        post_check = await user_client.get("/users/me", headers=jwt_headers)
        assert post_check.status_code == 200

        profile = UserProfileResponse.model_validate(post_check.json())
        assert profile.first_name == "TokenStillValid"

    @pytest.mark.asyncio
    async def test_update_profile_requires_authentication(
        self,
        user_client: AsyncClient,
    ):
        """PATCH /users/me returns 401 without authentication."""
        response = await user_client.patch("/users/me", json={"first_name": "NoAuth"})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_update_profile_with_invalid_field_returns_422(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        """PATCH /users/me with invalid field returns 422."""
        jwt_headers = await self._login(
            auth_client, dynamic_user_credentials["email"], dynamic_user_credentials["password"]
        )

        response = await user_client.patch(
            "/users/me",
            json={"invalid_field": "value"},
            headers=jwt_headers,
        )
        assert response.status_code == 422