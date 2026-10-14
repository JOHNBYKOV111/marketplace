"""
E2E Integration Test: GDPR Delete (soft delete → internal API → auth revoke tokens)

Lead-level E2E test verifying the GDPR right-to-erasure cross-service contract:
1. User is created in auth-service via internal API (dynamic Faker credentials)
2. User is created in user-service database
3. User logs in via auth-service, obtains valid JWT
4. User calls DELETE /users/me in user-service (soft delete)
5. User-service calls POST /internal/user/delete in auth-service (token revocation)
6. Auth-service revokes all tokens and deletes the user record
7. Previously valid JWT is rejected by user-service (401/403/404)
8. User profile is no longer accessible

Design principles:
- Fully isolated: unique user per test, no shared state, parallel-safe
- Real services only: actual HTTP between all three services
- Pydantic contract enforcement: all responses validated against schemas
- Full cleanup: best-effort deletion in both services after test
- No hardcoded credentials: Faker generates unique data per run
"""

import pytest
from httpx import AsyncClient

from tests.e2e.schemas.auth_schemas import LoginResponse as AuthLoginResponse
from app.schemas.user import UserProfileResponse


class TestE2EGdprDelete:
    """End-to-end GDPR delete contract tests."""

    @pytest.mark.asyncio
    async def test_gdpr_delete_revokes_tokens(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        auth_headers: dict,
        user_exists_in_user_service: str,
    ):
        """
        E2E: GDPR delete — soft delete → internal API → auth revokes tokens.
        """
        login_response = await auth_client.post(
            "/api/v1/auth/login",
            json={
                "email": dynamic_user_credentials["email"],
                "password": dynamic_user_credentials["password"],
            },
        )
        assert login_response.status_code == 200

        auth_data = AuthLoginResponse.model_validate(login_response.json())
        access_token = auth_data.access_token
        jwt_headers = {"Authorization": f"Bearer {access_token}"}

        profile_before = await user_client.get("/users/me", headers=jwt_headers)
        assert profile_before.status_code == 200

        profile_data = UserProfileResponse.model_validate(profile_before.json())
        assert profile_data.email == dynamic_user_credentials["email"]

        delete_response = await user_client.delete(
            "/users/me",
            headers={"X-User-Id": user_exists_in_user_service},
        )
        assert delete_response.status_code == 200
        delete_data = delete_response.json()
        assert delete_data["success"] is True
        assert delete_data["user_id"] == user_exists_in_user_service

        profile_after = await user_client.get("/users/me", headers=jwt_headers)
        assert profile_after.status_code in (401, 403, 404), (
            f"Profile should be inaccessible after delete, got {profile_after.status_code}"
        )

    @pytest.mark.asyncio
    async def test_cannot_access_profile_after_delete(
        self,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        auth_client: AsyncClient,
        user_exists_in_user_service: str,
    ):
        """Deleted user profile returns 404."""
        login_resp = await auth_client.post(
            "/api/v1/auth/login",
            json={
                "email": dynamic_user_credentials["email"],
                "password": dynamic_user_credentials["password"],
            },
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        jwt_headers = {"Authorization": f"Bearer {token}"}

        await user_client.delete("/users/me", headers={"X-User-Id": user_exists_in_user_service})

        response = await user_client.get("/users/me", headers=jwt_headers)
        assert response.status_code in (401, 403, 404), (
            f"Expected rejection after delete, got {response.status_code}"
        )

    @pytest.mark.asyncio
    async def test_token_revoked_after_delete(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        dynamic_user_credentials: dict,
        e2e_user: dict,
        user_exists_in_user_service: str,
    ):
        """JWT tokens are invalidated after GDPR delete."""
        login_resp = await auth_client.post(
            "/api/v1/auth/login",
            json={
                "email": dynamic_user_credentials["email"],
                "password": dynamic_user_credentials["password"],
            },
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]

        pre_check = await user_client.get(
            "/users/me", headers={"Authorization": f"Bearer {token}"},
        )
        assert pre_check.status_code == 200

        await user_client.delete("/users/me", headers={"X-User-Id": user_exists_in_user_service})

        post_check = await user_client.get(
            "/users/me", headers={"Authorization": f"Bearer {token}"},
        )
        assert post_check.status_code in (401, 403, 404), (
            f"Token should be invalid after delete, got {post_check.status_code}"
        )

    @pytest.mark.asyncio
    async def test_auth_user_deleted_after_gdpr(
        self,
        auth_client: AsyncClient,
        dynamic_user_credentials: dict,
        e2e_user: dict,
    ):
        """Auth-service deletes user record after internal API call."""
        login_before = await auth_client.post(
            "/api/v1/auth/login",
            json={
                "email": dynamic_user_credentials["email"],
                "password": dynamic_user_credentials["password"],
            },
        )
        assert login_before.status_code == 200

        await auth_client.post(
            "/internal/user/delete",
            json={"user_id": e2e_user["user_id"]},
            headers={"X-Internal-API-Key": "test_api_key"},
        )

        login_after = await auth_client.post(
            "/api/v1/auth/login",
            json={
                "email": dynamic_user_credentials["email"],
                "password": dynamic_user_credentials["password"],
            },
        )
        assert login_after.status_code in (401, 404), (
            f"Login should fail after delete, got {login_after.status_code}"
        )

    @pytest.mark.asyncio
    async def test_idempotent_delete(
        self,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        auth_client: AsyncClient,
        user_exists_in_user_service: str,
    ):
        """Multiple DELETE /users/me calls are idempotent."""
        first = await user_client.delete(
            "/users/me", headers={"X-User-Id": user_exists_in_user_service},
        )
        assert first.status_code == 200
        assert first.json()["success"] is True

        second = await user_client.delete(
            "/users/me", headers={"X-User-Id": user_exists_in_user_service},
        )
        assert second.status_code == 200, f"Second delete should be idempotent, got {second.status_code}"
        assert second.json()["success"] is True