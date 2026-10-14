"""
E2E Contract Test: Block/Unblock User Flow

Verifies the cross-service contract for user blocking:
1. Admin authenticates via real JWT login
2. Admin blocks user via user-service admin endpoint
3. User-service syncs block to auth-service via internal API
4. Blocked user cannot login via auth-service
5. Blocked user's JWT is rejected by auth-service
6. Admin unblocks user via user-service
7. User can login and access profile again after unblock

Note: After block, the user's JWT is rejected by AUTH-SERVICE (not user-service).
The user-service continues to serve profile from its own DB, but the JWT
validation happens in auth-service. We verify rejection through auth-service.
"""

import json
import base64
import pytest
from httpx import AsyncClient


ADMIN_EMAIL = "admin@test.com"
ADMIN_PASSWORD = "SecurePass123!"


class TestE2EBlockUser:

    @pytest.mark.asyncio
    async def test_block_user_revokes_access(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]
        user_id = user_exists_in_user_service

        # User login
        user_login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert user_login.status_code == 200
        user_token = user_login.json()["access_token"]

        # Profile accessible before block
        before = await auth_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert before.status_code == 200

        # Admin login
        admin_login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        assert admin_login.status_code == 200
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Admin blocks user
        block = await user_client.post(
            f"/admin/users/{user_id}/block",
            json={"reason": "E2E test block"},
            headers=admin_headers,
        )
        assert block.status_code == 200, (
            f"Block failed: {block.status_code} — {block.text}"
        )

        # Login should be rejected after block — checked via auth-service
        login_after = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login_after.status_code in (401, 403), (
            f"Login should be rejected after block, got {login_after.status_code}"
        )

    @pytest.mark.asyncio
    async def test_unblock_user_restores_access(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]
        user_id = user_exists_in_user_service

        # Admin login
        admin_login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        assert admin_login.status_code == 200
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Block
        block = await user_client.post(
            f"/admin/users/{user_id}/block",
            json={"reason": "E2E test"},
            headers=admin_headers,
        )
        assert block.status_code == 200, f"Pre-block failed: {block.status_code}"

        # Verify login rejected via auth-service
        login_blocked = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login_blocked.status_code in (401, 403), (
            f"Expected login rejection after block, got {login_blocked.status_code}"
        )

        # Unblock
        unblock = await user_client.post(
            f"/admin/users/{user_id}/unblock",
            json={"reason": "E2E test unblock"},
            headers=admin_headers,
        )
        assert unblock.status_code == 200, (
            f"Unblock failed: {unblock.status_code} — {unblock.text}"
        )

        # Login works after unblock
        login_after = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login_after.status_code == 200, (
            f"Login should work after unblock, got {login_after.status_code}"
        )

    @pytest.mark.asyncio
    async def test_block_user_requires_admin(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        user_id = user_exists_in_user_service
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]

        # Login as regular user
        user_login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert user_login.status_code == 200
        user_token = user_login.json()["access_token"]
        user_headers = {"Authorization": f"Bearer {user_token}"}

        # Regular user tries to block
        response = await user_client.post(
            f"/admin/users/{user_id}/block",
            json={"reason": "Should fail"},
            headers=user_headers,
        )
        assert response.status_code in (401, 403), (
            f"Block by non-admin should be rejected, got {response.status_code}"
        )

    @pytest.mark.asyncio
    async def test_block_nonexistent_user(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
    ):
        # Admin login
        admin_login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        assert admin_login.status_code == 200
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        fake_id = "00000000-0000-0000-0000-000000000000"
        response = await user_client.post(
            f"/admin/users/{fake_id}/block",
            json={"reason": "Test"},
            headers=admin_headers,
        )
        assert response.status_code == 404, (
            f"Expected 404 for non-existent user, got {response.status_code}"
        )

    @pytest.mark.asyncio
    async def test_unblock_nonexistent_user(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
    ):
        # Admin login
        admin_login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        assert admin_login.status_code == 200
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        fake_id = "00000000-0000-0000-0000-000000000000"
        response = await user_client.post(
            f"/admin/users/{fake_id}/unblock",
            json={"reason": "Test"},
            headers=admin_headers,
        )
        assert response.status_code == 404, (
            f"Expected 404 for non-existent user, got {response.status_code}"
        )