"""
E2E Contract Test: Change Password Flow

Verifies the cross-service contract for password change:
1. User authenticates via real login
2. User changes password via auth-service Gateway endpoint
3. Old password is rejected after change
4. New password works for login
5. All sessions are revoked after password change (old refresh tokens invalid)
6. Unauthorized requests are rejected
7. Validation errors for weak/same passwords
"""

import asyncio

import pytest
from httpx import AsyncClient


class TestE2EChangePassword:

    @pytest.mark.asyncio
    async def test_change_password_success(
        self,
        auth_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
    ):
        """User changes password, old stops working, new works."""
        user_id = e2e_user["user_id"]
        email = dynamic_user_credentials["email"]
        old_password = dynamic_user_credentials["password"]
        new_password = "NewSecurePass456!"

        # Login with old password
        login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": old_password},
        )
        assert login.status_code == 200, f"Login failed: {login.text}"

        # Change password via Gateway headers
        change = await auth_client.post(
            "/password/change",
            json={
                "old_password": old_password,
                "new_password": new_password,
            },
            headers={
                "X-User-Id": user_id,
                "X-User-Roles": "user",
                "X-User-Email": email,
            },
        )
        assert change.status_code == 200, f"Change failed: {change.text}"
        data = change.json()
        assert data["success"] is True
        assert "changed successfully" in data["message"]
        assert data["sessions_revoked"] is True

        # Old password rejected
        old_login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": old_password},
        )
        assert old_login.status_code == 401, (
            f"Old password should be rejected, got {old_login.status_code}"
        )

        # New password works
        new_login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": new_password},
        )
        assert new_login.status_code == 200, (
            f"New password should work, got {new_login.status_code}"
        )

        # Restore original password for cleanup
        await auth_client.post(
            "/password/change",
            json={
                "old_password": new_password,
                "new_password": old_password,
            },
            headers={
                "X-User-Id": user_id,
                "X-User-Roles": "user",
                "X-User-Email": email,
            },
        )

    @pytest.mark.asyncio
    async def test_change_password_wrong_old_password(
        self,
        auth_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
    ):
        """Change password fails with incorrect old password."""
        user_id = e2e_user["user_id"]
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]

        login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login.status_code == 200

        change = await auth_client.post(
            "/password/change",
            json={
                "old_password": "WrongOldPassword123!",
                "new_password": "NewPass456!",
            },
            headers={
                "X-User-Id": user_id,
                "X-User-Roles": "user",
                "X-User-Email": email,
            },
        )
        assert change.status_code == 401, (
            f"Wrong old password should return 401, got {change.status_code}"
        )

    @pytest.mark.asyncio
    async def test_change_password_same_as_old(
        self,
        auth_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
    ):
        """Change password fails when new equals old."""
        user_id = e2e_user["user_id"]
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]

        login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login.status_code == 200

        change = await auth_client.post(
            "/password/change",
            json={
                "old_password": password,
                "new_password": password,
            },
            headers={
                "X-User-Id": user_id,
                "X-User-Roles": "user",
                "X-User-Email": email,
            },
        )
        assert change.status_code == 400, (
            f"Same password should return 400, got {change.status_code}"
        )

    @pytest.mark.asyncio
    async def test_change_password_weak_new_password(
        self,
        auth_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
    ):
        """Change password fails with weak new password."""
        user_id = e2e_user["user_id"]
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]

        login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login.status_code == 200

        change = await auth_client.post(
            "/password/change",
            json={
                "old_password": password,
                "new_password": "weak",
            },
            headers={
                "X-User-Id": user_id,
                "X-User-Roles": "user",
                "X-User-Email": email,
            },
        )
        assert change.status_code == 422, (
            f"Weak password should return 422, got {change.status_code}"
        )

    @pytest.mark.asyncio
    async def test_change_password_unauthorized(
        self,
        auth_client: AsyncClient,
    ):
        """Change password fails without Gateway headers."""
        change = await auth_client.post(
            "/password/change",
            json={
                "old_password": "OldPass123!",
                "new_password": "NewPass456!",
            },
        )
        assert change.status_code == 401, (
            f"Unauthorized should return 401, got {change.status_code}"
        )

    @pytest.mark.asyncio
    async def test_change_password_sessions_revoked(
        self,
        auth_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
    ):
        """After password change, old refresh tokens are invalidated."""
        user_id = e2e_user["user_id"]
        email = dynamic_user_credentials["email"]
        old_password = dynamic_user_credentials["password"]
        new_password = "RevokedSessionPass1!"

        # Login to get tokens
        login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": old_password},
        )
        assert login.status_code == 200
        old_refresh = login.cookies.get("refresh_token")
        assert old_refresh is not None, "No refresh_token in cookies"

        # Change password
        change = await auth_client.post(
            "/password/change",
            json={
                "old_password": old_password,
                "new_password": new_password,
            },
            headers={
                "X-User-Id": user_id,
                "X-User-Roles": "user",
                "X-User-Email": email,
            },
        )
        assert change.status_code == 200
        assert change.json()["sessions_revoked"] is True

        # Wait for transaction to complete before checking refresh
        await asyncio.sleep(0.2)

        # Old refresh token should be rejected
        refresh = await auth_client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": old_refresh},
        )
        assert refresh.status_code == 401, (
            f"Old refresh token should be rejected, got {refresh.status_code}"
        )

        # Restore original password
        new_login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": new_password},
        )
        assert new_login.status_code == 200
        await auth_client.post(
            "/password/change",
            json={
                "old_password": new_password,
                "new_password": old_password,
            },
            headers={
                "X-User-Id": user_id,
                "X-User-Roles": "user",
                "X-User-Email": email,
            },
        )