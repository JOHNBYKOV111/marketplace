"""
E2E Contract Test: Audit Trail Flow

Verifies the cross-service contract for audit logging:
1. Admin authenticates via real JWT login
2. Admin performs block/unblock actions on a user
3. Audit logs are created in user-service database
4. Admin can retrieve audit trail for the user
5. Audit trail contains correct actions with pagination
6. Non-admin cannot access audit trail
7. Pagination works correctly (limit/offset)
"""

import pytest
from httpx import AsyncClient


ADMIN_EMAIL = "admin@test.com"
ADMIN_PASSWORD = "SecurePass123!"


class TestE2EAuditTrail:

    async def _admin_headers(self, auth_client: AsyncClient) -> dict:
        """Get admin authorization headers via real JWT login."""
        login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        assert login.status_code == 200, f"Admin login failed: {login.text}"
        token = login.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    async def _user_headers(
        self, auth_client: AsyncClient, email: str, password: str
    ) -> dict:
        """Get user authorization headers via real JWT login."""
        login = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login.status_code == 200, f"User login failed: {login.text}"
        token = login.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    @pytest.mark.asyncio
    async def test_audit_trail_after_block_unblock(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        """Audit trail contains block and unblock actions after admin operations."""
        user_id = user_exists_in_user_service
        admin_headers = await self._admin_headers(auth_client)

        # Block user
        block = await user_client.post(
            f"/admin/users/{user_id}/block",
            json={"reason": "Audit test block"},
            headers=admin_headers,
        )
        assert block.status_code == 200, f"Block failed: {block.text}"

        # Unblock user
        unblock = await user_client.post(
            f"/admin/users/{user_id}/unblock",
            json={"reason": "Audit test unblock"},
            headers=admin_headers,
        )
        assert unblock.status_code == 200, f"Unblock failed: {unblock.text}"

        # Retrieve audit trail
        audit = await user_client.get(
            f"/admin/users/{user_id}/audit",
            headers=admin_headers,
        )
        assert audit.status_code == 200, f"Audit failed: {audit.text}"
        data = audit.json()

        assert "items" in data
        assert "total" in data
        assert data["total"] >= 2, f"Expected at least 2 audit logs, got {data['total']}"

        actions = [item["action"] for item in data["items"]]
        assert "block_user" in actions, f"block_user not in {actions}"
        assert "unblock_user" in actions, f"unblock_user not in {actions}"

        # Verify success flag
        for item in data["items"]:
            assert item["success"] is True, f"Audit log {item['action']} should be successful"

    @pytest.mark.asyncio
    async def test_audit_trail_requires_admin(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        e2e_user: dict,
        dynamic_user_credentials: dict,
        user_exists_in_user_service: str,
    ):
        """Regular user cannot access audit trail."""
        user_id = user_exists_in_user_service
        email = dynamic_user_credentials["email"]
        password = dynamic_user_credentials["password"]
        user_headers = await self._user_headers(auth_client, email, password)

        audit = await user_client.get(
            f"/admin/users/{user_id}/audit",
            headers=user_headers,
        )
        assert audit.status_code == 403, (
            f"Regular user should be forbidden, got {audit.status_code}"
        )

    @pytest.mark.asyncio
    async def test_audit_trail_pagination(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        e2e_user: dict,
        user_exists_in_user_service: str,
    ):
        """Audit trail pagination works correctly."""
        user_id = user_exists_in_user_service
        admin_headers = await self._admin_headers(auth_client)

        # Create multiple audit entries via block/unblock
        for i in range(3):
            await user_client.post(
                f"/admin/users/{user_id}/block",
                json={"reason": f"Pagination test {i}"},
                headers=admin_headers,
            )
            await user_client.post(
                f"/admin/users/{user_id}/unblock",
                json={"reason": f"Pagination test {i}"},
                headers=admin_headers,
            )

        # Get first page
        page1 = await user_client.get(
            f"/admin/users/{user_id}/audit?limit=3&offset=0",
            headers=admin_headers,
        )
        assert page1.status_code == 200
        data1 = page1.json()
        assert len(data1["items"]) == 3
        assert data1["limit"] == 3
        assert data1["offset"] == 0

        # Get second page
        page2 = await user_client.get(
            f"/admin/users/{user_id}/audit?limit=3&offset=3",
            headers=admin_headers,
        )
        assert page2.status_code == 200
        data2 = page2.json()
        assert len(data2["items"]) >= 1
        assert data2["limit"] == 3
        assert data2["offset"] == 3

        # Verify no overlap between pages
        page1_ids = {item["id"] for item in data1["items"]}
        page2_ids = {item["id"] for item in data2["items"]}
        assert page1_ids.isdisjoint(page2_ids), "Pages should not overlap"

    @pytest.mark.asyncio
    async def test_audit_trail_unauthorized(
        self,
        user_client: AsyncClient,
        e2e_user: dict,
        user_exists_in_user_service: str,
    ):
        """Audit trail returns 401 without authentication."""
        user_id = user_exists_in_user_service
        audit = await user_client.get(f"/admin/users/{user_id}/audit")
        assert audit.status_code == 401, (
            f"Unauthorized should return 401, got {audit.status_code}"
        )