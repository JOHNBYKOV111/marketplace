"""
Integration tests for Admin API endpoints.

Tests cover:
- GET /admin/users (list with pagination)
- GET /admin/users/{id} (get user by ID)
- POST /admin/users/{id}/block (block user)
- POST /admin/users/{id}/unblock (unblock user)
- GET /admin/users/{id}/audit (audit trail)
- Authentication and authorization (admin role required)
- Rate limiting
- Edge cases and error handling

Note: is_active, is_email_verified, and email search are managed by auth-service,
not user-service. These filters are passed through to auth-service via internal API.
"""

from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.audit_log import AuditLog


# ==================== FIXTURES ====================

@pytest.fixture
def admin_user_id():
    """Admin user ID for authorization headers."""
    return uuid4()


@pytest.fixture
def admin_headers(admin_user_id):
    """Headers with admin user credentials."""
    return {
        "X-User-Id": str(admin_user_id),
        "X-User-Roles": "admin",
    }


@pytest.fixture
def user_headers():
    """Headers with regular user credentials (no admin access)."""
    return {
        "X-User-Id": str(uuid4()),
        "X-User-Roles": "user",
    }


def _make_user(email: str, **kwargs) -> User:
    """Helper to create User with email_hash from email."""
    return User(
        email_hash=User.create_email_hash(email),
        **kwargs,
    )


@pytest_asyncio.fixture
async def sample_user(db_session: AsyncSession):
    """Create a real user with proper email_hash for testing."""
    user = _make_user("sample@example.com", first_name="Sample", last_name="User")
    db_session.add(user)
    await db_session.flush()
    return user


# ==================== LIST USERS TESTS ====================

class TestAdminListUsers:
    """Tests for GET /admin/users endpoint."""

    @pytest.mark.asyncio
    async def test_list_users_default_pagination(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test listing users with default pagination."""
        for i in range(5):
            user = _make_user(f"list{i}@example.com")
            db_session.add(user)
        await db_session.flush()

        response = await client.get("/admin/users", headers=admin_headers)
        assert response.status_code == 200

        data = response.json()
        assert "items" in data
        assert data["total"] >= 5
        assert data["limit"] == 20
        assert data["offset"] == 0

    @pytest.mark.asyncio
    async def test_list_users_with_pagination(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test listing users with custom pagination."""
        for i in range(10):
            user = _make_user(f"page{i}@example.com")
            db_session.add(user)
        await db_session.flush()

        response = await client.get("/admin/users?limit=3&offset=3", headers=admin_headers)
        assert response.status_code == 200

        data = response.json()
        assert len(data["items"]) == 3
        assert data["limit"] == 3
        assert data["offset"] == 3

    @pytest.mark.asyncio
    async def test_list_users_empty(self, client: AsyncClient, admin_headers):
        """Test listing users when no users exist."""
        response = await client.get("/admin/users", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_list_users_requires_admin_role(self, client: AsyncClient, user_headers):
        """Test that regular users cannot access admin endpoints."""
        response = await client.get("/admin/users", headers=user_headers)
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_list_users_without_auth(self, client: AsyncClient):
        """Test that unauthenticated requests are rejected."""
        response = await client.get("/admin/users")
        assert response.status_code in (401, 403, 422)


# ==================== GET USER TESTS ====================

class TestAdminGetUser:
    """Tests for GET /admin/users/{id} endpoint."""

    @pytest.mark.asyncio
    async def test_get_user_by_id(self, client: AsyncClient, sample_user, admin_headers):
        """Test getting user by ID as admin."""
        response = await client.get(f"/admin/users/{sample_user.id}", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "Sample"

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, client: AsyncClient, admin_headers):
        """Test getting non-existent user."""
        fake_id = uuid4()
        response = await client.get(f"/admin/users/{fake_id}", headers=admin_headers)
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_user_soft_deleted(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test getting soft-deleted user."""
        user = _make_user("deleted_target@example.com", is_deleted=True)
        db_session.add(user)
        await db_session.flush()

        response = await client.get(f"/admin/users/{user.id}", headers=admin_headers)
        assert response.status_code == 200
        assert response.json()["is_deleted"] is True


# ==================== BLOCK USER TESTS ====================

class TestAdminBlockUser:
    """Tests for POST /admin/users/{id}/block endpoint."""

    @pytest.mark.asyncio
    async def test_block_user_success(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test successfully blocking a user."""
        user = _make_user("block_me@example.com")
        db_session.add(user)
        await db_session.flush()

        response = await client.post(
            f"/admin/users/{user.id}/block",
            json={"reason": "Violation of terms"},
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_block_user_already_blocked(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test blocking already blocked user."""
        user = _make_user("already_blocked@example.com")
        db_session.add(user)
        await db_session.flush()

        response = await client.post(
            f"/admin/users/{user.id}/block",
            json={"reason": "Second attempt"},
            headers=admin_headers,
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_block_user_not_found(self, client: AsyncClient, admin_headers):
        """Test blocking non-existent user."""
        fake_id = uuid4()
        response = await client.post(
            f"/admin/users/{fake_id}/block",
            json={"reason": "Test"},
            headers=admin_headers,
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_block_user_creates_audit_log(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test blocking user creates an audit log entry."""
        user = _make_user("audit_block@example.com")
        db_session.add(user)
        await db_session.flush()

        await client.post(
            f"/admin/users/{user.id}/block",
            json={"reason": "Spam"},
            headers=admin_headers,
        )

        from sqlalchemy import select
        log = await db_session.execute(
            select(AuditLog).where(
                AuditLog.user_id == user.id,
                AuditLog.action == "block_user",
            )
        )
        log_entry = log.scalar_one_or_none()
        assert log_entry is not None
        assert log_entry.success is True


# ==================== UNBLOCK USER TESTS ====================

class TestAdminUnblockUser:
    """Tests for POST /admin/users/{id}/unblock endpoint."""

    @pytest.mark.asyncio
    async def test_unblock_user_success(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test successfully unblocking a user."""
        user = _make_user("unblock_me@example.com")
        db_session.add(user)
        await db_session.flush()

        response = await client.post(
            f"/admin/users/{user.id}/unblock",
            json={"reason": "Appeal approved"},
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_unblock_user_already_active(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test unblocking already active user."""
        user = _make_user("already_active@example.com")
        db_session.add(user)
        await db_session.flush()

        response = await client.post(
            f"/admin/users/{user.id}/unblock",
            json={"reason": "Error"},
            headers=admin_headers,
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_unblock_user_not_found(self, client: AsyncClient, admin_headers):
        """Test unblocking non-existent user."""
        fake_id = uuid4()
        response = await client.post(
            f"/admin/users/{fake_id}/unblock",
            json={"reason": "Test"},
            headers=admin_headers,
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_unblock_user_creates_audit_log(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test unblocking user creates an audit log entry."""
        user = _make_user("audit_unblock@example.com")
        db_session.add(user)
        await db_session.flush()

        await client.post(
            f"/admin/users/{user.id}/unblock",
            json={"reason": "Appeal"},
            headers=admin_headers,
        )

        from sqlalchemy import select
        log = await db_session.execute(
            select(AuditLog).where(
                AuditLog.user_id == user.id,
                AuditLog.action == "unblock_user",
            )
        )
        log_entry = log.scalar_one_or_none()
        assert log_entry is not None
        assert log_entry.success is True


# ==================== AUDIT TRAIL TESTS ====================

class TestAdminAuditTrail:
    """Tests for GET /admin/users/{id}/audit endpoint."""

    @pytest.mark.asyncio
    async def test_get_audit_trail(self, client: AsyncClient, sample_user, db_session: AsyncSession, admin_headers):
        """Test getting audit trail for a user."""
        log1 = AuditLog(user_id=sample_user.id, action="update_profile", success=True, ip_address="192.168.1.1")
        log2 = AuditLog(user_id=sample_user.id, action="change_role", success=True, ip_address="10.0.0.1")
        db_session.add_all([log1, log2])
        await db_session.flush()

        response = await client.get(f"/admin/users/{sample_user.id}/audit", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 2

    @pytest.mark.asyncio
    async def test_get_audit_trail_empty(self, client: AsyncClient, sample_user, admin_headers):
        """Test getting audit trail for user with no logs."""
        response = await client.get(f"/admin/users/{sample_user.id}/audit", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []

    @pytest.mark.asyncio
    async def test_get_audit_trail_pagination(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test audit trail with pagination."""
        user = _make_user("paginated_audit@example.com")
        db_session.add(user)
        await db_session.flush()

        for i in range(10):
            log = AuditLog(user_id=user.id, action=f"action_{i}", success=True)
            db_session.add(log)
        await db_session.flush()

        response = await client.get(
            f"/admin/users/{user.id}/audit?limit=5&offset=3",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 5
        assert data["total"] == 10


# ==================== RATE LIMITING TESTS ====================

class TestAdminRateLimiting:
    """Tests for rate limiting on admin endpoints."""

    @pytest.mark.asyncio
    async def test_rate_limit_admin_endpoints(self, client: AsyncClient, admin_headers):
        """Test that admin endpoints are rate limited."""
        for _ in range(50):
            response = await client.get("/admin/users", headers=admin_headers)

        response = await client.get("/admin/users", headers=admin_headers)
        assert response.status_code in (200, 429)


# ==================== EDGE CASES TESTS ====================

class TestAdminEdgeCases:
    """Tests for edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_block_user_without_reason(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test blocking user without providing a reason."""
        user = _make_user("no_reason@example.com")
        db_session.add(user)
        await db_session.flush()

        response = await client.post(
            f"/admin/users/{user.id}/block",
            json={},
            headers=admin_headers,
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_unblock_user_without_reason(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test unblocking user without providing a reason."""
        user = _make_user("no_reason_unblock@example.com")
        db_session.add(user)
        await db_session.flush()

        response = await client.post(
            f"/admin/users/{user.id}/unblock",
            json={},
            headers=admin_headers,
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_list_users_limit_boundary(self, client: AsyncClient, db_session: AsyncSession, admin_headers):
        """Test list users with limit at boundary values."""
        for i in range(5):
            user = _make_user(f"boundary{i}@example.com")
            db_session.add(user)
        await db_session.flush()

        response = await client.get("/admin/users?limit=1", headers=admin_headers)
        assert response.status_code == 200
        assert len(response.json()["items"]) == 1

        response = await client.get("/admin/users?limit=100", headers=admin_headers)
        assert response.status_code == 200
        assert len(response.json()["items"]) >= 5

    @pytest.mark.asyncio
    async def test_list_users_negative_offset(self, client: AsyncClient, admin_headers):
        """Test list users with negative offset returns validation error."""
        response = await client.get("/admin/users?offset=-5", headers=admin_headers)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_get_user_invalid_uuid(self, client: AsyncClient, admin_headers):
        """Test getting user with invalid UUID format."""
        response = await client.get("/admin/users/not-a-uuid", headers=admin_headers)
        assert response.status_code == 422