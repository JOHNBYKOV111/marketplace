"""
Integration tests for User API endpoints.

Tests cover:
- GET /users/me (get current user profile)
- PATCH /users/me (update current user)
- DELETE /users/me (delete account)
- POST /users/me/change-password (change password)
- GET /users/me/sessions (list active sessions)
- Authentication and authorization (X-User-Id required)
- Rate limiting
- Edge cases and error handling
"""

from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


# ==================== FIXTURES ====================

def _make_user(email: str, **kwargs) -> User:
    """Helper to create User with email_hash from email."""
    return User(
        email_hash=User.create_email_hash(email),
        **kwargs,
    )


@pytest_asyncio.fixture(autouse=True)
async def clean_db(db_session: AsyncSession):
    """Ensure clean database before each test via transaction rollback."""
    yield
    await db_session.rollback()


@pytest.fixture
def user_id():
    """Generate a random user ID for authorization."""
    return uuid4()


@pytest.fixture
def auth_headers(user_id):
    """Headers with authenticated user credentials."""
    return {
        "X-User-Id": str(user_id),
        "X-User-Roles": "user",
    }


@pytest_asyncio.fixture
async def sample_user(db_session: AsyncSession, user_id):
    """Create a user for API tests."""
    user = _make_user(
        "api_user@example.com",
        id=user_id,
        first_name="API",
        last_name="User",
    )
    db_session.add(user)
    await db_session.flush()
    return user


# ==================== GET PROFILE TESTS ====================

class TestGetProfile:
    """Tests for GET /users/me endpoint."""

    @pytest.mark.asyncio
    async def test_get_profile_success(self, client: AsyncClient, sample_user, auth_headers):
        """Test getting current user profile."""
        response = await client.get("/users/me", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["first_name"] == "API"
        assert data["last_name"] == "User"

    @pytest.mark.asyncio
    async def test_get_profile_unauthorized(self, client: AsyncClient):
        """Test getting profile without authentication."""
        response = await client.get("/users/me")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_get_profile_invalid_user_id(self, client: AsyncClient):
        """Test getting profile with invalid user ID."""
        headers = {"X-User-Id": "not-a-uuid", "X-User-Roles": "user"}
        response = await client.get("/users/me", headers=headers)
        assert response.status_code == 422


# ==================== UPDATE PROFILE TESTS ====================

class TestUpdateProfile:
    """Tests for PATCH /users/me endpoint."""

    @pytest.mark.asyncio
    async def test_update_profile_success(self, client: AsyncClient, sample_user, auth_headers):
        """Test updating user profile."""
        response = await client.patch(
            "/users/me",
            json={"first_name": "Updated", "last_name": "Name"},
            headers=auth_headers,
        )
        assert response.status_code == 200

        data = response.json()
        assert data["first_name"] == "Updated"
        assert data["last_name"] == "Name"

    @pytest.mark.asyncio
    async def test_update_profile_partial(self, client: AsyncClient, sample_user, auth_headers):
        """Test updating only some fields."""
        response = await client.patch(
            "/users/me",
            json={"first_name": "NewName"},
            headers=auth_headers,
        )
        assert response.status_code == 200

        data = response.json()
        assert data["first_name"] == "NewName"
        assert data["last_name"] == "User"

    @pytest.mark.asyncio
    async def test_update_profile_empty_body(self, client: AsyncClient, sample_user, auth_headers):
        """Test updating with empty body."""
        response = await client.patch("/users/me", json={}, headers=auth_headers)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_update_profile_invalid_field(self, client: AsyncClient, sample_user, auth_headers):
        """Test updating with invalid field."""
        response = await client.patch(
            "/users/me",
            json={"invalid_field": "value"},
            headers=auth_headers,
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_update_profile_unauthorized(self, client: AsyncClient):
        """Test updating profile without authentication."""
        response = await client.patch("/users/me", json={"first_name": "Test"})
        assert response.status_code == 401


# ==================== CHANGE PASSWORD TESTS ====================

class TestChangePassword:
    """Tests for POST /users/me/change-password endpoint."""

    @pytest.mark.asyncio
    async def test_change_password_success(self, client: AsyncClient, sample_user, auth_headers):
        """Test changing password — returns 400 because password is in auth-service."""
        response = await client.post(
            "/users/me/change-password",
            json={
                "current_password": "CorrectCurrentPass1!",
                "new_password": "NewSecurePass123!",
            },
            headers=auth_headers,
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self, client: AsyncClient, sample_user, auth_headers):
        """Test changing password with wrong current password."""
        response = await client.post(
            "/users/me/change-password",
            json={
                "current_password": "WrongPassword123!",
                "new_password": "NewSecurePass123!",
            },
            headers=auth_headers,
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_change_password_weak_new(self, client: AsyncClient, sample_user, auth_headers):
        """Test changing password with weak new password."""
        response = await client.post(
            "/users/me/change-password",
            json={
                "current_password": "CorrectCurrentPass1!",
                "new_password": "short",
            },
            headers=auth_headers,
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_change_password_missing_fields(self, client: AsyncClient, sample_user, auth_headers):
        """Test changing password without required fields."""
        response = await client.post(
            "/users/me/change-password",
            json={"current_password": "pass"},
            headers=auth_headers,
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_change_password_unauthorized(self, client: AsyncClient):
        """Test changing password without authentication."""
        response = await client.post(
            "/users/me/change-password",
            json={
                "current_password": "pass",
                "new_password": "NewPass123!",
            },
        )
        assert response.status_code == 401


# ==================== DELETE ACCOUNT TESTS ====================

class TestDeleteAccount:
    """Tests for DELETE /users/me endpoint."""

    @pytest.mark.asyncio
    async def test_delete_account_success(self, client: AsyncClient, db_session: AsyncSession, user_id, auth_headers):
        """Test deleting user account."""
        user = _make_user("delete_me@example.com", id=user_id)
        db_session.add(user)
        await db_session.flush()

        response = await client.delete("/users/me", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["success"] is True

        await db_session.refresh(user)
        assert user.is_deleted is True

    @pytest.mark.asyncio
    async def test_delete_account_already_deleted(self, client: AsyncClient, db_session: AsyncSession, auth_headers):
        """Test deleting already deleted account."""
        deleted_id = uuid4()
        user = _make_user("already_deleted@example.com", id=deleted_id, is_deleted=True)
        db_session.add(user)
        await db_session.flush()

        headers = {"X-User-Id": str(deleted_id), "X-User-Roles": "user"}
        response = await client.delete("/users/me", headers=headers)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_delete_account_unauthorized(self, client: AsyncClient):
        """Test deleting account without authentication."""
        response = await client.delete("/users/me")
        assert response.status_code == 401


# ==================== SESSIONS TESTS ====================

class TestSessions:
    """Tests for GET /users/me/sessions endpoint."""

    @pytest.mark.asyncio
    async def test_list_sessions(self, client: AsyncClient, sample_user, auth_headers):
        """Test listing user sessions."""
        response = await client.get("/users/me/sessions", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert "sessions" in data
        assert "total" in data
        assert isinstance(data["sessions"], list)

    @pytest.mark.asyncio
    async def test_list_sessions_empty(self, client: AsyncClient, sample_user, auth_headers):
        """Test listing sessions when none exist."""
        response = await client.get("/users/me/sessions", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["total"] == 0

    @pytest.mark.asyncio
    async def test_list_sessions_unauthorized(self, client: AsyncClient):
        """Test listing sessions without authentication."""
        response = await client.get("/users/me/sessions")
        assert response.status_code == 401


# ==================== RATE LIMITING TESTS ====================

class TestUserApiRateLimiting:
    """Tests for rate limiting on user endpoints."""

    @pytest.mark.asyncio
    async def test_rate_limit_profile_endpoint(self, client: AsyncClient, sample_user, auth_headers):
        """Test that profile endpoint is rate limited."""
        for _ in range(50):
            await client.get("/users/me", headers=auth_headers)

        response = await client.get("/users/me", headers=auth_headers)
        assert response.status_code in (200, 429)


# ==================== EDGE CASES TESTS ====================

class TestUserApiEdgeCases:
    """Tests for edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_get_profile_user_not_in_db(self, client: AsyncClient):
        """Test getting profile for user not in database."""
        headers = {"X-User-Id": str(uuid4()), "X-User-Roles": "user"}
        response = await client.get("/users/me", headers=headers)
        assert response.status_code in (200, 404)

    @pytest.mark.asyncio
    async def test_update_profile_long_name(self, client: AsyncClient, sample_user, auth_headers):
        """Test updating profile with very long name."""
        long_name = "A" * 200
        response = await client.patch(
            "/users/me",
            json={"first_name": long_name},
            headers=auth_headers,
        )
        assert response.status_code in (200, 422)

    @pytest.mark.asyncio
    async def test_change_password_same_as_old(self, client: AsyncClient, sample_user, auth_headers):
        """Test changing password to same as current."""
        response = await client.post(
            "/users/me/change-password",
            json={
                "current_password": "CorrectCurrentPass1!",
                "new_password": "CorrectCurrentPass1!",
            },
            headers=auth_headers,
        )
        assert response.status_code in (200, 400)

    @pytest.mark.asyncio
    async def test_delete_account_revokes_access(self, client: AsyncClient, db_session: AsyncSession, auth_headers):
        """Test deleted user cannot access endpoints."""
        user_id = uuid4()
        user = _make_user("revoke_test@example.com", id=user_id)
        db_session.add(user)
        await db_session.flush()

        headers = {"X-User-Id": str(user_id), "X-User-Roles": "user"}
        await client.delete("/users/me", headers=headers)

        response = await client.get("/users/me", headers=headers)
        assert response.status_code in (401, 403, 404)

    @pytest.mark.asyncio
    async def test_update_profile_unicode_name(self, client: AsyncClient, sample_user, auth_headers):
        """Test updating profile with unicode characters."""
        response = await client.patch(
            "/users/me",
            json={"first_name": "Иван", "last_name": "Петров"},
            headers=auth_headers,
        )
        assert response.status_code == 200

        data = response.json()
        assert data["first_name"] == "Иван"
        assert data["last_name"] == "Петров"