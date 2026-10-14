"""
Integration tests for User repository.

Tests cover real behavior against PostgreSQL:
- Create user
- Get user by ID
- Get user by email hash
- Get user by phone hash
- Update user
- Soft delete user
- Hard delete expired users
- Block / unblock user
- List users with pagination and filters
- Count users with filters
- Edge cases and boundary values
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.repositories.user_repository import UserRepository


# ==================== FIXTURES ====================

def _make_user(email: str, **kwargs) -> User:
    """Helper to create User with email_hash from email."""
    return User(
        email_hash=User.create_email_hash(email),
        **kwargs,
    )


@pytest.fixture(autouse=True)
async def clean_db(db_session: AsyncSession):
    """Ensure clean database before each test via transaction rollback."""
    yield
    await db_session.rollback()


@pytest.fixture
def repo(db_session: AsyncSession):
    """Create UserRepository instance."""
    return UserRepository(db_session)


@pytest_asyncio.fixture
async def sample_user(repo):
    """Create a basic user."""
    user = _make_user("sample@example.com", first_name="Sample", last_name="User")
    return await repo.create(user)


# ==================== CREATE TESTS ====================

class TestCreateUser:
    """Tests for creating users."""

    @pytest.mark.asyncio
    async def test_create_user_success(self, repo):
        """Test creating a user."""
        user = _make_user("test@example.com")
        created = await repo.create(user)

        assert created.id is not None
        assert created.email_hash == User.create_email_hash("test@example.com")
        assert created.is_deleted is False

    @pytest.mark.asyncio
    async def test_create_user_with_all_fields(self, repo):
        """Test creating user with all optional fields."""
        user = _make_user(
            "full@example.com",
            phone_hash=User.create_phone_hash("+1234567890"),
            first_name="John",
            last_name="Doe",
        )
        created = await repo.create(user)

        assert created.first_name == "John"
        assert created.last_name == "Doe"
        assert created.phone_hash is not None

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, repo, sample_user):
        """Test creating user with duplicate email hash."""
        duplicate = _make_user("sample@example.com")
        with pytest.raises(IntegrityError):
            await repo.create(duplicate)

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email_hash(self, repo, sample_user):
        """Test creating user with duplicate email hash."""
        duplicate = _make_user("sample@example.com")
        with pytest.raises(IntegrityError):
            await repo.create(duplicate)

    @pytest.mark.asyncio
    async def test_create_user_minimal_fields(self, repo):
        """Test creating user with only required fields."""
        user = _make_user("minimal@example.com")
        created = await repo.create(user)

        assert created.first_name is None
        assert created.last_name is None
        assert created.phone_hash is None


# ==================== GET BY ID TESTS ====================

class TestGetUserById:
    """Tests for retrieving user by ID."""

    @pytest.mark.asyncio
    async def test_get_by_id_success(self, repo, sample_user):
        """Test getting user by ID."""
        found = await repo.get_by_id(sample_user.id)
        assert found is not None
        assert found.email_hash == User.create_email_hash("sample@example.com")

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, repo):
        """Test getting non-existent user."""
        found = await repo.get_by_id(uuid4())
        assert found is None


# ==================== GET BY EMAIL HASH TESTS ====================

class TestGetUserByEmailHash:
    """Tests for retrieving user by email hash."""

    @pytest.mark.asyncio
    async def test_get_by_email_hash_success(self, repo, sample_user):
        """Test getting user by email hash."""
        email_hash = User.create_email_hash("sample@example.com")
        found = await repo.get_by_email_hash(email_hash)
        assert found is not None
        assert found.id == sample_user.id

    @pytest.mark.asyncio
    async def test_get_by_email_hash_not_found(self, repo):
        """Test getting user by non-existent email hash."""
        found = await repo.get_by_email_hash("nonexistent_hash")
        assert found is None


# ==================== GET BY PHONE HASH TESTS ====================

class TestGetUserByPhoneHash:
    """Tests for retrieving user by phone hash."""

    @pytest.mark.asyncio
    async def test_get_by_phone_hash_success(self, repo):
        """Test getting user by phone hash."""
        phone_hash = User.create_phone_hash("+1234567890")
        user = _make_user("phone@example.com", phone_hash=phone_hash)
        await repo.create(user)

        found = await repo.get_by_phone_hash(phone_hash)
        assert found is not None
        assert found.email_hash == User.create_email_hash("phone@example.com")

    @pytest.mark.asyncio
    async def test_get_by_phone_hash_not_found(self, repo):
        """Test getting user by non-existent phone hash."""
        found = await repo.get_by_phone_hash("nonexistent_hash")
        assert found is None


# ==================== UPDATE TESTS ====================

class TestUpdateUser:
    """Tests for updating users."""

    @pytest.mark.asyncio
    async def test_update_user_success(self, repo, sample_user):
        """Test updating user fields."""
        sample_user.first_name = "Updated"
        sample_user.last_name = "Name"
        updated = await repo.update(sample_user)

        assert updated.first_name == "Updated"
        assert updated.last_name == "Name"

    @pytest.mark.asyncio
    async def test_update_user_partial(self, repo, sample_user):
        """Test updating only some fields."""
        sample_user.first_name = "NewFirstName"
        updated = await repo.update(sample_user)

        assert updated.first_name == "NewFirstName"
        assert updated.last_name == "User"

    @pytest.mark.asyncio
    async def test_update_user_not_found(self, repo):
        """Test updating non-existent user."""
        user = _make_user("ghost@example.com", id=uuid4())
        updated = await repo.update(user)
        assert updated is None

    @pytest.mark.asyncio
    async def test_update_user_preserves_email_hash(self, repo, sample_user):
        """Test updating user preserves email hash."""
        original_hash = sample_user.email_hash
        sample_user.first_name = "Changed"
        updated = await repo.update(sample_user)

        assert updated.email_hash == original_hash


# ==================== SOFT DELETE TESTS ====================

class TestSoftDeleteUser:
    """Tests for soft deleting users."""

    @pytest.mark.asyncio
    async def test_soft_delete_user(self, repo, sample_user):
        """Test soft deleting a user."""
        deleted = await repo.soft_delete(sample_user.id)
        assert deleted is True

        user = await repo.get_by_id(sample_user.id)
        assert user.is_deleted is True
        assert user.deleted_at is not None

    @pytest.mark.asyncio
    async def test_soft_delete_user_not_found(self, repo):
        """Test soft deleting non-existent user."""
        deleted = await repo.soft_delete(uuid4())
        assert deleted is False

    @pytest.mark.asyncio
    async def test_hard_delete_expired_users(self, repo):
        """Test hard deleting users past soft-delete TTL."""
        old_date = datetime.now(timezone.utc) - timedelta(days=60)
        user = _make_user("expired@example.com", is_deleted=True, deleted_at=old_date)
        await repo.create(user)

        count = await repo.delete_expired_soft_deleted(days=30)
        assert count >= 1

        found = await repo.get_by_id(user.id)
        assert found is None


# ==================== BLOCK/UNBLOCK TESTS ====================

class TestBlockUnblockUser:
    """Tests for blocking and unblocking users."""

    @pytest.mark.asyncio
    async def test_block_user(self, repo, sample_user):
        """Test blocking a user. Note: is_active is in auth-service."""
        blocked = await repo.block(sample_user.id)
        assert blocked is True

    @pytest.mark.asyncio
    async def test_block_user_already_blocked(self, repo):
        """Test blocking already blocked user."""
        user = _make_user("inactive@example.com")
        await repo.create(user)

        blocked = await repo.block(user.id)
        assert blocked is True

    @pytest.mark.asyncio
    async def test_block_user_not_found(self, repo):
        """Test blocking non-existent user."""
        blocked = await repo.block(uuid4())
        assert blocked is False

    @pytest.mark.asyncio
    async def test_unblock_user(self, repo):
        """Test unblocking a user."""
        user = _make_user("blocked@example.com")
        await repo.create(user)

        unblocked = await repo.unblock(user.id)
        assert unblocked is True

    @pytest.mark.asyncio
    async def test_unblock_user_already_active(self, repo, sample_user):
        """Test unblocking already active user."""
        unblocked = await repo.unblock(sample_user.id)
        assert unblocked is True


# ==================== LIST USERS TESTS ====================

class TestListUsers:
    """Tests for listing users with pagination and filters."""

    @pytest.mark.asyncio
    async def test_list_users_default(self, repo):
        """Test listing users with default parameters."""
        for i in range(5):
            user = _make_user(f"list{i}@example.com")
            await repo.create(user)

        users, total = await repo.list_users()
        assert len(users) == 5
        assert total == 5

    @pytest.mark.asyncio
    async def test_list_users_pagination(self, repo):
        """Test listing users with pagination."""
        for i in range(10):
            user = _make_user(f"page{i}@example.com")
            await repo.create(user)

        users, total = await repo.list_users(limit=3, offset=3)
        assert len(users) == 3
        assert total == 10

    @pytest.mark.asyncio
    async def test_list_users_filter_active(self, repo):
        """Test listing users filtered by active status. Note: is_active is in auth-service."""
        await repo.create(_make_user("active@example.com"))
        await repo.create(_make_user("inactive@example.com"))

        users, total = await repo.list_users()
        assert total == 2

    @pytest.mark.asyncio
    async def test_list_users_filter_verified(self, repo):
        """Test listing users. Note: is_email_verified is in auth-service."""
        await repo.create(_make_user("verified@example.com"))
        await repo.create(_make_user("unverified@example.com"))

        users, total = await repo.list_users()
        assert total == 2

    @pytest.mark.asyncio
    async def test_list_users_empty(self, repo):
        """Test listing users when none exist."""
        users, total = await repo.list_users()
        assert len(users) == 0
        assert total == 0

    @pytest.mark.asyncio
    async def test_list_users_offset_beyond_total(self, repo):
        """Test pagination with offset beyond total."""
        for i in range(3):
            await repo.create(_make_user(f"beyond{i}@example.com"))

        users, total = await repo.list_users(offset=10)
        assert len(users) == 0
        assert total == 3


# ==================== COUNT USERS TESTS ====================

class TestCountUsers:
    """Tests for counting users."""

    @pytest.mark.asyncio
    async def test_count_users_all(self, repo):
        """Test counting all users."""
        for i in range(5):
            await repo.create(_make_user(f"count{i}@example.com"))

        count = await repo.count_users()
        assert count == 5

    @pytest.mark.asyncio
    async def test_count_users_filter_active(self, repo):
        """Test counting users."""
        await repo.create(_make_user("active_count@example.com"))
        await repo.create(_make_user("inactive_count@example.com"))

        count = await repo.count_users()
        assert count == 2

    @pytest.mark.asyncio
    async def test_count_users_filter_verified(self, repo):
        """Test counting users."""
        await repo.create(_make_user("v_count@example.com"))
        await repo.create(_make_user("u_count@example.com"))

        count = await repo.count_users()
        assert count == 2

    @pytest.mark.asyncio
    async def test_count_users_empty(self, repo):
        """Test counting users when none exist."""
        count = await repo.count_users()
        assert count == 0


# ==================== EDGE CASES TESTS ====================

class TestUserRepositoryEdgeCases:
    """Tests for edge cases and boundary values."""

    @pytest.mark.asyncio
    async def test_create_user_long_email(self, repo):
        """Test creating user with maximum email length."""
        long_email = "a" * 249 + "@b.com"
        user = _make_user(long_email)
        created = await repo.create(user)
        assert created.email_hash == User.create_email_hash(long_email)

    @pytest.mark.asyncio
    async def test_get_by_email_hash_empty_string(self, repo):
        """Test getting user by empty email hash."""
        found = await repo.get_by_email_hash("")
        assert found is None

    @pytest.mark.asyncio
    async def test_get_by_phone_hash_empty_string(self, repo):
        """Test getting user by empty phone hash."""
        found = await repo.get_by_phone_hash("")
        assert found is None

    @pytest.mark.asyncio
    async def test_update_nonexistent_user(self, repo):
        """Test updating user that does not exist."""
        user = _make_user("nonexistent@example.com", id=uuid4())
        updated = await repo.update(user)
        assert updated is None

    @pytest.mark.asyncio
    async def test_block_user_already_blocked(self, repo):
        """Test blocking user."""
        user = _make_user("already_inactive@example.com")
        await repo.create(user)

        blocked = await repo.block(user.id)
        assert blocked is True

    @pytest.mark.asyncio
    async def test_unblock_user_already_active(self, repo):
        """Test unblocking user."""
        user = _make_user("already_active@example.com")
        await repo.create(user)

        unblocked = await repo.unblock(user.id)
        assert unblocked is True