"""
Integration tests for Role repository.

Tests cover real behavior against PostgreSQL:
- Create role
- Get role by ID
- Get role by name
- List all roles
- Update role
- Delete role (cascade to role_permissions and user_roles)
- Get roles by user ID
- Assign permission to role
- Remove permission from role
- Get role permissions
- Get roles with permissions
- Hierarchical roles (parent-child)
- Edge cases and boundary values
"""

from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.role import Role, Permission, RolePermission, UserRole
from app.repositories.role_repository import RoleRepository


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


@pytest_asyncio.fixture
async def repo(db_session: AsyncSession):
    """Create RoleRepository instance."""
    return RoleRepository(db_session)


@pytest_asyncio.fixture
async def sample_role(repo):
    """Create a basic role."""
    role = Role(name="admin", description="Administrator")
    return await repo.create(role)


@pytest_asyncio.fixture
async def sample_permission(repo):
    """Create a basic permission via repository."""
    perm = Permission(name="users.read", resource="users", action="read")
    db = repo.db
    db.add(perm)
    await db.flush()
    return perm


# ==================== CREATE TESTS ====================

class TestCreateRole:
    """Tests for creating roles."""

    @pytest.mark.asyncio
    async def test_create_role_success(self, repo):
        """Test creating a role."""
        role = Role(name="moderator", description="Content moderator")
        created = await repo.create(role)

        assert created.id is not None
        assert created.name == "moderator"
        assert created.description == "Content moderator"
        assert created.is_system is False
        assert created.inherits_permissions is True

    @pytest.mark.asyncio
    async def test_create_role_minimal(self, repo):
        """Test creating role with only required field."""
        role = Role(name="user")
        created = await repo.create(role)

        assert created.name == "user"
        assert created.description is None

    @pytest.mark.asyncio
    async def test_create_role_duplicate_name(self, repo, sample_role):
        """Test creating role with duplicate name."""
        duplicate = Role(name="admin")
        with pytest.raises(IntegrityError):
            await repo.create(duplicate)

    @pytest.mark.asyncio
    async def test_create_role_system(self, repo):
        """Test creating system role."""
        role = Role(name="superadmin", is_system=True)
        created = await repo.create(role)

        assert created.is_system is True

    @pytest.mark.asyncio
    async def test_create_role_with_parent(self, repo, sample_role):
        """Test creating role with parent for hierarchy."""
        child = Role(name="team_lead", parent_role_id=sample_role.id)
        created = await repo.create(child)

        assert created.parent_role_id == sample_role.id


# ==================== GET TESTS ====================

class TestGetRole:
    """Tests for retrieving roles."""

    @pytest.mark.asyncio
    async def test_get_by_id_success(self, repo, sample_role):
        """Test getting role by ID."""
        found = await repo.get_by_id(sample_role.id)
        assert found is not None
        assert found.name == "admin"

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, repo):
        """Test getting non-existent role."""
        found = await repo.get_by_id(uuid4())
        assert found is None

    @pytest.mark.asyncio
    async def test_get_by_name_success(self, repo, sample_role):
        """Test getting role by name."""
        found = await repo.get_by_name("admin")
        assert found is not None
        assert found.id == sample_role.id

    @pytest.mark.asyncio
    async def test_get_by_name_not_found(self, repo):
        """Test getting role by non-existent name."""
        found = await repo.get_by_name("nonexistent")
        assert found is None

    @pytest.mark.asyncio
    async def test_list_all(self, repo):
        """Test listing all roles."""
        await repo.create(Role(name="role1"))
        await repo.create(Role(name="role2"))
        await repo.create(Role(name="role3"))

        roles = await repo.list_all()
        assert len(roles) == 3

    @pytest.mark.asyncio
    async def test_list_all_empty(self, repo):
        """Test listing roles when none exist."""
        roles = await repo.list_all()
        assert len(roles) == 0


# ==================== UPDATE TESTS ====================

class TestUpdateRole:
    """Tests for updating roles."""

    @pytest.mark.asyncio
    async def test_update_role_description(self, repo, sample_role):
        """Test updating role description."""
        sample_role.description = "Updated description"
        updated = await repo.update(sample_role)

        assert updated.description == "Updated description"

    @pytest.mark.asyncio
    async def test_update_role_name(self, repo, sample_role):
        """Test updating role name."""
        sample_role.name = "administrator"
        updated = await repo.update(sample_role)

        assert updated.name == "administrator"

    @pytest.mark.asyncio
    async def test_update_role_duplicate_name(self, repo, sample_role):
        """Test updating role to existing name."""
        await repo.create(Role(name="manager"))
        sample_role.name = "manager"

        with pytest.raises(IntegrityError):
            await repo.update(sample_role)


# ==================== DELETE TESTS ====================

class TestDeleteRole:
    """Tests for deleting roles."""

    @pytest.mark.asyncio
    async def test_delete_role_success(self, repo):
        """Test deleting a role."""
        role = await repo.create(Role(name="temp_role"))
        deleted = await repo.delete(role.id)

        assert deleted is True
        found = await repo.get_by_id(role.id)
        assert found is None

    @pytest.mark.asyncio
    async def test_delete_role_not_found(self, repo):
        """Test deleting non-existent role."""
        deleted = await repo.delete(uuid4())
        assert deleted is False

    @pytest.mark.asyncio
    async def test_delete_system_role_raises(self, repo):
        """Test deleting system role raises error."""
        role = await repo.create(Role(name="system_role", is_system=True))

        with pytest.raises(ValueError, match="cannot be deleted"):
            await repo.delete(role.id)

    @pytest.mark.asyncio
    async def test_delete_role_cascades_to_permissions(self, repo, sample_role, sample_permission):
        """Test deleting role removes role_permission associations."""
        db = repo.db
        rp = RolePermission(role_id=sample_role.id, permission_id=sample_permission.id)
        db.add(rp)
        await db.flush()

        await repo.delete(sample_role.id)

        result = await db.execute(
            select(RolePermission).where(RolePermission.role_id == sample_role.id)
        )
        remaining = result.scalars().all()
        assert len(remaining) == 0


# ==================== ROLE-PERMISSION TESTS ====================

class TestRolePermissions:
    """Tests for role-permission associations."""

    @pytest.mark.asyncio
    async def test_assign_permission_to_role(self, repo, sample_role, sample_permission):
        """Test assigning a permission to a role."""
        rp = await repo.assign_permission(sample_role.id, sample_permission.id)
        assert rp is not None
        assert rp.role_id == sample_role.id
        assert rp.permission_id == sample_permission.id

    @pytest.mark.asyncio
    async def test_assign_duplicate_permission(self, repo, sample_role, sample_permission):
        """Test assigning same permission twice raises IntegrityError."""
        await repo.assign_permission(sample_role.id, sample_permission.id)
        with pytest.raises(IntegrityError):
            await repo.assign_permission(sample_role.id, sample_permission.id)
            await repo.db.flush()

    @pytest.mark.asyncio
    async def test_remove_permission_from_role(self, repo, sample_role, sample_permission):
        """Test removing a permission from a role."""
        await repo.assign_permission(sample_role.id, sample_permission.id)
        removed = await repo.remove_permission(sample_role.id, sample_permission.id)
        assert removed is True

    @pytest.mark.asyncio
    async def test_remove_permission_not_assigned(self, repo, sample_role, sample_permission):
        """Test removing non-assigned permission."""
        removed = await repo.remove_permission(sample_role.id, sample_permission.id)
        assert removed is False

    @pytest.mark.asyncio
    async def test_get_role_permissions(self, repo, sample_role):
        """Test getting permissions for a role."""
        db = repo.db
        perm1 = Permission(name="p1", resource="r1", action="read")
        perm2 = Permission(name="p2", resource="r2", action="write")
        db.add_all([perm1, perm2])
        await db.flush()

        await repo.assign_permission(sample_role.id, perm1.id)
        await repo.assign_permission(sample_role.id, perm2.id)

        permissions = await repo.get_role_permissions(sample_role.id)
        assert len(permissions) == 2

    @pytest.mark.asyncio
    async def test_get_role_permissions_empty(self, repo, sample_role):
        """Test getting permissions for role with none."""
        permissions = await repo.get_role_permissions(sample_role.id)
        assert len(permissions) == 0


# ==================== USER-ROLE TESTS ====================

class TestUserRoles:
    """Tests for user-role associations."""

    @pytest.mark.asyncio
    async def test_assign_role_to_user(self, repo, sample_role):
        """Test assigning a role to a user."""
        db = repo.db
        user = _make_user("roleuser@example.com")
        db.add(user)
        await db.flush()

        ur = await repo.assign_role_to_user(user.id, sample_role.id)
        assert ur is not None
        assert ur.user_id == user.id
        assert ur.role_id == sample_role.id

    @pytest.mark.asyncio
    async def test_get_roles_by_user_id(self, repo, sample_role):
        """Test getting roles for a user."""
        db = repo.db
        user = _make_user("rolesuser@example.com")
        db.add(user)
        await db.flush()

        await repo.assign_role_to_user(user.id, sample_role.id)

        roles = await repo.get_roles_by_user_id(user.id)
        assert len(roles) == 1
        assert roles[0].name == "admin"

    @pytest.mark.asyncio
    async def test_get_roles_by_user_id_empty(self, repo):
        """Test getting roles for user with none."""
        roles = await repo.get_roles_by_user_id(uuid4())
        assert len(roles) == 0

    @pytest.mark.asyncio
    async def test_remove_role_from_user(self, repo, sample_role):
        """Test removing a role from a user."""
        db = repo.db
        user = _make_user("remove_role@example.com")
        db.add(user)
        await db.flush()

        await repo.assign_role_to_user(user.id, sample_role.id)
        removed = await repo.remove_role_from_user(user.id, sample_role.id)
        assert removed is True

        roles = await repo.get_roles_by_user_id(user.id)
        assert len(roles) == 0

    @pytest.mark.asyncio
    async def test_assign_role_with_expiry(self, repo, sample_role):
        """Test assigning role with expiration."""
        from datetime import datetime, timedelta, timezone

        db = repo.db
        user = _make_user("expiry@example.com")
        db.add(user)
        await db.flush()

        expires = datetime.now(timezone.utc) + timedelta(days=30)
        ur = await repo.assign_role_to_user(user.id, sample_role.id, expires_at=expires)
        assert ur.expires_at == expires


# ==================== HIERARCHICAL ROLES TESTS ====================

class TestHierarchicalRoles:
    """Tests for role hierarchy."""

    @pytest.mark.asyncio
    async def test_get_child_roles(self, repo, sample_role):
        """Test getting child roles."""
        child1 = await repo.create(Role(name="child1", parent_role_id=sample_role.id))
        child2 = await repo.create(Role(name="child2", parent_role_id=sample_role.id))

        children = await repo.get_child_roles(sample_role.id)
        assert len(children) == 2

    @pytest.mark.asyncio
    async def test_get_child_roles_empty(self, repo, sample_role):
        """Test getting child roles when none exist."""
        children = await repo.get_child_roles(sample_role.id)
        assert len(children) == 0

    @pytest.mark.asyncio
    async def test_get_parent_role(self, repo, sample_role):
        """Test getting parent role."""
        child = await repo.create(Role(name="child", parent_role_id=sample_role.id))

        parent = await repo.get_parent_role(child.id)
        assert parent is not None
        assert parent.id == sample_role.id

    @pytest.mark.asyncio
    async def test_get_parent_role_none(self, repo, sample_role):
        """Test getting parent for root role."""
        parent = await repo.get_parent_role(sample_role.id)
        assert parent is None


# ==================== EDGE CASES TESTS ====================

class TestRoleRepositoryEdgeCases:
    """Tests for edge cases and boundary values."""

    @pytest.mark.asyncio
    async def test_create_role_long_name(self, repo):
        """Test creating role with maximum name length."""
        long_name = "r" * 100
        role = Role(name=long_name)
        created = await repo.create(role)
        assert created.name == long_name

    @pytest.mark.asyncio
    async def test_assign_role_to_multiple_users(self, repo, sample_role):
        """Test assigning same role to many users."""
        db = repo.db
        users = []
        for i in range(10):
            user = _make_user(f"multi{i}@example.com")
            db.add(user)
            users.append(user)
        await db.flush()

        for user in users:
            await repo.assign_role_to_user(user.id, sample_role.id)

        for user in users:
            roles = await repo.get_roles_by_user_id(user.id)
            assert len(roles) == 1

    @pytest.mark.asyncio
    async def test_get_role_by_name_case_sensitive(self, repo):
        """Test role name lookup is case-sensitive."""
        await repo.create(Role(name="Admin"))
        found_lower = await repo.get_by_name("admin")
        found_upper = await repo.get_by_name("Admin")
        assert found_lower is None
        assert found_upper is not None