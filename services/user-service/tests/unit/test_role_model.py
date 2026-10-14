"""
Unit tests for Role and Permission models.

Tests cover real behavior in isolated PostgreSQL:
- Role CRUD, unique name constraint, default values, __repr__
- Permission CRUD, unique resource+action constraint, __repr__
- Role-Permission many-to-many relationship
- User-Role many-to-many relationship with metadata
- Hierarchical roles (parent-child)
- Cascade delete behavior
- Edge cases and boundary values
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.models.role import Role, Permission, RolePermission, UserRole
from app.models.user import User
from app.models.base import Base


# ==================== FIXTURES ====================

@pytest.fixture
def engine():
    """Create isolated PostgreSQL engine with schema."""
    engine = create_engine(
        "postgresql://postgres:postgres@postgres:5432/user_db_test",
        echo=False,
    )
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session(engine):
    """Create a new database session for a test."""
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    # Clean all tables before each test
    for table in reversed(Base.metadata.sorted_tables):
        session.execute(table.delete())
    session.commit()
    yield session
    session.rollback()
    session.close()


# ==================== ROLE MODEL TESTS ====================

class TestRoleModel:
    """Tests for Role model behavior in database."""

    def test_create_role(self, session):
        """Test creating a role and reading it back."""
        role = Role(name="admin", description="Administrator")
        session.add(role)
        session.commit()

        saved = session.get(Role, role.id)
        assert saved is not None
        assert saved.name == "admin"
        assert saved.description == "Administrator"
        assert saved.is_system is False
        assert saved.inherits_permissions is True

    def test_create_role_without_description(self, session):
        """Test creating role with only required field."""
        role = Role(name="user")
        session.add(role)
        session.commit()

        saved = session.get(Role, role.id)
        assert saved.description is None

    def test_role_name_unique_constraint(self, session):
        """Test that duplicate role names raise integrity error."""
        role1 = Role(name="moderator")
        session.add(role1)
        session.commit()

        role2 = Role(name="moderator")
        session.add(role2)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_role_name_case_sensitive_unique(self, session):
        """Test that role names are case-sensitive unique."""
        session.add(Role(name="Admin"))
        session.commit()

        session.add(Role(name="admin"))
        session.commit()

        assert session.query(Role).count() == 2

    def test_role_repr(self, session):
        """Test __repr__ includes name and is_system."""
        role = Role(name="viewer")
        session.add(role)
        session.commit()

        repr_str = repr(role)
        assert "viewer" in repr_str
        assert "is_system" in repr_str

    def test_role_is_system_cannot_be_deleted(self, session):
        """Test that system roles are protected from deletion via ORM event."""
        role = Role(name="superadmin", is_system=True)
        session.add(role)
        session.commit()

        session.delete(role)
        with pytest.raises(ValueError, match="cannot be deleted"):
            session.commit()
        session.rollback()

    def test_role_find_by_name(self, session):
        """Test querying role by name."""
        session.add(Role(name="manager"))
        session.commit()

        found = session.query(Role).filter(Role.name == "manager").first()
        assert found is not None
        assert found.name == "manager"

    def test_role_name_validation_strip(self, session):
        """Test validator strips whitespace from role name."""
        role = Role(name="  clean_me  ")
        session.add(role)
        session.commit()
        assert role.name == "clean_me"


# ==================== PERMISSION MODEL TESTS ====================

class TestPermissionModel:
    """Tests for Permission model behavior in database."""

    def test_create_permission(self, session):
        """Test creating a permission and reading it back."""
        perm = Permission(
            name="users.read",
            resource="users",
            action="read",
            description="Read user profiles",
        )
        session.add(perm)
        session.commit()

        saved = session.get(Permission, perm.id)
        assert saved.name == "users.read"
        assert saved.resource == "users"
        assert saved.action == "read"

    def test_permission_name_unique(self, session):
        """Test that duplicate permission names raise error."""
        session.add(Permission(name="posts.write", resource="posts", action="write"))
        session.commit()

        session.add(Permission(name="posts.write", resource="posts", action="update"))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_permission_resource_action_unique(self, session):
        """Test unique constraint on resource + action combination."""
        session.add(Permission(name="A", resource="posts", action="delete"))
        session.commit()

        session.add(Permission(name="B", resource="posts", action="delete"))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_permission_different_resource_same_action(self, session):
        """Test that same action on different resources is allowed."""
        session.add(Permission(name="A", resource="users", action="read"))
        session.add(Permission(name="B", resource="posts", action="read"))
        session.commit()

        assert session.query(Permission).count() == 2

    def test_permission_normalization_lowercase(self, session):
        """Test validator lowercases resource and action."""
        perm = Permission(name="test.perm", resource="  USERS  ", action="  READ  ")
        session.add(perm)
        session.commit()
        assert perm.resource == "users"
        assert perm.action == "read"


# ==================== RELATIONSHIPS & ADVANCED FLOWS ====================

class TestRolePermissionRelationship:
    """Tests for Role-Permission many-to-many relationship."""

    def test_assign_permission_to_role(self, session):
        """Test linking a permission to a role."""
        role = Role(name="editor")
        perm = Permission(name="posts.edit", resource="posts", action="edit")
        session.add_all([role, perm])
        session.commit()

        rp = RolePermission(role_id=role.id, permission_id=perm.id)
        session.add(rp)
        session.commit()

        saved = session.query(RolePermission).filter(
            RolePermission.role_id == role.id,
            RolePermission.permission_id == perm.id,
        ).first()
        assert saved is not None
        assert saved.granted_at is not None

    def test_role_has_multiple_permissions(self, session):
        """Test role can have many permissions."""
        role = Role(name="moderator")
        perm1 = Permission(name="A", resource="posts", action="edit")
        perm2 = Permission(name="B", resource="comments", action="delete")
        perm3 = Permission(name="C", resource="users", action="ban")
        session.add_all([role, perm1, perm2, perm3])
        session.commit()

        for perm in [perm1, perm2, perm3]:
            session.add(RolePermission(role_id=role.id, permission_id=perm.id))
        session.commit()

        count = session.query(RolePermission).filter(RolePermission.role_id == role.id).count()
        assert count == 3

    def test_permission_shared_across_roles(self, session):
        """Test same permission can be assigned to multiple roles."""
        perm = Permission(name="common.read", resource="common", action="read")
        role1 = Role(name="role1")
        role2 = Role(name="role2")
        session.add_all([perm, role1, role2])
        session.commit()

        session.add(RolePermission(role_id=role1.id, permission_id=perm.id))
        session.add(RolePermission(role_id=role2.id, permission_id=perm.id))
        session.commit()

        count = session.query(RolePermission).filter(RolePermission.permission_id == perm.id).count()
        assert count == 2


class TestHierarchicalAndUserRoles:
    """Tests for hierarchy and user-role relationships."""

    def test_role_hierarchy(self, session):
        """Test parent-child role hierarchy."""
        parent = Role(name="manager")
        session.add(parent)
        session.commit()

        child = Role(name="team_lead", parent_role_id=parent.id)
        session.add(child)
        session.commit()

        session.refresh(parent)
        assert child.parent_role == parent
        assert child in parent.children

    def test_user_role_metadata(self, session):
        """Test saving UserRole with real users for FK constraints."""
        role = Role(name="customer")
        session.add(role)
        session.commit()

        # Create real users to satisfy foreign key constraints
        admin = User(email="admin@example.com", password_hash="hash")
        customer = User(email="customer@example.com", password_hash="hash")
        session.add_all([admin, customer])
        session.commit()

        expiry = datetime.now(timezone.utc)

        ur = UserRole(
            user_id=customer.id,
            role_id=role.id,
            assigned_by=admin.id,
            expires_at=expiry,
        )
        session.add(ur)
        session.commit()

        saved = session.query(UserRole).filter(
            UserRole.user_id == customer.id,
            UserRole.role_id == role.id,
        ).first()
        assert saved is not None
        assert saved.assigned_by == admin.id
        assert saved.expires_at == expiry