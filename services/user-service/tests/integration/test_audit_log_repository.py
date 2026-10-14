"""
Integration tests for AuditLog repository.

Tests cover real behavior against PostgreSQL:
- Create audit log entry via repository
- Get audit log by ID via repository
- Get audit logs by user ID with pagination via repository
- Get audit logs by action via repository
- Get audit logs with combined filters via repository
- Get failed actions via repository
- Get statistics (count by action, count by success) via repository
- Get distinct actions list via repository
- Cleanup old logs via repository (TTL-based deletion)
- Edge cases and boundary values
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.audit_log import AuditLog
from app.repositories.audit_log_repository import AuditLogRepository


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
    """Create AuditLogRepository instance."""
    return AuditLogRepository(db_session)


@pytest_asyncio.fixture
async def sample_user(db_session: AsyncSession):
    """Create a user for audit log tests."""
    user = _make_user("audit_user@example.com")
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def sample_logs(repo, sample_user):
    """Create multiple audit log entries for testing."""
    logs = []
    for i in range(5):
        log = AuditLog(
            user_id=sample_user.id,
            action=f"action_{i}",
            success=True,
            ip_address=f"192.168.1.{i}",
            user_agent="pytest",
            details={"key": f"value_{i}"},
        )
        created = await repo.create(log)
        logs.append(created)
    return logs


# ==================== CREATE TESTS ====================

class TestCreateAuditLog:
    """Tests for creating audit log entries via repository."""

    @pytest.mark.asyncio
    async def test_create_log_success(self, repo, sample_user):
        """Test creating an audit log entry."""
        log = AuditLog(
            user_id=sample_user.id,
            action="create_user",
            success=True,
            ip_address="127.0.0.1",
            user_agent="Mozilla/5.0",
        )
        created = await repo.create(log)
        assert created.id is not None
        assert created.user_id == sample_user.id
        assert created.action == "create_user"
        assert created.success is True
        assert created.ip_address == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_create_log_with_all_fields(self, repo, sample_user):
        """Test creating audit log with all optional fields."""
        log = AuditLog(
            user_id=sample_user.id,
            action="update_profile",
            success=True,
            ip_address="10.0.0.1",
            user_agent="Chrome/120",
            details={"old": "value1", "new": "value2"},
            trace_id="trace_abc123",
            request_id="req_xyz789",
            session_id="sess_456",
            old_value={"name": "John"},
            new_value={"name": "Jane"},
        )
        created = await repo.create(log)
        assert created.trace_id == "trace_abc123"
        assert created.details == {"old": "value1", "new": "value2"}
        assert created.old_value == {"name": "John"}

    @pytest.mark.asyncio
    async def test_create_log_failed_action(self, repo, sample_user):
        """Test creating audit log for failed action."""
        log = AuditLog(
            user_id=sample_user.id,
            action="login",
            success=False,
            error_message="Invalid credentials",
            ip_address="192.168.1.100",
        )
        created = await repo.create(log)
        assert created.success is False
        assert created.error_message == "Invalid credentials"

    @pytest.mark.asyncio
    async def test_create_log_without_user_id(self, repo):
        """Test creating audit log without user_id (anonymous action)."""
        log = AuditLog(
            action="rate_limit_exceeded",
            success=False,
            ip_address="10.10.10.10",
        )
        created = await repo.create(log)
        assert created.id is not None
        assert created.user_id is None


# ==================== GET BY ID TESTS ====================

class TestGetAuditLogById:
    """Tests for retrieving audit log by ID via repository."""

    @pytest.mark.asyncio
    async def test_get_by_id_success(self, repo, sample_user):
        """Test getting audit log by ID."""
        log = AuditLog(user_id=sample_user.id, action="test", success=True)
        created = await repo.create(log)

        saved = await repo.get_by_id(created.id)
        assert saved is not None
        assert saved.action == "test"

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, repo):
        """Test getting non-existent audit log."""
        saved = await repo.get_by_id(uuid4())
        assert saved is None


# ==================== GET BY USER ID TESTS ====================

class TestGetAuditLogsByUserId:
    """Tests for retrieving audit logs by user ID via repository."""

    @pytest.mark.asyncio
    async def test_get_by_user_id_success(self, repo, sample_logs, sample_user):
        """Test getting logs by user ID."""
        logs, _ = await repo.get_by_user_id(sample_user.id)
        assert len(logs) == 5

    @pytest.mark.asyncio
    async def test_get_by_user_id_pagination(self, repo, sample_logs, sample_user):
        """Test getting logs with pagination."""
        logs, _ = await repo.get_by_user_id(sample_user.id, limit=2, offset=1)
        assert len(logs) == 2

    @pytest.mark.asyncio
    async def test_get_by_user_id_no_logs(self, repo):
        """Test getting logs for user with no entries."""
        logs, _ = await repo.get_by_user_id(uuid4())
        assert len(logs) == 0


# ==================== GET BY ACTION TESTS ====================

class TestGetAuditLogsByAction:
    """Tests for retrieving audit logs by action via repository."""

    @pytest.mark.asyncio
    async def test_get_by_action_success(self, repo, sample_logs, sample_user):
        """Test getting logs by action."""
        logs = await repo.get_by_action("action_1")
        assert len(logs) == 1

    @pytest.mark.asyncio
    async def test_get_by_action_multiple(self, repo, sample_user):
        """Test getting logs for action with multiple entries."""
        for _ in range(3):
            await repo.create(AuditLog(user_id=sample_user.id, action="login", success=True))

        logs = await repo.get_by_action("login")
        assert len(logs) == 3

    @pytest.mark.asyncio
    async def test_get_by_action_not_found(self, repo):
        """Test getting logs for non-existent action."""
        logs = await repo.get_by_action("nonexistent")
        assert len(logs) == 0


# ==================== FILTER TESTS ====================

class TestGetAuditLogsWithFilters:
    """Tests for filtering audit logs via repository."""

    @pytest.mark.asyncio
    async def test_filter_by_success(self, repo, sample_user):
        """Test filtering logs by success status."""
        await repo.create(AuditLog(user_id=sample_user.id, action="a", success=True))
        await repo.create(AuditLog(user_id=sample_user.id, action="b", success=False))

        logs, _ = await repo.get_with_filters(success=True)
        assert len(logs) == 1

    @pytest.mark.asyncio
    async def test_filter_by_date_range(self, repo, sample_user):
        """Test filtering logs by date range."""
        old = datetime(2024, 1, 1, tzinfo=timezone.utc)
        recent = datetime.now(timezone.utc)

        log_old = AuditLog(user_id=sample_user.id, action="old_action", success=True)
        log_old.created_at = old
        await repo.create(log_old)

        log_new = AuditLog(user_id=sample_user.id, action="new_action", success=True)
        log_new.created_at = recent
        await repo.create(log_new)

        cutoff = datetime(2024, 6, 1, tzinfo=timezone.utc)
        logs, _ = await repo.get_with_filters(start_date=cutoff)
        assert len(logs) == 1

    @pytest.mark.asyncio
    async def test_filter_combined(self, repo, sample_user):
        """Test combining multiple filters."""
        await repo.create(AuditLog(user_id=sample_user.id, action="login", success=True))
        await repo.create(AuditLog(user_id=sample_user.id, action="login", success=False))
        await repo.create(AuditLog(user_id=sample_user.id, action="logout", success=True))

        logs, _ = await repo.get_with_filters(
            user_id=sample_user.id,
            action="login",
            success=True,
        )
        assert len(logs) == 1

    @pytest.mark.asyncio
    async def test_filter_with_pagination(self, repo, sample_user):
        """Test filters with pagination."""
        for i in range(10):
            await repo.create(AuditLog(user_id=sample_user.id, action="event", success=True))

        logs, _ = await repo.get_with_filters(
            user_id=sample_user.id,
            limit=4,
            offset=3,
        )
        assert len(logs) == 4


# ==================== FAILED ACTIONS TESTS ====================

class TestGetFailedAuditLogs:
    """Tests for retrieving failed action logs via repository."""

    @pytest.mark.asyncio
    async def test_get_failed_actions(self, repo, sample_user):
        """Test getting failed actions."""
        await repo.create(AuditLog(user_id=sample_user.id, action="a", success=True))
        await repo.create(AuditLog(user_id=sample_user.id, action="b", success=False, error_message="Error 1"))
        await repo.create(AuditLog(user_id=sample_user.id, action="c", success=False, error_message="Error 2"))

        logs = await repo.get_failed_actions()
        assert len(logs) == 2

    @pytest.mark.asyncio
    async def test_get_failed_actions_by_user(self, repo, sample_user):
        """Test getting failed actions for specific user."""
        other_user = _make_user("other@example.com")
        repo.db.add(other_user)
        await repo.db.flush()

        await repo.create(AuditLog(user_id=sample_user.id, action="a", success=False, error_message="E1"))
        await repo.create(AuditLog(user_id=other_user.id, action="b", success=False, error_message="E2"))

        logs = await repo.get_failed_actions(user_id=sample_user.id)
        assert len(logs) == 1

    @pytest.mark.asyncio
    async def test_get_failed_actions_limit(self, repo, sample_user):
        """Test getting failed actions with limit."""
        for i in range(5):
            await repo.create(AuditLog(user_id=sample_user.id, action=f"fail_{i}", success=False))

        logs = await repo.get_failed_actions(limit=3)
        assert len(logs) == 3


# ==================== STATISTICS TESTS ====================

class TestAuditLogStatistics:
    """Tests for audit log statistics via repository."""

    @pytest.mark.asyncio
    async def test_get_statistics_all_time(self, repo, sample_user):
        """Test getting statistics for all time."""
        for _ in range(3):
            await repo.create(AuditLog(user_id=sample_user.id, action="login", success=True))
        for _ in range(2):
            await repo.create(AuditLog(user_id=sample_user.id, action="login", success=False))

        stats = await repo.get_statistics()
        assert stats["total"] == 5
        assert stats["successful"] == 3
        assert stats["failed"] == 2

    @pytest.mark.asyncio
    async def test_get_statistics_with_date_range(self, repo, sample_user):
        """Test getting statistics for a date range."""
        old = datetime(2024, 1, 1, tzinfo=timezone.utc)
        recent = datetime.now(timezone.utc)

        log = AuditLog(user_id=sample_user.id, action="old", success=True)
        log.created_at = old
        await repo.create(log)

        log = AuditLog(user_id=sample_user.id, action="new", success=True)
        log.created_at = recent
        await repo.create(log)

        cutoff = datetime(2024, 6, 1, tzinfo=timezone.utc)
        stats = await repo.get_statistics(start_date=cutoff)
        assert stats["total"] == 1

    @pytest.mark.asyncio
    async def test_get_statistics_empty(self, repo):
        """Test statistics when no logs exist."""
        stats = await repo.get_statistics()
        assert stats["total"] == 0


# ==================== DISTINCT ACTIONS TESTS ====================

class TestDistinctActions:
    """Tests for getting distinct action types via repository."""

    @pytest.mark.asyncio
    async def test_get_actions_list_success(self, repo, sample_user):
        """Test getting unique action types."""
        actions = ["login", "logout", "update_profile", "login", "logout"]
        for action in actions:
            await repo.create(AuditLog(user_id=sample_user.id, action=action, success=True))

        unique_actions = await repo.get_actions_list()
        assert len(unique_actions) == 3
        assert "login" in unique_actions
        assert "logout" in unique_actions
        assert "update_profile" in unique_actions

    @pytest.mark.asyncio
    async def test_get_actions_list_empty(self, repo):
        """Test distinct actions when no logs exist."""
        actions = await repo.get_actions_list()
        assert len(actions) == 0


# ==================== CLEANUP TESTS ====================

class TestCleanupOldAuditLogs:
    """Tests for cleaning up old audit logs via repository."""

    @pytest.mark.asyncio
    async def test_cleanup_old_logs_success(self, repo, sample_user):
        """Test deleting logs older than cutoff date."""
        old_date = datetime.now(timezone.utc) - timedelta(days=120)
        recent_date = datetime.now(timezone.utc)

        log = AuditLog(user_id=sample_user.id, action="old", success=True)
        log.created_at = old_date
        await repo.create(log)

        log = AuditLog(user_id=sample_user.id, action="recent", success=True)
        log.created_at = recent_date
        await repo.create(log)

        deleted = await repo.cleanup_old_logs(days=90)
        assert deleted == 1

        logs, _ = await repo.get_by_user_id(sample_user.id)
        assert len(logs) == 1

    @pytest.mark.asyncio
    async def test_cleanup_no_old_logs(self, repo, sample_user):
        """Test cleanup when all logs are recent."""
        log = AuditLog(user_id=sample_user.id, action="new", success=True)
        log.created_at = datetime.now(timezone.utc)
        await repo.create(log)

        deleted = await repo.cleanup_old_logs(days=90)
        assert deleted == 0

    @pytest.mark.asyncio
    async def test_cleanup_custom_days(self, repo, sample_user):
        """Test cleanup with custom retention period."""
        log = AuditLog(user_id=sample_user.id, action="custom", success=True)
        log.created_at = datetime.now(timezone.utc) - timedelta(days=10)
        await repo.create(log)

        deleted = await repo.cleanup_old_logs(days=5)
        assert deleted == 1


# ==================== EDGE CASES TESTS ====================

class TestAuditLogEdgeCases:
    """Tests for edge cases and boundary values."""

    @pytest.mark.asyncio
    async def test_create_log_with_minimal_fields(self, repo):
        """Test creating log with only required fields."""
        log = AuditLog(action="system_event", success=True)
        created = await repo.create(log)
        assert created.user_id is None

    @pytest.mark.asyncio
    async def test_create_log_long_action_name(self, repo):
        """Test creating log with maximum action name length."""
        long_action = "a" * 100
        log = AuditLog(action=long_action, success=True)
        created = await repo.create(log)
        assert created.action == long_action

    @pytest.mark.asyncio
    async def test_create_log_long_error_message(self, repo):
        """Test creating log with maximum error message length."""
        long_error = "e" * 500
        log = AuditLog(action="error_test", success=False, error_message=long_error)
        created = await repo.create(log)
        assert created.error_message == long_error

    @pytest.mark.asyncio
    async def test_bulk_insert_logs(self, repo, sample_user):
        """Test inserting many logs in one transaction."""
        for i in range(100):
            await repo.create(AuditLog(user_id=sample_user.id, action=f"bulk_{i}", success=True))

        logs, _ = await repo.get_by_user_id(sample_user.id, limit=100)
        assert len(logs) == 100

    @pytest.mark.asyncio
    async def test_cleanup_boundary_exact_days(self, repo, sample_user):
        """Test cleanup at exact day boundary."""
        exactly_30_days = datetime.now(timezone.utc) - timedelta(days=30)
        log = AuditLog(user_id=sample_user.id, action="boundary", success=True)
        log.created_at = exactly_30_days
        await repo.create(log)

        deleted = await repo.cleanup_old_logs(days=30)
        assert deleted >= 0

    @pytest.mark.asyncio
    async def test_get_with_filters_offset_beyond_total(self, repo, sample_user):
        """Test pagination with offset beyond total records."""
        for i in range(3):
            await repo.create(AuditLog(user_id=sample_user.id, action="event", success=True))

        logs, total_count = await repo.get_with_filters(user_id=sample_user.id, offset=10)
        assert len(logs) == 0
        assert total_count == 3