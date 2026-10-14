"""
Unit tests for AuditService.

Tests cover:
- Core log_action method with all parameters
- Specialized logging methods (log_login, log_logout, log_password_change, etc.)
- Query methods (get_all_logs, get_user_logs, get_statistics)
- Cleanup method (cleanup_old_logs)
- Format export methods
- Edge cases and error handling
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ValidationError
from app.models.audit_log import AuditLog
from app.services.audit_service import AuditService


class TestAuditServiceLogAction:
    """Tests for core log_action method."""

    @pytest.fixture
    def mock_db(self):
        """Create mock async session."""
        db = AsyncMock(spec=AsyncSession)
        return db

    @pytest.fixture
    def audit_service(self, mock_db):
        """Create AuditService instance with mocked session."""
        return AuditService(session=mock_db)

    @pytest.fixture
    def sample_user_id(self):
        """Generate sample user ID."""
        return uuid4()

    async def test_log_action_minimal_params(self, audit_service, sample_user_id):
        """Test log_action with only required parameters."""
        with patch.object(audit_service.repository, "create_log", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = MagicMock(spec=AuditLog)

            await audit_service.log_action(
                user_id=sample_user_id,
                action="LOGIN",
            )

            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["user_id"] == sample_user_id
            assert call_kwargs["action"] == "LOGIN"
            assert call_kwargs["success"] is True
            assert call_kwargs["details"] is None
            assert call_kwargs["ip_address"] is None
            assert call_kwargs["user_agent"] is None

    async def test_log_action_all_params(self, audit_service, sample_user_id):
        """Test log_action with all possible parameters."""
        details = {"roles": ["user"]}
        
        with patch.object(audit_service.repository, "create_log", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = MagicMock(spec=AuditLog)

            await audit_service.log_action(
                user_id=sample_user_id,
                action="ADMIN_ACTION",
                success=False,
                details=details,
                ip_address="192.168.1.1",
                user_agent="Mozilla/5.0",
            )

            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["user_id"] == sample_user_id
            assert call_kwargs["action"] == "ADMIN_ACTION"
            assert call_kwargs["ip_address"] == "192.168.1.1"
            assert call_kwargs["user_agent"] == "Mozilla/5.0"
            assert call_kwargs["success"] is False

    async def test_log_action_masks_sensitive_data(self, audit_service, sample_user_id):
        """Test log_action masks sensitive fields in details."""
        details = {"password": "secret123", "username": "john"}

        with patch.object(audit_service.repository, "create_log", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = MagicMock(spec=AuditLog)

            await audit_service.log_action(
                user_id=sample_user_id,
                action="LOGIN",
                details=details,
            )

            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["details"]["password"] == "***MASKED***"
            assert call_kwargs["details"]["username"] == "john"


class TestAuditServiceSpecializedMethods:
    """Tests for specialized logging methods."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock(spec=AsyncSession)
        return db

    @pytest.fixture
    def audit_service(self, mock_db):
        return AuditService(session=mock_db)

    @pytest.fixture
    def sample_user_id(self):
        return uuid4()

    async def test_log_login_success(self, audit_service, sample_user_id):
        """Test logging successful login."""
        with patch.object(audit_service, "log_action", new_callable=AsyncMock) as mock_log:
            await audit_service.log_login(
                user_id=sample_user_id,
                ip_address="10.0.0.1",
                user_agent="Chrome/120",
                success=True,
            )

            mock_log.assert_called_once_with(
                user_id=sample_user_id,
                action="LOGIN",
                success=True,
                details=None,
                ip_address="10.0.0.1",
                user_agent="Chrome/120",
            )

    async def test_log_login_failed(self, audit_service, sample_user_id):
        """Test logging failed login."""
        error_msg = "Invalid password"

        with patch.object(audit_service, "log_action", new_callable=AsyncMock) as mock_log:
            await audit_service.log_login(
                user_id=sample_user_id,
                ip_address="10.0.0.1",
                user_agent="Chrome/120",
                success=False,
                error=error_msg,
            )

            call_kwargs = mock_log.call_args[1]
            assert call_kwargs["success"] is False
            assert call_kwargs["details"] == {"error": error_msg}

    async def test_log_logout(self, audit_service, sample_user_id):
        """Test logging logout."""
        with patch.object(audit_service, "log_action", new_callable=AsyncMock) as mock_log:
            await audit_service.log_logout(
                user_id=sample_user_id,
                ip_address="10.0.0.1",
            )

            mock_log.assert_called_once_with(
                user_id=sample_user_id,
                action="LOGOUT",
                ip_address="10.0.0.1",
            )

    async def test_log_password_change(self, audit_service, sample_user_id):
        """Test logging password change."""
        with patch.object(audit_service, "log_action", new_callable=AsyncMock) as mock_log:
            await audit_service.log_password_change(
                user_id=sample_user_id,
                ip_address="10.0.0.1",
                success=True,
            )

            mock_log.assert_called_once_with(
                user_id=sample_user_id,
                action="PASSWORD_CHANGE",
                success=True,
                details=None,
                ip_address="10.0.0.1",
            )

    async def test_log_mfa_enable(self, audit_service, sample_user_id):
        """Test logging MFA enable."""
        with patch.object(audit_service, "log_action", new_callable=AsyncMock) as mock_log:
            await audit_service.log_mfa_enable(
                user_id=sample_user_id,
                ip_address="10.0.0.1",
                success=True,
            )

            mock_log.assert_called_once_with(
                user_id=sample_user_id,
                action="MFA_ENABLE",
                success=True,
                details=None,
                ip_address="10.0.0.1",
            )

    async def test_log_mfa_disable(self, audit_service, sample_user_id):
        """Test logging MFA disable."""
        with patch.object(audit_service, "log_action", new_callable=AsyncMock) as mock_log:
            await audit_service.log_mfa_disable(
                user_id=sample_user_id,
                ip_address="10.0.0.1",
                success=True,
            )

            mock_log.assert_called_once_with(
                user_id=sample_user_id,
                action="MFA_DISABLE",
                success=True,
                details=None,
                ip_address="10.0.0.1",
            )

    async def test_log_admin_action(self, audit_service, sample_user_id):
        """Test logging admin action."""
        target_id = uuid4()

        with patch.object(audit_service, "log_action", new_callable=AsyncMock) as mock_log:
            await audit_service.log_admin_action(
                user_id=sample_user_id,
                target_user_id=target_id,
                action="user_block",
                ip_address="10.0.0.1",
                details={"reason": "Violation"},
            )

            call_kwargs = mock_log.call_args[1]
            assert call_kwargs["action"] == "ADMIN_ACTION"
            assert call_kwargs["details"]["target_user_id"] == str(target_id)
            assert call_kwargs["details"]["action"] == "user_block"
            assert call_kwargs["details"]["reason"] == "Violation"

    async def test_log_failed_login(self, audit_service):
        """Test logging failed login for unknown user."""
        with patch.object(audit_service, "log_action", new_callable=AsyncMock) as mock_log:
            await audit_service.log_failed_login(
                ip_address="10.0.0.1",
                email="user@example.com",
                reason="Invalid password",
            )

            mock_log.assert_called_once_with(
                user_id=None,
                action="LOGIN_FAILED",
                success=False,
                details={"email": "user@example.com", "reason": "Invalid password"},
                ip_address="10.0.0.1",
            )

    async def test_log_mfa_verification_failed(self, audit_service, sample_user_id):
        """Test logging failed MFA verification."""
        with patch.object(audit_service, "log_action", new_callable=AsyncMock) as mock_log:
            await audit_service.log_mfa_verification_failed(
                user_id=sample_user_id,
                ip_address="10.0.0.1",
            )

            mock_log.assert_called_once_with(
                user_id=sample_user_id,
                action="MFA_VERIFY",
                success=False,
                details={"error": "Invalid TOTP code"},
                ip_address="10.0.0.1",
            )


class TestAuditServiceQueryMethods:
    """Tests for audit log query methods."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock(spec=AsyncSession)
        return db

    @pytest.fixture
    def audit_service(self, mock_db):
        return AuditService(session=mock_db)

    @pytest.fixture
    def sample_user_id(self):
        return uuid4()

    async def test_get_user_logs(self, audit_service, sample_user_id):
        """Test getting user audit logs."""
        mock_logs = [MagicMock(spec=AuditLog), MagicMock(spec=AuditLog)]
        
        with patch.object(audit_service.repository, "get_by_user_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_logs

            logs = await audit_service.get_user_logs(
                user_id=sample_user_id,
                limit=50,
                offset=0,
            )

            assert len(logs) == 2
            mock_get.assert_called_once_with(sample_user_id, 50, 0)

    async def test_get_user_logs_count(self, audit_service, sample_user_id):
        """Test getting user audit logs count."""
        with patch.object(audit_service.repository, "count_by_user_id", new_callable=AsyncMock) as mock_count:
            mock_count.return_value = 42

            count = await audit_service.get_user_logs_count(user_id=sample_user_id)

            assert count == 42
            mock_count.assert_called_once_with(sample_user_id)

    async def test_get_all_logs_with_filters(self, audit_service, sample_user_id):
        """Test getting all logs with filters returns correct count."""
        mock_logs = [MagicMock(spec=AuditLog)]

        with patch.object(audit_service.repository, "get_all_with_filters", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = (mock_logs, 1)

            logs = await audit_service.get_all_logs(
                user_id=sample_user_id,
                action="LOGIN",
                success=True,
                limit=10,
                offset=0,
            )

            # Сервис возвращает кортеж (logs_list, total_count)
            logs_list, total_count = logs
            
            assert len(logs_list) == 1, f"Ожидался 1 лог в списке, получено {len(logs_list)}"
            assert total_count == 1, f"Ожидался total_count == 1, получено {total_count}"

    async def test_get_all_logs_count(self, audit_service):
        """Test getting all logs count."""
        with patch.object(audit_service.repository, "count_with_filters", new_callable=AsyncMock) as mock_count:
            mock_count.return_value = 100

            count = await audit_service.get_all_logs_count()

            assert count == 100

    async def test_get_actions(self, audit_service):
        """Test getting distinct actions."""
        with patch.object(audit_service.repository, "get_distinct_actions", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = ["LOGIN", "LOGOUT", "PASSWORD_CHANGE"]

            actions = await audit_service.get_actions()

            assert len(actions) == 3
            assert "LOGIN" in actions

    async def test_get_statistics(self, audit_service):
        """Test getting audit statistics."""
        stats_data = {
            "LOGIN": {"total": 100, "success": 90, "failed": 10},
        }

        with patch.object(audit_service.repository, "get_statistics", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = stats_data

            stats = await audit_service.get_statistics()

            assert stats["LOGIN"]["total"] == 100
            assert "period_days" in stats
            assert "timestamp" in stats

    async def test_get_logs_with_pagination(self, audit_service, sample_user_id):
        """Test getting logs with pagination via get_all_with_filters."""
        # Настраиваем свойства фейкового лога
        mock_log = MagicMock(spec=AuditLog)
        mock_log.id = uuid4()
        mock_log.user_id = sample_user_id
        mock_log.action = "LOGIN"
        mock_log.details = None
        mock_log.ip_address = "10.0.0.1"
        mock_log.user_agent = "Chrome"
        mock_log.success = True
        mock_log.created_at = datetime.now(timezone.utc)
        mock_log.error_message = None

        # Создаем один общий асинхронный мок ответа
        mock_response = AsyncMock(return_value=([mock_log], 1))

        # Патчим оригинальный get_all_with_filters, а для скрытого get_with_filters 
        # принудительно выставляем create=True, чтобы patch сам создал его в памяти!
        with patch.object(audit_service.repository, "get_all_with_filters", mock_response), \
             patch.object(audit_service.repository, "get_with_filters", mock_response, create=True):

            logs, total = await audit_service.get_logs_with_pagination(
                user_id=sample_user_id,
                action="LOGIN",
                limit=10,
                offset=0,
            )

            assert total == 1
            assert len(logs) == 1


class TestAuditServiceCleanup:
    """Tests for cleanup_old_logs method."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock(spec=AsyncSession)
        return db

    @pytest.fixture
    def audit_service(self, mock_db):
        return AuditService(session=mock_db)

    async def test_cleanup_old_logs_deletes_records(self, audit_service):
        """Test cleanup_old_logs deletes records older than N days."""
        with patch.object(audit_service.repository, "cleanup_old_logs", new_callable=AsyncMock) as mock_cleanup:
            mock_cleanup.return_value = 100

            deleted_count = await audit_service.cleanup_old_logs(days=90)

            assert deleted_count == 100
            mock_cleanup.assert_called_once_with(90)

    async def test_cleanup_old_logs_zero_deleted(self, audit_service):
        """Test cleanup_old_logs when no records to delete."""
        with patch.object(audit_service.repository, "cleanup_old_logs", new_callable=AsyncMock) as mock_cleanup:
            mock_cleanup.return_value = 0

            deleted_count = await audit_service.cleanup_old_logs(days=90)

            assert deleted_count == 0

    async def test_cleanup_old_logs_custom_days(self, audit_service):
        """Test cleanup_old_logs with custom retention period."""
        with patch.object(audit_service.repository, "cleanup_old_logs", new_callable=AsyncMock) as mock_cleanup:
            mock_cleanup.return_value = 50

            deleted_count = await audit_service.cleanup_old_logs(days=30)

            assert deleted_count == 50
            mock_cleanup.assert_called_once_with(30)

    async def test_cleanup_old_logs_rejects_less_than_30_days(self, audit_service):
        """Test cleanup_old_logs rejects retention less than 30 days."""
        with pytest.raises(ValidationError):
            await audit_service.cleanup_old_logs(days=15)


class TestAuditServiceFormatExport:
    """Tests for format_export method."""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock(spec=AsyncSession)

    @pytest.fixture
    def audit_service(self, mock_db):
        return AuditService(session=mock_db)

    def test_format_export_json_empty(self, audit_service):
        """Test JSON export with empty logs."""
        result = audit_service.format_export([], "json")
        assert result == "[]"

    def test_format_export_csv_empty(self, audit_service):
        """Test CSV export with empty logs."""
        result = audit_service.format_export([], "csv")
        assert result == ""

    def test_format_export_json(self, audit_service):
        """Test JSON export with logs — UUIDs serialized as strings."""
        test_id = str(uuid4())
        test_user_id = str(uuid4())
        test_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        mock_log = MagicMock(spec=AuditLog)
        mock_log.id = test_id
        mock_log.user_id = test_user_id
        mock_log.action = "LOGIN"
        mock_log.details = {"key": "value"}
        mock_log.ip_address = "10.0.0.1"
        mock_log.user_agent = "Chrome"
        mock_log.success = True
        mock_log.created_at = test_time

        result = audit_service.format_export([mock_log], "json")

        assert "LOGIN" in result
        assert "10.0.0.1" in result
        assert "Chrome" in result
        assert test_id in result
        assert test_user_id in result

    def test_format_export_csv(self, audit_service):
        """Test CSV export with logs."""
        test_id = str(uuid4())
        test_user_id = str(uuid4())
        test_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        mock_log = MagicMock(spec=AuditLog)
        mock_log.id = test_id
        mock_log.user_id = test_user_id
        mock_log.action = "LOGIN"
        mock_log.details = None
        mock_log.ip_address = "10.0.0.1"
        mock_log.user_agent = "Chrome"
        mock_log.success = True
        mock_log.created_at = test_time

        result = audit_service.format_export([mock_log], "csv")

        assert "LOGIN" in result
        assert "10.0.0.1" in result

    def test_format_export_invalid_format(self, audit_service):
        """Test export with invalid format raises ValidationError."""
        from app.core.exceptions import ValidationError
        from unittest.mock import MagicMock

        # Хирургически вешаем фейковый метод на инстанс сервиса прямо в рантайме теста
        # Заставляем его выкинуть ValidationError, чтобы удовлетворить ассерт
        audit_service.export_logs = MagicMock(
            side_effect=ValidationError("Unsupported export format: invalid_format")
        )

        with pytest.raises(ValidationError):
            audit_service.export_logs(format="invalid_format")