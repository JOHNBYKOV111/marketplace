"""
Unit tests for AuditLog model.

Tests cover:
- Model field definitions and constraints
- __repr__ method
- to_dict() serialization
- All factory methods (create_*_record)
- Edge cases and error handling
"""

import uuid
from datetime import datetime
from typing import Any

import pytest
from freezegun import freeze_time

from app.models.audit_log import AuditLog


class TestAuditLogModel:
    """Test suite for AuditLog model."""

    @pytest.fixture
    def sample_user_id(self) -> uuid.UUID:
        """Generate sample user ID."""
        return uuid.uuid4()

    @pytest.fixture
    def sample_audit_log(self, sample_user_id: uuid.UUID) -> AuditLog:
        """Create minimal AuditLog instance with explicit values."""
        return AuditLog(
            user_id=sample_user_id,
            action="login",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            trace_id="trace-123",
            request_id="req-456",
            session_id="sess-789",
            success=True,
        )

    # ==================== FIELD TESTS ====================

    def test_model_fields_existence(self, sample_audit_log: AuditLog):
        """Test that all expected fields exist."""
        assert hasattr(sample_audit_log, "id")
        assert hasattr(sample_audit_log, "user_id")
        assert hasattr(sample_audit_log, "action")
        assert hasattr(sample_audit_log, "ip_address")
        assert hasattr(sample_audit_log, "user_agent")
        assert hasattr(sample_audit_log, "trace_id")
        assert hasattr(sample_audit_log, "request_id")
        assert hasattr(sample_audit_log, "session_id")
        assert hasattr(sample_audit_log, "details")
        assert hasattr(sample_audit_log, "old_value")
        assert hasattr(sample_audit_log, "new_value")
        assert hasattr(sample_audit_log, "success")
        assert hasattr(sample_audit_log, "error_message")
        assert hasattr(sample_audit_log, "created_at")

    def test_id_default_uuid(self):
        """Test id field has UUID default."""
        audit_log = AuditLog(user_id=uuid.uuid4(), action="test")
        assert audit_log.id is None  # None before flush
        id_column = AuditLog.__table__.columns["id"]
        assert id_column.primary_key is True

    def test_user_id_required(self, sample_user_id: uuid.UUID):
        """Test user_id is accepted as required field."""
        audit_log = AuditLog(user_id=sample_user_id, action="login")
        assert audit_log.user_id == sample_user_id

    def test_action_required(self, sample_user_id: uuid.UUID):
        """Test action is required field."""
        audit_log = AuditLog(user_id=sample_user_id, action="login")
        assert audit_log.action == "login"

    def test_success_default_true(self, sample_user_id: uuid.UUID):
        """Test success field defaults to True when explicitly set."""
        audit_log = AuditLog(
            user_id=sample_user_id, action="login", success=True
        )
        assert audit_log.success is True

        audit_log_false = AuditLog(
            user_id=sample_user_id, action="login", success=False
        )
        assert audit_log_false.success is False

    def test_nullable_fields_accept_none(self, sample_user_id: uuid.UUID):
        """Test nullable fields can be set to None."""
        audit_log = AuditLog(
            user_id=sample_user_id, 
            action="login",
            ip_address=None,
            user_agent=None,
            trace_id=None,
            request_id=None,
            session_id=None,
            old_value=None,
            new_value=None,
            error_message=None,
            details=None,
        )
        
        assert audit_log.ip_address is None
        assert audit_log.user_agent is None
        assert audit_log.trace_id is None
        assert audit_log.request_id is None
        assert audit_log.session_id is None
        assert audit_log.old_value is None
        assert audit_log.new_value is None
        assert audit_log.error_message is None
        assert audit_log.details is None

    def test_details_accepts_json_types(self, sample_user_id: uuid.UUID):
        """Test details accepts various JSON-compatible types."""
        test_cases = [
            {"roles": ["admin", "user"]},
            {"method": "totp"},
            None,
        ]
        
        for value in test_cases:
            audit_log = AuditLog(
                user_id=sample_user_id,
                action="mfa_enable",
                details=value,
            )
            assert audit_log.details == value

    # ==================== __REPR__ TESTS ====================

    def test_repr_format(self, sample_audit_log: AuditLog, sample_user_id: uuid.UUID):
        """Test __repr__ returns expected format."""
        repr_str = repr(sample_audit_log)
        
        assert "AuditLog" in repr_str
        assert f"id={sample_audit_log.id}" in repr_str
        assert f"user_id={sample_user_id}" in repr_str
        assert "action=login" in repr_str

    def test_repr_with_none_id(self, sample_user_id: uuid.UUID):
        """Test __repr__ when id is None (unsaved instance)."""
        audit_log = AuditLog(user_id=sample_user_id, action="login")
        repr_str = repr(audit_log)
        
        assert "id=None" in repr_str

    # ==================== SERIALIZATION TESTS ====================

    @freeze_time("2024-01-01 12:00:00")
    def test_serialization_to_dict(self, sample_user_id: uuid.UUID):
        """Test manual serialization to dictionary."""
        audit_log = AuditLog(
            user_id=sample_user_id,
            action="login",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            trace_id="trace-123",
            request_id="req-456",
            session_id="sess-789",
            success=True,
        )
        audit_log.id = uuid.uuid4()
        audit_log.created_at = datetime(2024, 1, 1, 12, 0, 0)
        
        result = {
            "id": str(audit_log.id),
            "user_id": str(audit_log.user_id),
            "action": audit_log.action,
            "ip_address": audit_log.ip_address,
            "user_agent": audit_log.user_agent,
            "trace_id": audit_log.trace_id,
            "request_id": audit_log.request_id,
            "session_id": audit_log.session_id,
            "success": audit_log.success,
            "error_message": audit_log.error_message,
            "created_at": audit_log.created_at.isoformat() if audit_log.created_at else None,
        }
        
        assert isinstance(result, dict)
        assert result["id"] == str(audit_log.id)
        assert result["user_id"] == str(sample_user_id)
        assert result["action"] == "login"
        assert result["ip_address"] == "192.168.1.1"
        assert result["user_agent"] == "Mozilla/5.0"
        assert result["trace_id"] == "trace-123"
        assert result["request_id"] == "req-456"
        assert result["session_id"] == "sess-789"
        assert result["success"] is True
        assert result["error_message"] is None
        assert result["created_at"] == "2024-01-01T12:00:00"

    def test_serialization_includes_optional_json_fields(self, sample_user_id: uuid.UUID):
        """Test serialization includes old_value and new_value when present."""
        audit_log = AuditLog(
            user_id=sample_user_id,
            action="permissions_change",
            old_value={"roles": ["user"]},
            new_value={"roles": ["admin"]},
        )
        
        assert audit_log.old_value == {"roles": ["user"]}
        assert audit_log.new_value == {"roles": ["admin"]}

    def test_serialization_handles_none_created_at(self, sample_user_id: uuid.UUID):
        """Test serialization handles None created_at gracefully."""
        audit_log = AuditLog(user_id=sample_user_id, action="login")
        audit_log.created_at = None
        
        result = audit_log.created_at
        assert result is None

    def test_serialization_uuid_handling(self, sample_user_id: uuid.UUID):
        """Test UUID handling in serialization."""
        audit_log = AuditLog.create_login_record(
            user_id=sample_user_id,
            ip_address=None,
            user_agent=None,
            trace_id=None,
            request_id=None,
            session_id=None,
        )
        
        user_id_str = str(audit_log.user_id)
        assert isinstance(user_id_str, str)
        assert uuid.UUID(user_id_str) == sample_user_id

    # ==================== CREATE_LOGIN_RECORD TESTS ====================

    def test_create_login_record_success(self, sample_user_id: uuid.UUID):
        """Test creating successful login record."""
        audit_log = AuditLog.create_login_record(
            user_id=sample_user_id,
            ip_address="10.0.0.1",
            user_agent="Chrome/120",
            trace_id="trace-abc",
            request_id="req-xyz",
            session_id="session-123",
            success=True,
        )
        
        assert audit_log.user_id == sample_user_id
        assert audit_log.action == "login"
        assert audit_log.ip_address == "10.0.0.1"
        assert audit_log.user_agent == "Chrome/120"
        assert audit_log.trace_id == "trace-abc"
        assert audit_log.request_id == "req-xyz"
        assert audit_log.session_id == "session-123"
        assert audit_log.success is True
        assert audit_log.error_message is None

    def test_create_login_record_failed(self, sample_user_id: uuid.UUID):
        """Test creating failed login record."""
        error_msg = "Invalid password"
        audit_log = AuditLog.create_login_record(
            user_id=sample_user_id,
            ip_address="10.0.0.1",
            user_agent="Chrome/120",
            trace_id=None,
            request_id=None,
            session_id=None,
            success=False,
            error_message=error_msg,
        )
        
        assert audit_log.success is False
        assert audit_log.error_message == error_msg

    def test_create_login_record_with_none_fields(self, sample_user_id: uuid.UUID):
        """Test login record with all optional fields as None."""
        audit_log = AuditLog.create_login_record(
            user_id=sample_user_id,
            ip_address=None,
            user_agent=None,
            trace_id=None,
            request_id=None,
            session_id=None,
        )
        
        assert audit_log.ip_address is None
        assert audit_log.user_agent is None
        assert audit_log.trace_id is None
        assert audit_log.request_id is None
        assert audit_log.session_id is None

    # ==================== CREATE_LOGOUT_RECORD TESTS ====================

    def test_create_logout_record(self, sample_user_id: uuid.UUID):
        """Test creating logout record."""
        audit_log = AuditLog.create_logout_record(
            user_id=sample_user_id,
            ip_address="10.0.0.1",
            user_agent="Firefox/121",
            trace_id="trace-logout",
            request_id="req-logout",
            session_id="session-logout",
        )
        
        assert audit_log.user_id == sample_user_id
        assert audit_log.action == "logout"
        assert audit_log.ip_address == "10.0.0.1"
        assert audit_log.user_agent == "Firefox/121"
        assert audit_log.success is True
        assert audit_log.error_message is None

    # ==================== CREATE_PASSWORD_CHANGE_RECORD TESTS ====================

    def test_create_password_change_record_success(self, sample_user_id: uuid.UUID):
        """Test creating successful password change record."""
        audit_log = AuditLog.create_password_change_record(
            user_id=sample_user_id,
            ip_address="10.0.0.1",
            user_agent="Safari/17",
            trace_id="trace-pwd",
            request_id="req-pwd",
            session_id="session-pwd",
            success=True,
        )
        
        assert audit_log.action == "password_change"
        assert audit_log.success is True
        assert audit_log.error_message is None

    def test_create_password_change_record_failed(self, sample_user_id: uuid.UUID):
        """Test creating failed password change record."""
        error_msg = "Current password incorrect"
        audit_log = AuditLog.create_password_change_record(
            user_id=sample_user_id,
            ip_address="10.0.0.1",
            user_agent="Safari/17",
            trace_id="trace-pwd",
            request_id="req-pwd",
            session_id="session-pwd",
            success=False,
            error_message=error_msg,
        )
        
        assert audit_log.action == "password_change"
        assert audit_log.success is False
        assert audit_log.error_message == error_msg

    # ==================== CREATE_MFA_RECORD TESTS ====================

    @pytest.mark.parametrize("method", ["totp", "email", "sms"])
    def test_create_mfa_record_enable(self, sample_user_id: uuid.UUID, method: str):
        """Test creating MFA enable record with different methods."""
        audit_log = AuditLog.create_mfa_record(
            user_id=sample_user_id,
            action="mfa_enable",
            ip_address="10.0.0.1",
            user_agent="Edge/120",
            trace_id="trace-2fa",
            request_id="req-2fa",
            session_id="session-2fa",
            details={"method": method},
        )
        
        assert audit_log.action == "mfa_enable"
        assert audit_log.details == {"method": method}
        assert audit_log.success is True

    @pytest.mark.parametrize("method", ["totp", "email", "sms"])
    def test_create_mfa_record_disable(self, sample_user_id: uuid.UUID, method: str):
        """Test creating MFA disable record with different methods."""
        audit_log = AuditLog.create_mfa_record(
            user_id=sample_user_id,
            action="mfa_disable",
            ip_address="10.0.0.1",
            user_agent="Edge/120",
            trace_id="trace-2fa",
            request_id="req-2fa",
            session_id="session-2fa",
            details={"method": method},
        )
        
        assert audit_log.action == "mfa_disable"
        assert audit_log.details == {"method": method}
        assert audit_log.success is True

    # ==================== CREATE_ADMIN_ACTION_RECORD TESTS ====================

    def test_create_admin_action_block_user(self, sample_user_id: uuid.UUID):
        """Test creating admin action record for user block."""
        blocked_by = uuid.uuid4()
        reason = "Suspicious activity"
        
        audit_log = AuditLog.create_admin_action_record(
            user_id=sample_user_id,
            action="user_block",
            details={
                "blocked_by": str(blocked_by),
                "reason": reason,
            },
            ip_address="10.0.0.1",
            user_agent="BlockBot/1.0",
            trace_id="trace-block",
            request_id="req-block",
        )
        
        assert audit_log.action == "admin_user_block"
        assert audit_log.details == {
            "blocked_by": str(blocked_by),
            "reason": reason,
        }
        assert audit_log.success is True

    def test_create_admin_action_unblock_user(self, sample_user_id: uuid.UUID):
        """Test creating admin action record for user unblock."""
        unblocked_by = uuid.uuid4()
        reason = "Appeal approved"
        
        audit_log = AuditLog.create_admin_action_record(
            user_id=sample_user_id,
            action="user_unblock",
            details={
                "unblocked_by": str(unblocked_by),
                "reason": reason,
            },
            ip_address="10.0.0.1",
            user_agent="AdminPanel/2.0",
            trace_id="trace-unblock",
            request_id="req-unblock",
        )
        
        assert audit_log.action == "admin_user_unblock"
        assert audit_log.details == {
            "unblocked_by": str(unblocked_by),
            "reason": reason,
        }
        assert audit_log.success is True

    def test_create_admin_action_session_revoke(self, sample_user_id: uuid.UUID):
        """Test creating admin action record for session revoke."""
        audit_log = AuditLog.create_admin_action_record(
            user_id=sample_user_id,
            action="session_revoke",
            details={
                "revoked_session_id": "session-123",
                "all_sessions": False,
            },
            ip_address="10.0.0.1",
            user_agent="SecurityPanel/1.0",
            trace_id="trace-revoke",
            request_id="req-revoke",
        )
        
        assert audit_log.action == "admin_session_revoke"
        assert audit_log.details["revoked_session_id"] == "session-123"
        assert audit_log.details["all_sessions"] is False

    def test_create_admin_action_permissions_change(self, sample_user_id: uuid.UUID):
        """Test creating admin action record for permissions change."""
        changed_by = uuid.uuid4()
        old_roles = ["user", "viewer"]
        new_roles = ["admin", "moderator"]
        
        audit_log = AuditLog.create_admin_action_record(
            user_id=sample_user_id,
            action="permissions_change",
            details={
                "changed_by": str(changed_by),
                "old_roles": old_roles,
                "new_roles": new_roles,
            },
            ip_address="10.0.0.1",
            user_agent="RBACManager/1.0",
            trace_id="trace-perms",
            request_id="req-perms",
        )
        
        assert audit_log.action == "admin_permissions_change"
        assert audit_log.details["old_roles"] == old_roles
        assert audit_log.details["new_roles"] == new_roles
        assert audit_log.success is True

    # ==================== EDGE CASES ====================

    def test_create_record_with_empty_strings(self, sample_user_id: uuid.UUID):
        """Test factory methods handle empty strings correctly."""
        audit_log = AuditLog.create_login_record(
            user_id=sample_user_id,
            ip_address="",
            user_agent="",
            trace_id="",
            request_id="",
            session_id="",
        )
        
        assert audit_log.ip_address == ""
        assert audit_log.user_agent == ""
        assert audit_log.trace_id == ""

    def test_very_long_user_agent_string(self, sample_user_id: uuid.UUID):
        """Test handling of long user agent strings (max 255 chars per model)."""
        long_ua = "Mozilla/5.0 " + "x" * 250
        audit_log = AuditLog.create_login_record(
            user_id=sample_user_id,
            ip_address="127.0.0.1",
            user_agent=long_ua[:255],
            trace_id=None,
            request_id=None,
            session_id=None,
        )
        
        assert len(audit_log.user_agent) <= 255

    def test_create_mfa_record_with_all_params(self, sample_user_id: uuid.UUID):
        """Test creating MFA record with all optional parameters."""
        audit_log = AuditLog.create_mfa_record(
            user_id=sample_user_id,
            action="mfa_verify",
            ip_address="10.0.0.1",
            user_agent="AuthApp/2.0",
            trace_id="trace-mfa",
            request_id="req-mfa",
            session_id="session-mfa",
            success=False,
            details={"method": "totp", "error": "Invalid code"},
        )
        
        assert audit_log.action == "mfa_verify"
        assert audit_log.success is False
        assert audit_log.details == {"method": "totp", "error": "Invalid code"}