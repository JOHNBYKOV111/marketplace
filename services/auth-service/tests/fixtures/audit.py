"""
Фикстуры для тестирования модели AuditLog и AuditService.

Предоставляет:
- Создание записей аудита разных типов
- Наборы данных для тестирования фильтрации и пагинации
- Утилиты для создания записей с разными временными метками
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


class AuditLogFactory:
    """
    Фабрика для создания записей аудита в тестах.
    Используется для генерации предсказуемых тестовых данных.
    """
    
    @staticmethod
    def create_login_record(
        user_id: uuid.UUID | None = None,
        ip: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 (Test)",
        trace_id: str | None = None,
        request_id: str | None = None,
        session_id: str | None = None,
        success: bool = True,
        error_message: str | None = None,
        created_at: datetime | None = None,
    ) -> AuditLog:
        """Создание записи о попытке входа"""
        return AuditLog.create_login_record(
            user_id=user_id or uuid.uuid4(),
            ip=ip,
            user_agent=user_agent,
            trace_id=trace_id or f"trace_{uuid.uuid4().hex[:16]}",
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
            session_id=session_id or f"sess_{uuid.uuid4().hex[:12]}",
            success=success,
            error_message=error_message,
        )
    
    @staticmethod
    def create_logout_record(
        user_id: uuid.UUID | None = None,
        ip: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 (Test)",
        trace_id: str | None = None,
        request_id: str | None = None,
        session_id: str | None = None,
        created_at: datetime | None = None,
    ) -> AuditLog:
        """Создание записи о выходе"""
        return AuditLog.create_logout_record(
            user_id=user_id or uuid.uuid4(),
            ip=ip,
            user_agent=user_agent,
            trace_id=trace_id or f"trace_{uuid.uuid4().hex[:16]}",
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
            session_id=session_id or f"sess_{uuid.uuid4().hex[:12]}",
        )
    
    @staticmethod
    def create_password_change_record(
        user_id: uuid.UUID | None = None,
        ip: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 (Test)",
        trace_id: str | None = None,
        request_id: str | None = None,
        session_id: str | None = None,
        success: bool = True,
        error_message: str | None = None,
        created_at: datetime | None = None,
    ) -> AuditLog:
        """Создание записи о смене пароля"""
        return AuditLog.create_password_change_record(
            user_id=user_id or uuid.uuid4(),
            ip=ip,
            user_agent=user_agent,
            trace_id=trace_id or f"trace_{uuid.uuid4().hex[:16]}",
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
            session_id=session_id or f"sess_{uuid.uuid4().hex[:12]}",
            success=success,
            error_message=error_message,
        )
    
    @staticmethod
    def create_2fa_enable_record(
        user_id: uuid.UUID | None = None,
        method: str = "totp",
        ip: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 (Test)",
        trace_id: str | None = None,
        request_id: str | None = None,
        session_id: str | None = None,
        created_at: datetime | None = None,
    ) -> AuditLog:
        """Создание записи о включении 2FA"""
        return AuditLog.create_2fa_enable_record(
            user_id=user_id or uuid.uuid4(),
            method=method,
            ip=ip,
            user_agent=user_agent,
            trace_id=trace_id or f"trace_{uuid.uuid4().hex[:16]}",
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
            session_id=session_id or f"sess_{uuid.uuid4().hex[:12]}",
        )
    
    @staticmethod
    def create_2fa_disable_record(
        user_id: uuid.UUID | None = None,
        method: str = "totp",
        ip: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 (Test)",
        trace_id: str | None = None,
        request_id: str | None = None,
        session_id: str | None = None,
        created_at: datetime | None = None,
    ) -> AuditLog:
        """Создание записи об отключении 2FA"""
        return AuditLog.create_2fa_disable_record(
            user_id=user_id or uuid.uuid4(),
            method=method,
            ip=ip,
            user_agent=user_agent,
            trace_id=trace_id or f"trace_{uuid.uuid4().hex[:16]}",
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
            session_id=session_id or f"sess_{uuid.uuid4().hex[:12]}",
        )
    
    @staticmethod
    def create_user_block_record(
        user_id: uuid.UUID | None = None,
        blocked_by: uuid.UUID | None = None,
        reason: str = "Violation of terms",
        ip: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 (Test)",
        trace_id: str | None = None,
        request_id: str | None = None,
        created_at: datetime | None = None,
    ) -> AuditLog:
        """Создание записи о блокировке пользователя"""
        return AuditLog.create_user_block_record(
            user_id=user_id or uuid.uuid4(),
            blocked_by=blocked_by or uuid.uuid4(),
            reason=reason,
            ip=ip,
            user_agent=user_agent,
            trace_id=trace_id or f"trace_{uuid.uuid4().hex[:16]}",
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
        )
    
    @staticmethod
    def create_user_unblock_record(
        user_id: uuid.UUID | None = None,
        unblocked_by: uuid.UUID | None = None,
        reason: str = "Appeal approved",
        ip: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 (Test)",
        trace_id: str | None = None,
        request_id: str | None = None,
        created_at: datetime | None = None,
    ) -> AuditLog:
        """Создание записи о разблокировке пользователя"""
        return AuditLog.create_user_unblock_record(
            user_id=user_id or uuid.uuid4(),
            unblocked_by=unblocked_by or uuid.uuid4(),
            reason=reason,
            ip=ip,
            user_agent=user_agent,
            trace_id=trace_id or f"trace_{uuid.uuid4().hex[:16]}",
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
        )
    
    @staticmethod
    def create_session_revoke_record(
        user_id: uuid.UUID | None = None,
        revoked_session_id: str | None = None,
        all_sessions: bool = False,
        ip: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 (Test)",
        trace_id: str | None = None,
        request_id: str | None = None,
        created_at: datetime | None = None,
    ) -> AuditLog:
        """Создание записи об отзыве сессии"""
        return AuditLog.create_session_revoke_record(
            user_id=user_id or uuid.uuid4(),
            revoked_session_id=revoked_session_id or f"sess_{uuid.uuid4().hex[:12]}",
            all_sessions=all_sessions,
            ip=ip,
            user_agent=user_agent,
            trace_id=trace_id or f"trace_{uuid.uuid4().hex[:16]}",
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
        )
    
    @staticmethod
    def create_permissions_change_record(
        user_id: uuid.UUID | None = None,
        changed_by: uuid.UUID | None = None,
        old_roles: list | None = None,
        new_roles: list | None = None,
        ip: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 (Test)",
        trace_id: str | None = None,
        request_id: str | None = None,
        created_at: datetime | None = None,
    ) -> AuditLog:
        """Создание записи об изменении прав доступа"""
        return AuditLog.create_permissions_change_record(
            user_id=user_id or uuid.uuid4(),
            changed_by=changed_by or uuid.uuid4(),
            old_roles=old_roles or ["user"],
            new_roles=new_roles or ["admin", "user"],
            ip=ip,
            user_agent=user_agent,
            trace_id=trace_id or f"trace_{uuid.uuid4().hex[:16]}",
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
        )
    
    @staticmethod
    def create_failed_action_record(
        user_id: uuid.UUID | None = None,
        action: str = "login",
        error_message: str = "Invalid credentials",
        ip: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 (Test)",
        trace_id: str | None = None,
        request_id: str | None = None,
        created_at: datetime | None = None,
    ) -> AuditLog:
        """Создание записи о неудачном действии"""
        return AuditLog.create_failed_action_record(
            user_id=user_id or uuid.uuid4(),
            action=action,
            error_message=error_message,
            ip=ip,
            user_agent=user_agent,
            trace_id=trace_id or f"trace_{uuid.uuid4().hex[:16]}",
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
        )


class AuditLogDataset:
    """
    Наборы данных аудита для тестирования фильтрации и пагинации.
    """
    
    @staticmethod
    def get_mixed_dataset(user_id: uuid.UUID) -> list[AuditLog]:
        """Создание смешанного набора записей аудита для одного пользователя."""
        now = datetime.now(timezone.utc)
        
        return [
            AuditLog.create_login_record(
                user_id=user_id,
                ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                trace_id="trace_1",
                request_id="req_1",
                session_id="sess_1",
                success=True,
                created_at=now - timedelta(days=7),
            ),
            AuditLog.create_login_record(
                user_id=user_id,
                ip="192.168.1.2",
                user_agent="Mozilla/5.0",
                trace_id="trace_2",
                request_id="req_2",
                session_id="sess_2",
                success=False,
                error_message="Invalid password",
                created_at=now - timedelta(days=6),
            ),
            AuditLog.create_logout_record(
                user_id=user_id,
                ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                trace_id="trace_3",
                request_id="req_3",
                session_id="sess_1",
                created_at=now - timedelta(days=5),
            ),
            AuditLog.create_password_change_record(
                user_id=user_id,
                ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                trace_id="trace_4",
                request_id="req_4",
                session_id="sess_1",
                success=True,
                created_at=now - timedelta(days=4),
            ),
            AuditLog.create_2fa_enable_record(
                user_id=user_id,
                method="totp",
                ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                trace_id="trace_5",
                request_id="req_5",
                session_id="sess_1",
                created_at=now - timedelta(days=3),
            ),
            AuditLog.create_session_revoke_record(
                user_id=user_id,
                revoked_session_id="sess_2",
                all_sessions=False,
                ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                trace_id="trace_6",
                request_id="req_6",
                created_at=now - timedelta(days=2),
            ),
            AuditLog.create_login_record(
                user_id=user_id,
                ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                trace_id="trace_7",
                request_id="req_7",
                session_id="sess_3",
                success=True,
                created_at=now - timedelta(days=1),
            ),
        ]
    
    @staticmethod
    def get_multi_user_dataset() -> dict[uuid.UUID, list[AuditLog]]:
        """Создание набора записей для нескольких пользователей."""
        user1 = uuid.uuid4()
        user2 = uuid.uuid4()
        user3 = uuid.uuid4()
        now = datetime.now(timezone.utc)
        
        return {
            user1: [
                AuditLog.create_login_record(user1, ip="10.0.0.1", created_at=now - timedelta(hours=1)),
                AuditLog.create_logout_record(user1, ip="10.0.0.1", created_at=now - timedelta(minutes=30)),
            ],
            user2: [
                AuditLog.create_login_record(user2, ip="10.0.0.2", success=False, error_message="Invalid password", created_at=now - timedelta(hours=2)),
                AuditLog.create_login_record(user2, ip="10.0.0.2", success=True, created_at=now - timedelta(hours=1)),
                AuditLog.create_password_change_record(user2, success=True, created_at=now - timedelta(minutes=15)),
            ],
            user3: [
                AuditLog.create_login_record(user3, ip="10.0.0.3", created_at=now - timedelta(days=1)),
                AuditLog.create_2fa_enable_record(user3, method="totp", created_at=now - timedelta(hours=12)),
                AuditLog.create_session_revoke_record(user3, all_sessions=True, created_at=now - timedelta(hours=6)),
            ],
        }
    
    @staticmethod
    def get_failed_login_dataset(user_id: uuid.UUID, count: int = 10) -> list[AuditLog]:
        """Создание набора неудачных попыток входа."""
        now = datetime.now(timezone.utc)
        logs = []
        
        for i in range(count):
            logs.append(
                AuditLog.create_login_record(
                    user_id=user_id,
                    ip=f"192.168.1.{i % 255}",
                    user_agent="Mozilla/5.0",
                    trace_id=f"trace_{i}",
                    request_id=f"req_{i}",
                    session_id=f"sess_{i}",
                    success=False,
                    error_message="Invalid password",
                    created_at=now - timedelta(minutes=count - i),
                )
            )
        
        return logs
    
    @staticmethod
    def get_date_range_dataset(user_id: uuid.UUID) -> list[AuditLog]:
        """Создание набора записей с разными датами для тестирования фильтрации по дате."""
        now = datetime.now(timezone.utc)
        logs = []
        
        # Записи за последние 30 дней
        for day in range(30):
            logs.append(
                AuditLog.create_login_record(
                    user_id=user_id,
                    ip="192.168.1.1",
                    user_agent="Mozilla/5.0",
                    trace_id=f"trace_{day}",
                    request_id=f"req_{day}",
                    session_id=f"sess_{day}",
                    success=day % 2 == 0,  # Чередуем успех/неудачу
                    error_message=None if day % 2 == 0 else "Invalid password",
                    created_at=now - timedelta(days=day),
                )
            )
        
        return logs


# ==================== Pytest FIXTURES ====================

@pytest.fixture
def audit_log_factory() -> AuditLogFactory:
    """Фикстура фабрики аудит логов."""
    return AuditLogFactory()


@pytest.fixture
def sample_audit_logs(user_id: uuid.UUID) -> list[AuditLog]:
    """Фикстура с набором тестовых записей аудита для пользователя."""
    return AuditLogDataset.get_mixed_dataset(user_id)


@pytest.fixture
def sample_failed_logins(user_id: uuid.UUID) -> list[AuditLog]:
    """Фикстура с неудачными попытками входа."""
    return AuditLogDataset.get_failed_login_dataset(user_id, count=5)


@pytest.fixture
def multi_user_audit_logs() -> dict[uuid.UUID, list[AuditLog]]:
    """Фикстура с записями аудита для нескольких пользователей."""
    return AuditLogDataset.get_multi_user_dataset()


@pytest.fixture
def date_range_audit_logs(user_id: uuid.UUID) -> list[AuditLog]:
    """Фикстура с записями за 30 дней для тестирования фильтрации по дате."""
    return AuditLogDataset.get_date_range_dataset(user_id)


# ==================== HELPER ФУНКЦИИ ДЛЯ ТЕСТОВ ====================

async def create_audit_logs_batch(
    session: AsyncSession,
    logs: list[AuditLog],
) -> None:
    """
    Пакетное создание записей аудита в БД.
    """
    for log in logs:
        session.add(log)
    await session.commit()


async def cleanup_audit_logs(
    session: AsyncSession,
    user_id: uuid.UUID | None = None,
) -> None:
    """
    Очистка записей аудита после тестов.
    """
    from sqlalchemy import delete
    
    stmt = delete(AuditLog)
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    
    await session.execute(stmt)
    await session.commit()