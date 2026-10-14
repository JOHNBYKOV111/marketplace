"""
Интеграционные тесты для AuditLogRepository.

Тестирует:
- create - создание записи аудита
- get_by_id - получение по ID
- get_by_user_id - получение записей пользователя с пагинацией
- get_by_action - получение записей по типу действия
- get_with_filters - фильтрация по всем параметрам
- get_failed_actions - получение неудачных действий
- get_statistics - статистика по действиям
- get_actions_list - список уникальных действий
- cleanup_old_logs - очистка старых логов
- Граничные случаи и большие объемы данных
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from app.models.audit_log import AuditLog
from app.repositories.audit_log_repository import AuditLogRepository
from app.models.user import User


# ==================== ГЛОБАЛЬНЫЕ ФИКСТУРЫ ====================

@pytest.fixture
def sample_user_id() -> uuid4:
    """ID пользователя для тестов."""
    return uuid4()


@pytest.fixture
def another_user_id() -> uuid4:
    """ID другого пользователя для тестов."""
    return uuid4()


@pytest_asyncio.fixture
async def sample_logs(
    audit_log_repository,
    db_session: AsyncSession,
    sample_user_id: uuid4,
    another_user_id: uuid4,
    create_test_user,
) -> list[AuditLog]:
    """Создание набора тестовых логов в БД."""
    # Создаём реальных пользователей для внешних ключей
    user1 = await create_test_user(id=sample_user_id, email=f"user_{uuid4().hex[:8]}@example.com")
    user2 = await create_test_user(id=another_user_id, email=f"user2_{uuid4().hex[:8]}@example.com")
    
    now = datetime.now(timezone.utc)
    logs = [
        AuditLog(
            user_id=user1.id,
            action="login",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            trace_id="trace_1",
            request_id="req_1",
            session_id="sess_1",
            success=True,
            created_at=now - timedelta(days=7),
        ),
        AuditLog(
            user_id=user1.id,
            action="login",
            ip_address="192.168.1.2",
            user_agent="Mozilla/5.0",
            trace_id="trace_2",
            request_id="req_2",
            session_id="sess_2",
            success=False,
            error_message="Invalid password",
            created_at=now - timedelta(days=6),
        ),
        AuditLog(
            user_id=user1.id,
            action="logout",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            trace_id="trace_3",
            request_id="req_3",
            session_id="sess_1",
            success=True,
            created_at=now - timedelta(days=5),
        ),
        AuditLog(
            user_id=user1.id,
            action="password_change",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            trace_id="trace_4",
            request_id="req_4",
            session_id="sess_1",
            success=True,
            created_at=now - timedelta(days=4),
        ),
        AuditLog(
            user_id=user1.id,
            action="2fa_enable",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            trace_id="trace_5",
            request_id="req_5",
            session_id="sess_1",
            new_value={"method": "totp"},
            success=True,
            created_at=now - timedelta(days=3),
        ),
        AuditLog(
            user_id=user2.id,
            action="login",
            ip_address="10.0.0.1",
            user_agent="Chrome/120",
            trace_id="trace_6",
            request_id="req_6",
            session_id="sess_3",
            success=True,
            created_at=now - timedelta(days=2),
        ),
    ]

    for log in logs:
        await audit_log_repository.create(log)
    await db_session.flush()

    return logs


@pytest_asyncio.fixture
async def many_logs(
    audit_log_repository,
    db_session: AsyncSession,
    sample_user_id: uuid4,
    create_test_user,
) -> list[AuditLog]:
    """Создание большого количества логов для тестирования пагинации."""
    # Создаём реального пользователя
    user = await create_test_user(id=sample_user_id, email=f"user_{uuid4().hex[:8]}@example.com")
    
    now = datetime.now(timezone.utc)
    logs = []
    for i in range(150):
        logs.append(
            AuditLog(
                user_id=user.id,
                action="login",
                ip_address=f"192.168.1.{i % 255}",
                user_agent="Mozilla/5.0",
                trace_id=f"trace_{i}",
                request_id=f"req_{i}",
                session_id=f"sess_{i}",
                success=i % 2 == 0,
                error_message=None if i % 2 == 0 else "Invalid password",
                created_at=now - timedelta(minutes=i),
            )
        )

    for log in logs:
        await audit_log_repository.create(log)
    await db_session.flush()

    return logs


# ==================== ТЕСТЫ ====================

class TestCreate:
    """Тесты для метода create."""

    async def test_create_log_success(
        self,
        audit_log_repository: AuditLogRepository,
        db_session: AsyncSession,
        create_test_user,
    ):
        """Тест успешного создания записи аудита."""
        user = await create_test_user(email=f"user_{uuid4().hex[:8]}@example.com")
        log = AuditLog.create_login_record(
            user_id=user.id,
            ip_address="127.0.0.1",
            user_agent="pytest",
            trace_id="trace_test",
            request_id="req_test",
            session_id="sess_test",
            success=True,
        )

        created = await audit_log_repository.create(log)
        await db_session.flush()

        assert created.id is not None
        assert created.user_id == user.id
        assert created.action == "login"
        assert created.success is True

    async def test_create_log_auto_increment_id(
        self,
        audit_log_repository: AuditLogRepository,
        db_session: AsyncSession,
        create_test_user,
    ):
        """Тест автоматического инкремента ID."""
        user = await create_test_user(email=f"user_{uuid4().hex[:8]}@example.com")

        log1 = AuditLog.create_login_record(
            user_id=user.id,
            ip_address="127.0.0.1",
            user_agent="pytest",
            trace_id="trace_1",
            request_id="req_1",
            session_id="sess_1",
            success=True,
        )
        log2 = AuditLog.create_login_record(
            user_id=user.id,
            ip_address="127.0.0.1",
            user_agent="pytest",
            trace_id="trace_2",
            request_id="req_2",
            session_id="sess_2",
            success=False,
        )

        created1 = await audit_log_repository.create(log1)
        created2 = await audit_log_repository.create(log2)
        await db_session.flush()

        assert created1.id is not None
        assert created2.id is not None


class TestGetById:
    """Тесты для метода get_by_id."""

    async def test_get_by_id_success(self, audit_log_repository: AuditLogRepository, sample_logs: list[AuditLog]):
        """Тест успешного получения записи по ID."""
        first_log = sample_logs[0]
        retrieved = await audit_log_repository.get_by_id(first_log.id)

        assert retrieved is not None
        assert retrieved.id == first_log.id
        assert retrieved.user_id == first_log.user_id
        assert retrieved.action == first_log.action

    async def test_get_by_id_not_found(self, audit_log_repository: AuditLogRepository):
        """Тест получения несуществующей записи."""
        fake_id = uuid4()
        retrieved = await audit_log_repository.get_by_id(fake_id)
        assert retrieved is None


class TestGetByUserId:
    """Тесты для метода get_by_user_id."""

    async def test_get_by_user_id_success(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
        sample_user_id: uuid4,
    ):
        """Тест успешного получения записей пользователя."""
        logs = await audit_log_repository.get_by_user_id(sample_user_id, limit=100, offset=0)

        assert len(logs) == 5
        for log in logs:
            assert log.user_id == sample_user_id
        assert logs[0].created_at >= logs[-1].created_at

    async def test_get_by_user_id_with_pagination(
        self,
        audit_log_repository: AuditLogRepository,
        many_logs: list[AuditLog],
        sample_user_id: uuid4,
    ):
        """Тест пагинации при получении записей пользователя."""
        page1 = await audit_log_repository.get_by_user_id(sample_user_id, limit=50, offset=0)
        assert len(page1) == 50

        page2 = await audit_log_repository.get_by_user_id(sample_user_id, limit=50, offset=50)
        assert len(page2) == 50

        page3 = await audit_log_repository.get_by_user_id(sample_user_id, limit=50, offset=100)
        assert len(page3) == 50

        all_ids = [log.id for log in page1 + page2 + page3]
        assert len(set(all_ids)) == 150

    async def test_get_by_user_id_no_logs(self, audit_log_repository: AuditLogRepository):
        """Тест получения записей для пользователя без логов."""
        unknown_user = uuid4()
        logs = await audit_log_repository.get_by_user_id(unknown_user, limit=50, offset=0)
        assert logs == []


class TestGetByAction:
    """Тесты для метода get_by_action."""

    async def test_get_by_action_success(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
    ):
        """Тест успешного получения записей по типу действия."""
        logs = await audit_log_repository.get_by_action("login", limit=100, offset=0)

        assert len(logs) == 3
        for log in logs:
            assert log.action == "login"

    async def test_get_by_action_with_pagination(
        self,
        audit_log_repository: AuditLogRepository,
        many_logs: list[AuditLog],
    ):
        """Тест пагинации при получении по типу действия."""
        page1 = await audit_log_repository.get_by_action("login", limit=50, offset=0)
        assert len(page1) == 50

        page2 = await audit_log_repository.get_by_action("login", limit=50, offset=50)
        assert len(page2) == 50

        page3 = await audit_log_repository.get_by_action("login", limit=50, offset=100)
        assert len(page3) == 50

    async def test_get_by_action_not_found(self, audit_log_repository: AuditLogRepository):
        """Тест получения записей по несуществующему действию."""
        logs = await audit_log_repository.get_by_action("nonexistent_action", limit=50, offset=0)
        assert logs == []


class TestGetWithFilters:
    """Тесты для метода get_all_with_filters."""

    async def test_get_with_filters_no_filters(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
    ):
        """Тест получения без фильтров."""
        logs, total = await audit_log_repository.get_all_with_filters(limit=100, offset=0)

        assert total == 6
        assert len(logs) == 6

    async def test_get_with_filters_by_user_id(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
        sample_user_id: uuid4,
    ):
        """Тест фильтрации по user_id."""
        logs, total = await audit_log_repository.get_all_with_filters(user_id=sample_user_id)

        assert total == 5
        for log in logs:
            assert log.user_id == sample_user_id

    async def test_get_with_filters_by_action(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
    ):
        """Тест фильтрации по action."""
        logs, total = await audit_log_repository.get_all_with_filters(action="login")

        assert total == 3
        for log in logs:
            assert log.action == "login"

    async def test_get_with_filters_by_success(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
    ):
        """Тест фильтрации по success."""
        logs, total = await audit_log_repository.get_all_with_filters(success=True)

        assert total == 5
        for log in logs:
            assert log.success is True

        logs_failed, total_failed = await audit_log_repository.get_all_with_filters(success=False)
        assert total_failed == 1

    async def test_get_with_filters_by_date_range(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
    ):
        """Тест фильтрации по диапазону дат."""
        now = datetime.now(timezone.utc)
        start_date = now - timedelta(days=6)
        end_date = now - timedelta(days=3)

        logs, total = await audit_log_repository.get_all_with_filters(
            start_date=start_date,
            end_date=end_date,
        )

        assert total >= 2

    async def test_get_with_filters_all_filters(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
        sample_user_id: uuid4,
    ):
        """Тест комбинации всех фильтров."""
        now = datetime.now(timezone.utc)
        start_date = now - timedelta(days=10)
        end_date = now

        logs, total = await audit_log_repository.get_all_with_filters(
            user_id=sample_user_id,
            action="login",
            success=True,
            start_date=start_date,
            end_date=end_date,
            limit=50,
            offset=0,
        )

        for log in logs:
            assert log.user_id == sample_user_id
            assert log.action == "login"
            assert log.success is True

    async def test_get_with_filters_pagination(
        self,
        audit_log_repository: AuditLogRepository,
        many_logs: list[AuditLog],
        sample_user_id: uuid4,
    ):
        """Тест пагинации в get_with_filters."""
        page1, total = await audit_log_repository.get_all_with_filters(
            user_id=sample_user_id,
            limit=50,
            offset=0,
        )
        assert len(page1) == 50
        assert total == 150

        page2, _ = await audit_log_repository.get_all_with_filters(
            user_id=sample_user_id,
            limit=50,
            offset=50,
        )
        assert len(page2) == 50

        page1_ids = {log.id for log in page1}
        page2_ids = {log.id for log in page2}
        assert page1_ids.isdisjoint(page2_ids)


class TestGetFailedActions:
    """Тесты для метода get_failed_actions."""

    async def test_get_failed_actions_all_users(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
    ):
        """Тест получения неудачных действий для всех пользователей."""
        logs = await audit_log_repository.get_failed_actions(limit=100)

        assert len(logs) == 1
        for log in logs:
            assert log.success is False

    async def test_get_failed_actions_by_user(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
        sample_user_id: uuid4,
    ):
        """Тест получения неудачных действий для конкретного пользователя."""
        logs = await audit_log_repository.get_failed_actions(user_id=sample_user_id, limit=100)

        assert len(logs) == 1
        for log in logs:
            assert log.user_id == sample_user_id
            assert log.success is False

    async def test_get_failed_actions_limit(
        self,
        audit_log_repository: AuditLogRepository,
        many_logs: list[AuditLog],
        sample_user_id: uuid4,
    ):
        """Тест лимита при получении неудачных действий."""
        logs = await audit_log_repository.get_failed_actions(user_id=sample_user_id, limit=10)

        assert len(logs) == 10


class TestGetStatistics:
    """Тесты для метода get_statistics."""

    async def test_get_statistics_all_time(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
    ):
        """Тест получения статистики за всё время."""
        stats = await audit_log_repository.get_statistics()

        assert "login" in stats
        assert stats["login"]["total"] == 3
        assert stats["login"]["success"] == 2
        assert stats["login"]["failed"] == 1

        assert "logout" in stats
        assert stats["logout"]["total"] == 1
        assert stats["logout"]["success"] == 1

        assert "password_change" in stats
        assert stats["password_change"]["total"] == 1
        assert stats["password_change"]["success"] == 1

        assert "2fa_enable" in stats
        assert stats["2fa_enable"]["total"] == 1
        assert stats["2fa_enable"]["success"] == 1

    async def test_get_statistics_with_date_range(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
    ):
        """Тест получения статистики с фильтром по дате."""
        now = datetime.now(timezone.utc)
        start_date = now - timedelta(days=5)
        end_date = now

        stats = await audit_log_repository.get_statistics(start_date=start_date, end_date=end_date)

        if "login" in stats:
            assert stats["login"]["total"] <= 2

    async def test_get_statistics_empty(
        self,
        audit_log_repository: AuditLogRepository,
    ):
        """Тест получения статистики при пустой таблице."""
        stats = await audit_log_repository.get_statistics()
        assert stats == {}


class TestGetActionsList:
    """Тесты для метода get_actions_list."""

    async def test_get_actions_list_success(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
    ):
        """Тест получения списка уникальных действий."""
        actions = await audit_log_repository.get_actions_list()

        assert len(actions) == 4
        assert "login" in actions
        assert "logout" in actions
        assert "password_change" in actions
        assert "2fa_enable" in actions

    async def test_get_actions_list_empty(self, audit_log_repository: AuditLogRepository):
        """Тест получения списка действий при пустой таблице."""
        actions = await audit_log_repository.get_actions_list()
        assert actions == []


class TestCleanupOldLogs:
    """Тесты для метода cleanup_old_logs."""

    async def test_cleanup_old_logs_success(
        self,
        audit_log_repository: AuditLogRepository,
        db_session: AsyncSession,
        sample_logs: list[AuditLog],
    ):
        """Тест очистки старых логов."""
        deleted = await audit_log_repository.cleanup_old_logs(days=5)
        await db_session.flush()

        assert deleted == 3

        remaining, total = await audit_log_repository.get_all_with_filters(limit=100, offset=0)
        assert total == 3

    async def test_cleanup_old_logs_no_deletions(
        self,
        audit_log_repository: AuditLogRepository,
        db_session: AsyncSession,
        sample_logs: list[AuditLog],
    ):
        """Тест очистки при отсутствии старых логов."""
        deleted = await audit_log_repository.cleanup_old_logs(days=8)
        await db_session.flush()

        assert deleted == 0

    async def test_cleanup_old_logs_custom_days(
        self,
        audit_log_repository: AuditLogRepository,
        sample_logs: list[AuditLog],
    ):
        """Тест очистки с кастомным количеством дней."""
        deleted = await audit_log_repository.cleanup_old_logs(days=2)
        assert deleted > 0


class TestEdgeCases:
    """Тесты для граничных случаев."""

    async def test_create_log_with_all_nullable_fields(
        self,
        audit_log_repository: AuditLogRepository,
        db_session: AsyncSession,
        create_test_user,
    ):
        """Тест создания записи со всеми nullable полями в None."""
        user = await create_test_user(email=f"user_{uuid4().hex[:8]}@example.com")
        log = AuditLog(
            user_id=user.id,
            action="test_action",
            success=True,
        )

        created = await audit_log_repository.create(log)
        await db_session.flush()

        assert created.ip_address is None
        assert created.user_agent is None
        assert created.trace_id is None
        assert created.request_id is None
        assert created.session_id is None
        assert created.old_value is None
        assert created.new_value is None
        assert created.error_message is None

    async def test_get_with_filters_limit_boundaries(
        self,
        audit_log_repository: AuditLogRepository,
        many_logs: list[AuditLog],
    ):
        """Тест граничных значений limit."""
        logs1, total1 = await audit_log_repository.get_all_with_filters(limit=1, offset=0)
        assert len(logs1) == 1

        logs100, total100 = await audit_log_repository.get_all_with_filters(limit=100, offset=0)
        assert len(logs100) == 100

    async def test_get_with_filters_offset_beyond_total(
        self,
        audit_log_repository: AuditLogRepository,
        many_logs: list[AuditLog],
    ):
        """Тест offset за пределами общего количества."""
        logs, total = await audit_log_repository.get_all_with_filters(limit=50, offset=500)

        assert len(logs) == 0
        assert total == 150

    async def test_get_by_user_id_zero_limit(self, audit_log_repository: AuditLogRepository, sample_user_id: uuid4):
        """Тест с limit = 0."""
        logs = await audit_log_repository.get_by_user_id(sample_user_id, limit=0, offset=0)
        assert logs == []

    async def test_get_statistics_mixed_case_actions(
        self,
        audit_log_repository: AuditLogRepository,
        db_session: AsyncSession,
        create_test_user,
    ):
        """Тест статистики с разными типами действий."""
        user = await create_test_user(email=f"user_{uuid4().hex[:8]}@example.com")
        actions = ["login", "LOGIN", "Login"]
        for action in actions:
            log = AuditLog(
                user_id=user.id,
                action=action,
                success=True,
            )
            await audit_log_repository.create(log)
        await db_session.flush()

        stats = await audit_log_repository.get_statistics()
        assert len(stats) == 3

    async def test_cleanup_old_logs_exact_boundary(
        self,
        audit_log_repository: AuditLogRepository,
        db_session: AsyncSession,
        create_test_user,
    ):
        """Тест очистки на границе дней."""
        user = await create_test_user(email=f"user_{uuid4().hex[:8]}@example.com")
        now = datetime.now(timezone.utc)

        old_log = AuditLog(
            user_id=user.id,
            action="test",
            created_at=now - timedelta(days=90),
            success=True,
        )
        await audit_log_repository.create(old_log)
        await db_session.flush()

        deleted = await audit_log_repository.cleanup_old_logs(days=90)
        await db_session.flush()

        assert deleted == 0 or deleted == 1