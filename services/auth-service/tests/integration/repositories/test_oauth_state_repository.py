"""
Интеграционные тесты для OAuthStateRepository.

Тестирует:
- create - создание OAuth state
- get_by_state - получение по state
- get_by_user_id - получение по user_id
- delete_by_state - удаление по state
- delete_expired - удаление просроченных состояний
- delete_by_user_id - удаление всех состояний пользователя
- Граничные случаи (несуществующий state, истекший state, пустые результаты)
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_state import OAuthState
from app.repositories.oauth_state_repository import OAuthStateRepository


class TestOAuthStateRepository:
    """Интеграционные тесты для OAuthStateRepository."""

    @pytest.fixture
    async def oauth_state_repository(self, db_session: AsyncSession) -> OAuthStateRepository:
        """Фикстура репозитория с реальной БД."""
        return OAuthStateRepository(db_session)

    @pytest.fixture
    def sample_user_id(self) -> uuid4:
        """ID пользователя для тестов."""
        return uuid4()

    @pytest.fixture
    async def sample_oauth_state(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ) -> OAuthState:
        """Создание тестового OAuth state."""
        oauth_state, state, code_verifier = OAuthState.create_login_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            scope="email profile",
            ttl_seconds=600,
        )
        created = await oauth_state_repository.create(oauth_state)
        await db_session.flush()
        return created


class TestCreate:
    """Тесты для метода create."""

    async def test_create_oauth_state_success(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
    ):
        """Тест успешного создания OAuth state."""
        oauth_state, state, code_verifier = OAuthState.create_login_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            scope="email profile",
        )

        created = await oauth_state_repository.create(oauth_state)
        await db_session.flush()

        assert created.id is not None
        assert created.state == state
        assert created.code_verifier == code_verifier
        assert created.provider == "google"
        assert created.redirect_uri == "https://example.com/callback"
        assert created.scope == "email profile"
        assert created.is_linked is False
        assert created.expires_at is not None
        assert created.created_at is not None

    async def test_create_oauth_state_for_link(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест создания OAuth state для привязки аккаунта."""
        oauth_state, state, code_verifier = OAuthState.create_link_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            user_id=sample_user_id,
            scope="email",
        )

        created = await oauth_state_repository.create(oauth_state)
        await db_session.flush()

        assert created.user_id == sample_user_id
        assert created.is_linked is True


class TestGetByState:
    """Тесты для метода get_by_state."""

    async def test_get_by_state_success(
        self,
        oauth_state_repository: OAuthStateRepository,
        sample_oauth_state: OAuthState,
    ):
        """Тест успешного получения OAuth state по state."""
        retrieved = await oauth_state_repository.get_by_state(sample_oauth_state.state)

        assert retrieved is not None
        assert retrieved.id == sample_oauth_state.id
        assert retrieved.state == sample_oauth_state.state
        assert retrieved.provider == sample_oauth_state.provider
        assert retrieved.code_verifier == sample_oauth_state.code_verifier

    async def test_get_by_state_not_found(
        self,
        oauth_state_repository: OAuthStateRepository,
    ):
        """Тест получения несуществующего state."""
        retrieved = await oauth_state_repository.get_by_state("nonexistent_state_123")
        assert retrieved is None

    async def test_get_by_state_after_expiry(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
    ):
        """Тест получения просроченного state."""
        # Создаём state с истекшим TTL
        oauth_state, state, _ = OAuthState.create_login_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            ttl_seconds=-3600,  # Истекший
        )
        await oauth_state_repository.create(oauth_state)
        await db_session.flush()

        retrieved = await oauth_state_repository.get_by_state(state)

        assert retrieved is not None  # Запись существует в БД
        assert retrieved.is_expired() is True  # Но просрочена


class TestGetByUserId:
    """Тесты для метода get_by_user_id."""

    async def test_get_by_user_id_success(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест успешного получения OAuth state по user_id."""
        oauth_state, state, _ = OAuthState.create_link_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            user_id=sample_user_id,
        )
        await oauth_state_repository.create(oauth_state)
        await db_session.flush()

        retrieved = await oauth_state_repository.get_by_user_id(sample_user_id)

        assert retrieved is not None
        assert retrieved.user_id == sample_user_id
        assert retrieved.is_linked is True

    async def test_get_by_user_id_not_found(
        self,
        oauth_state_repository: OAuthStateRepository,
    ):
        """Тест получения state для пользователя без привязки."""
        unknown_user = uuid4()
        retrieved = await oauth_state_repository.get_by_user_id(unknown_user)
        assert retrieved is None


class TestDeleteByState:
    """Тесты для метода delete_by_state."""

    async def test_delete_by_state_success(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
        sample_oauth_state: OAuthState,
    ):
        """Тест успешного удаления OAuth state по state."""
        deleted = await oauth_state_repository.delete_by_state(sample_oauth_state.state)
        await db_session.flush()

        assert deleted == 1

        # Проверка что state удалён
        retrieved = await oauth_state_repository.get_by_state(sample_oauth_state.state)
        assert retrieved is None

    async def test_delete_by_state_not_found(
        self,
        oauth_state_repository: OAuthStateRepository,
    ):
        """Тест удаления несуществующего state."""
        deleted = await oauth_state_repository.delete_by_state("nonexistent_state")
        assert deleted == 0


class TestDeleteExpired:
    """Тесты для метода delete_expired."""

    async def test_delete_expired_success(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест удаления просроченных OAuth состояний."""
        # Создаём активный state
        active_state, _, _ = OAuthState.create_login_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            ttl_seconds=3600,
        )
        await oauth_state_repository.create(active_state)

        # Создаём просроченный state
        expired_state, _, _ = OAuthState.create_login_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            ttl_seconds=-3600,  # Истекший
        )
        await oauth_state_repository.create(expired_state)

        await db_session.flush()

        deleted = await oauth_state_repository.delete_expired()
        await db_session.flush()

        assert deleted == 1

        # Активный state должен остаться (используем get по ID)
        active_retrieved = await oauth_state_repository.get(active_state.id)
        assert active_retrieved is not None

        # Просроченный должен быть удалён
        expired_retrieved = await oauth_state_repository.get_by_state(expired_state.state)
        assert expired_retrieved is None

    async def test_delete_expired_none(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
    ):
        """Тест удаления когда нет просроченных состояний."""
        active_state, _, _ = OAuthState.create_login_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            ttl_seconds=3600,
        )
        await oauth_state_repository.create(active_state)
        await db_session.flush()

        deleted = await oauth_state_repository.delete_expired()
        await db_session.flush()

        assert deleted == 0
        assert await oauth_state_repository.get_by_state(active_state.state) is not None


class TestDeleteByUserId:
    """Тесты для метода delete_by_user_id."""

    async def test_delete_by_user_id_success(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест удаления всех OAuth состояний пользователя."""
        # Создаём несколько состояний для пользователя
        state1, _, _ = OAuthState.create_link_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            user_id=sample_user_id,
        )
        state2, _, _ = OAuthState.create_link_state(
            provider="vk",
            redirect_uri="https://example.com/callback",
            user_id=sample_user_id,
        )
        await oauth_state_repository.create(state1)
        await oauth_state_repository.create(state2)
        await db_session.flush()

        deleted = await oauth_state_repository.delete_by_user_id(sample_user_id)
        await db_session.flush()

        assert deleted == 2

        # Состояния должны быть удалены
        assert await oauth_state_repository.get_by_state(state1.state) is None
        assert await oauth_state_repository.get_by_state(state2.state) is None

    async def test_delete_by_user_id_no_states(
        self,
        oauth_state_repository: OAuthStateRepository,
    ):
        """Тест удаления когда у пользователя нет состояний."""
        unknown_user = uuid4()
        deleted = await oauth_state_repository.delete_by_user_id(unknown_user)
        assert deleted == 0

    async def test_delete_by_user_id_preserves_other_users(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест что удаление не затрагивает состояния других пользователей."""
        other_user = uuid4()

        # Создаём состояние для пользователя
        user_state, _, _ = OAuthState.create_link_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            user_id=sample_user_id,
        )
        # Создаём состояние для другого пользователя
        other_state, _, _ = OAuthState.create_link_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            user_id=other_user,
        )

        await oauth_state_repository.create(user_state)
        await oauth_state_repository.create(other_state)
        await db_session.flush()

        deleted = await oauth_state_repository.delete_by_user_id(sample_user_id)
        await db_session.flush()

        assert deleted == 1

        # Состояние пользователя удалено
        assert await oauth_state_repository.get_by_state(user_state.state) is None

        # Состояние другого пользователя осталось
        assert await oauth_state_repository.get_by_state(other_state.state) is not None


class TestEdgeCases:
    """Тесты для граничных случаев."""

    async def test_create_oauth_state_with_max_ttl(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
    ):
        """Тест создания OAuth state с максимальным TTL."""
        max_ttl = 3600
        oauth_state, state, _ = OAuthState.create_login_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            ttl_seconds=max_ttl,
        )

        created = await oauth_state_repository.create(oauth_state)
        await db_session.flush()

        assert created.expires_at > datetime.now(timezone.utc)
        assert (created.expires_at - datetime.now(timezone.utc)).total_seconds() <= max_ttl + 1

    async def test_create_oauth_state_with_min_ttl(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
    ):
        """Тест создания OAuth state с минимальным TTL."""
        min_ttl = 60
        oauth_state, state, _ = OAuthState.create_login_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            ttl_seconds=min_ttl,
        )

        created = await oauth_state_repository.create(oauth_state)
        await db_session.flush()

        assert created.expires_at > datetime.now(timezone.utc)

    async def test_get_by_state_case_sensitive(
        self,
        oauth_state_repository: OAuthStateRepository,
        sample_oauth_state: OAuthState,
    ):
        """Тест что поиск state регистрозависим."""
        # Поиск с другим регистром
        retrieved = await oauth_state_repository.get_by_state(sample_oauth_state.state.upper())
        assert retrieved is None

    async def test_delete_expired_boundary(
        self,
        oauth_state_repository: OAuthStateRepository,
        db_session: AsyncSession,
    ):
        """Тест удаления на границе истечения (Lead-подход)."""
        # Гарантированно сдвигаем время в будущее на 5 секунд.
        # Этот стейт точно НЕ должен удалиться, так как он просрочится только через 5 секунд.
        future_time = datetime.now(timezone.utc) + timedelta(seconds=5)
        
        oauth_state, state, _ = OAuthState.create_login_state(
            provider="google",
            redirect_uri="https://example.com/callback",
            ttl_seconds=5,
        )
        oauth_state.expires_at = future_time

        await oauth_state_repository.create(oauth_state)
        await db_session.flush()

        # Выполняем удаление. Наш стейт в будущем, база его не тронет.
        deleted = await oauth_state_repository.delete_expired()
        await db_session.flush()

        # Проверяем, что ничего не удалилось
        assert deleted == 0