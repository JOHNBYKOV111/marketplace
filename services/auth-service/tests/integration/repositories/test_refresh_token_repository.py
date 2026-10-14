"""
Интеграционные тесты для RefreshTokenRepository.

Тестирует:
- create - создание токена
- create_from_object - создание из объекта
- get_by_token_id - получение по token_id
- get_active_by_token_id - получение активного токена
- get_active_by_user_id - получение всех активных токенов пользователя
- get_all_by_user_id - получение всех токенов пользователя
- revoke - отзыв токена
- revoke_all_by_user_id - отзыв всех токенов пользователя
- update_last_used - обновление метаданных
- delete_expired - удаление просроченных
- delete_by_token_id - удаление по ID
- is_active / exists - проверки
- Граничные случаи (несуществующий токен, истекший токен)
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.refresh_token import RefreshToken
from app.repositories.refresh_token_repository import RefreshTokenRepository


# ==================== ФИКСТУРЫ ====================

@pytest.fixture
async def refresh_token_repository(db_session: AsyncSession) -> RefreshTokenRepository:
    """Фикстура репозитория с реальной БД."""
    return RefreshTokenRepository(db_session)


@pytest.fixture
def sample_user_id() -> uuid4:
    """ID пользователя для тестов."""
    return uuid4()


@pytest.fixture
def sample_token_id() -> str:
    """ID токена для тестов."""
    return f"rt_{uuid4().hex}"


@pytest.fixture
async def sample_refresh_token(
    refresh_token_repository: RefreshTokenRepository,
    db_session: AsyncSession,
    sample_user_id: uuid4,
    sample_token_id: str,
) -> RefreshToken:
    """Создание тестового Refresh Token."""
    token = await refresh_token_repository.create(
        token_id=sample_token_id,
        user_id=sample_user_id,
        device_id="test_device",
        device_name="Test Device",
        ip_address="127.0.0.1",
        user_agent="pytest",
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    await db_session.commit()
    return token


# ==================== ТЕСТЫ ====================

class TestRefreshTokenRepository:
    """Интеграционные тесты для RefreshTokenRepository."""

    async def test_create_success(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест успешного создания Refresh Token."""
        token_id = f"rt_{uuid4().hex}"
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        token = await refresh_token_repository.create(
            token_id=token_id,
            user_id=sample_user_id,
            device_id="device_123",
            device_name="iPhone 15",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            expires_at=expires_at,
        )
        await db_session.commit()

        assert token.token_id == token_id
        assert token.user_id == sample_user_id
        assert token.device_id == "device_123"
        assert token.device_name == "iPhone 15"
        assert token.ip_address == "192.168.1.1"
        assert token.user_agent == "Mozilla/5.0"
        assert token.expires_at == expires_at
        assert token.revoked_at is None
        assert token.is_rotated is False

    async def test_create_minimal(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест создания Refresh Token с минимальными полями."""
        token_id = f"rt_{uuid4().hex}"

        token = await refresh_token_repository.create(
            token_id=token_id,
            user_id=sample_user_id,
        )
        await db_session.commit()

        assert token.token_id == token_id
        assert token.user_id == sample_user_id
        assert token.device_id is None
        assert token.device_name is None
        assert token.ip_address is None
        assert token.user_agent is None
        assert token.expires_at is not None

    async def test_create_from_object(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест создания Refresh Token из готового объекта."""
        token = RefreshToken.create_token(
            user_id=sample_user_id,
            expires_days=30,
            device_id="test_device",
        )

        created = await refresh_token_repository.create_from_object(token)
        await db_session.commit()

        assert created.id is not None
        assert created.token_id == token.token_id
        assert created.user_id == sample_user_id


class TestGetByTokenId:
    """Тесты для метода get_by_token_id."""

    async def test_get_by_token_id_success(
        self,
        refresh_token_repository: RefreshTokenRepository,
        sample_refresh_token: RefreshToken,
    ):
        """Тест успешного получения токена по token_id."""
        retrieved = await refresh_token_repository.get_by_token_id(sample_refresh_token.token_id)

        assert retrieved is not None
        assert retrieved.id == sample_refresh_token.id
        assert retrieved.token_id == sample_refresh_token.token_id

    async def test_get_by_token_id_not_found(
        self,
        refresh_token_repository: RefreshTokenRepository,
    ):
        """Тест получения несуществующего токена."""
        retrieved = await refresh_token_repository.get_by_token_id("nonexistent_token")
        assert retrieved is None


class TestGetActiveByTokenId:
    """Тесты для метода get_active_by_token_id."""

    async def test_get_active_by_token_id_success(
        self,
        refresh_token_repository: RefreshTokenRepository,
        sample_refresh_token: RefreshToken,
    ):
        """Тест успешного получения активного токена."""
        retrieved = await refresh_token_repository.get_active_by_token_id(sample_refresh_token.token_id)

        assert retrieved is not None
        assert retrieved.id == sample_refresh_token.id
        assert retrieved.is_active is True

    async def test_get_active_by_token_id_revoked(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_refresh_token: RefreshToken,
    ):
        """Тест получения отозванного токена (должен вернуть None)."""
        await refresh_token_repository.revoke(sample_refresh_token.token_id)
        await db_session.commit()

        retrieved = await refresh_token_repository.get_active_by_token_id(sample_refresh_token.token_id)

        assert retrieved is None


class TestGetActiveByUserId:
    """Тесты для метода get_active_by_user_id."""

    async def test_get_active_by_user_id_success(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест получения всех активных токенов пользователя."""
        # Создаём несколько токенов
        token1 = await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        token2 = await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        # Создаём отозванный токен (не должен попасть в результат)
        revoked_token = await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        await refresh_token_repository.revoke(revoked_token.token_id)

        await db_session.commit()

        active_tokens = await refresh_token_repository.get_active_by_user_id(sample_user_id)

        assert len(active_tokens) == 2
        token_ids = [t.token_id for t in active_tokens]
        assert token1.token_id in token_ids
        assert token2.token_id in token_ids
        assert revoked_token.token_id not in token_ids

    async def test_get_active_by_user_id_no_tokens(
        self,
        refresh_token_repository: RefreshTokenRepository,
    ):
        """Тест получения активных токенов пользователя без токенов."""
        tokens = await refresh_token_repository.get_active_by_user_id(uuid4())
        assert tokens == []


class TestGetAllByUserId:
    """Тесты для метода get_all_by_user_id."""

    async def test_get_all_by_user_id_success(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест получения всех токенов пользователя (включая revoked и expired)."""
        # Создаём активный токен
        await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        # Создаём отозванный токен
        revoked = await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        await refresh_token_repository.revoke(revoked.token_id)
        # Создаём истекший токен
        expired = await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )

        await db_session.commit()

        all_tokens = await refresh_token_repository.get_all_by_user_id(sample_user_id)

        assert len(all_tokens) == 3


class TestRevoke:
    """Тесты для метода revoke."""

    async def test_revoke_success(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_refresh_token: RefreshToken,
    ):
        """Тест успешного отзыва токена."""
        assert sample_refresh_token.revoked_at is None

        await refresh_token_repository.revoke(sample_refresh_token.token_id)
        await db_session.commit()

        retrieved = await refresh_token_repository.get_by_token_id(sample_refresh_token.token_id)
        assert retrieved.revoked_at is not None

    async def test_revoke_already_revoked(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_refresh_token: RefreshToken,
    ):
        """Тест отзыва уже отозванного токена."""
        await refresh_token_repository.revoke(sample_refresh_token.token_id)
        await db_session.commit()

        # Повторный отзыв не должен вызвать ошибку
        await refresh_token_repository.revoke(sample_refresh_token.token_id)
        await db_session.commit()


class TestRevokeAllByUserId:
    """Тесты для метода revoke_all_by_user_id."""

    async def test_revoke_all_by_user_id_success(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест отзыва всех токенов пользователя."""
        # Создаём несколько токенов
        token1 = await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        token2 = await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )

        await db_session.commit()

        revoked_count = await refresh_token_repository.revoke_all_by_user_id(sample_user_id)
        await db_session.commit()

        assert revoked_count == 2

        # Проверка что токены отозваны
        token1_revoked = await refresh_token_repository.get_by_token_id(token1.token_id)
        token2_revoked = await refresh_token_repository.get_by_token_id(token2.token_id)
        assert token1_revoked.revoked_at is not None
        assert token2_revoked.revoked_at is not None

    async def test_revoke_all_by_user_id_with_exception(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
        sample_token_id: str,
    ):
        """Тест отзыва всех токенов кроме указанного."""
        # Создаём 3 токена
        token1 = await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        token2 = await refresh_token_repository.create(
            token_id=sample_token_id,
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        token3 = await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )

        await db_session.commit()

        revoked_count = await refresh_token_repository.revoke_all_by_user_id(
            sample_user_id,
            except_token_id=sample_token_id,
        )
        await db_session.commit()

        assert revoked_count == 2

        # Токен с except_token_id должен остаться активным
        token2_retrieved = await refresh_token_repository.get_by_token_id(sample_token_id)
        assert token2_retrieved.revoked_at is None


class TestUpdateLastUsed:
    """Тесты для метода update_last_used."""

    async def test_update_last_used_success(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_refresh_token: RefreshToken,
    ):
        """Тест обновления метаданных токена."""
        assert sample_refresh_token.last_used_at is None
        assert sample_refresh_token.ip_address == "127.0.0.1"

        await refresh_token_repository.update_last_used(
            token_id=sample_refresh_token.token_id,
            ip_address="10.0.0.1",
            user_agent="New User Agent",
        )
        await db_session.commit()

        retrieved = await refresh_token_repository.get_by_token_id(sample_refresh_token.token_id)
        assert retrieved.last_used_at is not None
        assert retrieved.ip_address == "10.0.0.1"
        assert retrieved.user_agent == "New User Agent"

    async def test_update_last_used_only_timestamp(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_refresh_token: RefreshToken,
    ):
        """Тест обновления только временной метки."""
        await refresh_token_repository.update_last_used(token_id=sample_refresh_token.token_id)
        await db_session.commit()

        retrieved = await refresh_token_repository.get_by_token_id(sample_refresh_token.token_id)
        assert retrieved.last_used_at is not None
        # IP и User-Agent не изменились
        assert retrieved.ip_address == "127.0.0.1"


class TestDeleteExpired:
    """Тесты для метода delete_expired."""

    async def test_delete_expired_success(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест удаления просроченных токенов."""
        # Создаём активный токен
        active = await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        # Создаём просроченный токен
        expired = await refresh_token_repository.create(
            token_id=f"rt_{uuid4().hex}",
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )

        await db_session.commit()

        deleted = await refresh_token_repository.delete_expired()
        await db_session.commit()

        assert deleted == 1

        # Активный токен должен остаться
        active_retrieved = await refresh_token_repository.get_by_token_id(active.token_id)
        assert active_retrieved is not None

        # Просроченный токен должен быть удалён
        expired_retrieved = await refresh_token_repository.get_by_token_id(expired.token_id)
        assert expired_retrieved is None


class TestDeleteByTokenId:
    """Тесты для метода delete_by_token_id."""

    async def test_delete_by_token_id_success(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_refresh_token: RefreshToken,
    ):
        """Тест полного удаления токена."""
        deleted = await refresh_token_repository.delete_by_token_id(sample_refresh_token.token_id)
        await db_session.commit()

        assert deleted == 1

        retrieved = await refresh_token_repository.get_by_token_id(sample_refresh_token.token_id)
        assert retrieved is None


class TestCheckMethods:
    """Тесты для методов is_active и exists."""

    async def test_is_active_true(
        self,
        refresh_token_repository: RefreshTokenRepository,
        sample_refresh_token: RefreshToken,
    ):
        """Тест проверки активного токена."""
        is_active = await refresh_token_repository.is_active(sample_refresh_token.token_id)

        assert is_active is True

    async def test_is_active_false_revoked(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_refresh_token: RefreshToken,
    ):
        """Тест проверки отозванного токена."""
        await refresh_token_repository.revoke(sample_refresh_token.token_id)
        await db_session.commit()

        is_active = await refresh_token_repository.is_active(sample_refresh_token.token_id)

        assert is_active is False

    async def test_exists_true(
        self,
        refresh_token_repository: RefreshTokenRepository,
        sample_refresh_token: RefreshToken,
    ):
        """Тест существования токена."""
        exists = await refresh_token_repository.exists(sample_refresh_token.token_id)

        assert exists is True

    async def test_exists_false(
        self,
        refresh_token_repository: RefreshTokenRepository,
    ):
        """Тест несуществующего токена."""
        exists = await refresh_token_repository.exists("nonexistent_token")

        assert exists is False


class TestEdgeCases:
    """Тесты для граничных случаев."""

    async def test_create_token_with_expires_at_null(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест создания токена с expires_at = None."""
        token_id = f"rt_{uuid4().hex}"

        token = await refresh_token_repository.create(
            token_id=token_id,
            user_id=sample_user_id,
            expires_at=None,
        )
        await db_session.commit()

        assert token.expires_at is not None  # Должна быть установлена текущая дата

    async def test_get_active_by_token_id_expired(
        self,
        refresh_token_repository: RefreshTokenRepository,
        db_session: AsyncSession,
        sample_user_id: uuid4,
    ):
        """Тест получения истекшего токена (должен вернуть None)."""
        token_id = f"rt_{uuid4().hex}"
        await refresh_token_repository.create(
            token_id=token_id,
            user_id=sample_user_id,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        await db_session.commit()

        retrieved = await refresh_token_repository.get_active_by_token_id(token_id)

        assert retrieved is None

    async def test_revoke_all_by_user_id_no_tokens(
        self,
        refresh_token_repository: RefreshTokenRepository,
        sample_user_id: uuid4,
    ):
        """Тест отзыва токенов пользователя без токенов."""
        revoked_count = await refresh_token_repository.revoke_all_by_user_id(sample_user_id)

        assert revoked_count == 0

    async def test_update_last_used_nonexistent_token(
        self,
        refresh_token_repository: RefreshTokenRepository,
    ):
        """Тест обновления несуществующего токена."""
        await refresh_token_repository.update_last_used("nonexistent_token")