"""
Интеграционные тесты для UserRepository и UserSecuritySettingsRepository.

Тестирует:
- UserRepository: create, get_by_id, get_by_email_hash, get_by_phone_hash
- UserRepository: update, update_password, update_verification_token
- UserRepository: verify_email, update_reset_token, clear_reset_token
- UserRepository: block_user, unblock_user, delete
- UserRepository: list_users, count_users
- UserSecuritySettingsRepository: get_or_create, get_by_user_id, update, delete
- Граничные случаи и обработку ошибок
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.user_security_settings import UserSecuritySettings
from app.repositories.user_repository import UserRepository
from app.repositories.user_security_settings_repository import UserSecuritySettingsRepository


@pytest.fixture
async def user_repository(db_session: AsyncSession) -> UserRepository:
    """Фикстура репозитория пользователей."""
    return UserRepository(db_session)


@pytest.fixture
def sample_user() -> User:
    """Тестовый пользователь."""
    return User(
        id=uuid4(),
        email="test@example.com",
        email_hash=User.create_email_hash("test@example.com"),
        password_hash="$2b$12$test_hashed_password",
        is_active=True,
        is_email_verified=False,
    )


@pytest.fixture
async def created_user(user_repository: UserRepository, sample_user: User) -> User:
    """Созданный в БД пользователь (изолированный для каждого теста)."""
    return await user_repository.create(
        user_id=sample_user.id,
        email=sample_user.email,
        email_hash=sample_user.email_hash,
        password_hash=sample_user.password_hash,
        is_active=sample_user.is_active,
        is_email_verified=sample_user.is_email_verified,
    )


class TestUserRepositoryCreate:
    """Тесты для метода create."""

    async def test_create_user_success(self, user_repository: UserRepository, sample_user: User):
        """Тест успешного создания пользователя."""
        created = await user_repository.create(
            user_id=sample_user.id,
            email=sample_user.email,
            email_hash=sample_user.email_hash,
            password_hash=sample_user.password_hash,
            is_active=sample_user.is_active,
            is_email_verified=sample_user.is_email_verified,
        )

        assert created.id == sample_user.id
        assert created.email_hash == sample_user.email_hash
        assert created.is_active is True
        assert created.is_email_verified is False
        assert created.created_at is not None
        assert created.updated_at is not None

    async def test_create_user_duplicate_email(
        self,
        user_repository: UserRepository,
        sample_user: User,
        db_session: AsyncSession,
    ):
        """Тест создания пользователя с дублирующимся email."""
        # Создаем первого пользователя
        await user_repository.create(
            user_id=sample_user.id,
            email=sample_user.email,
            email_hash=sample_user.email_hash,
            password_hash=sample_user.password_hash,
            is_active=sample_user.is_active,
            is_email_verified=sample_user.is_email_verified,
        )
        await db_session.flush()

        # Пытаемся создать второго пользователя с тем же email_hash
        with pytest.raises(IntegrityError):
            await user_repository.create(
                user_id=uuid4(),  # ID обязательно уникальный
                email=sample_user.email,  # Тот же email
                email_hash=sample_user.email_hash,  # Тот же хэш (триггер уникальности!)
                password_hash="completely_different_hash",
                is_active=True,
                is_email_verified=False,
            )
            # Выталкиваем в базу. Здесь должна вылететь IntegrityError
            await db_session.flush()


class TestUserRepositoryGetById:
    """Тесты для метода get_by_id."""

    async def test_get_by_id_success(self, user_repository: UserRepository, created_user: User):
        """Тест успешного получения пользователя по ID."""
        retrieved = await user_repository.get_by_id(created_user.id)

        assert retrieved is not None
        if retrieved:
            assert retrieved.id == created_user.id
            assert retrieved.email_hash == created_user.email_hash

    async def test_get_by_id_not_found(self, user_repository: UserRepository):
        """Тест получения несуществующего пользователя."""
        retrieved = await user_repository.get_by_id(uuid4())
        assert retrieved is None


class TestUserRepositoryGetByEmailHash:
    """Тесты для метода get_by_email_hash."""

    async def test_get_by_email_hash_success(self, user_repository: UserRepository, created_user: User):
        """Тест успешного получения пользователя по email_hash."""
        retrieved = await user_repository.get_by_email_hash(created_user.email_hash)

        assert retrieved is not None
        if retrieved:
            assert retrieved.id == created_user.id

    async def test_get_by_email_hash_not_found(self, user_repository: UserRepository):
        """Тест получения по несуществующему email_hash."""
        email_hash = User.create_email_hash("nonexistent@example.com")
        retrieved = await user_repository.get_by_email_hash(email_hash)
        assert retrieved is None


class TestUserRepositoryGetByPhoneHash:
    """Тесты для метода get_by_phone_hash."""

    async def test_get_by_phone_hash_success(self, user_repository: UserRepository):
        """Тест успешного получения пользователя по phone_hash."""
        user_id = uuid4()
        email = "user@example.com"
        email_hash = User.create_email_hash(email)
        phone_hash = User.create_phone_hash("+79001234567")

        await user_repository.create(
            user_id=user_id,
            email=email,
            email_hash=email_hash,
            password_hash="hash",
            phone_hash=phone_hash,
        )

        retrieved = await user_repository.get_by_phone_hash(phone_hash)

        assert retrieved is not None
        if retrieved:
            assert retrieved.id == user_id

    async def test_get_by_phone_hash_not_found(self, user_repository: UserRepository):
        """Тест получения по несуществующему phone_hash."""
        phone_hash = User.create_phone_hash("+79999999999")
        retrieved = await user_repository.get_by_phone_hash(phone_hash)
        assert retrieved is None


class TestUserRepositoryUpdate:
    """Тесты для метода update."""

    async def test_update_user_success(self, user_repository: UserRepository, created_user: User):
        """Тест успешного обновления пользователя."""
        updated = await user_repository.update(
            created_user.id,
            is_active=False,
            is_email_verified=True,
        )

        assert updated is not None
        if updated:
            assert updated.is_active is False
            assert updated.is_email_verified is True

    async def test_update_user_not_found(self, user_repository: UserRepository):
        """Тест обновления несуществующего пользователя."""
        updated = await user_repository.update(uuid4(), is_active=False)
        assert updated is None

    async def test_update_automatically_sets_updated_at(self, user_repository: UserRepository, created_user: User):
        """Тест автоматического обновления updated_at."""
        original_updated_at = created_user.updated_at

        await user_repository.update(created_user.id, is_active=False)

        updated_user = await user_repository.get_by_id(created_user.id)
        assert updated_user is not None
        if updated_user:
            assert updated_user.updated_at > original_updated_at


class TestUserRepositoryUpdatePassword:
    """Тесты для метода update_password."""

    async def test_update_password_success(self, user_repository: UserRepository, created_user: User):
        """Тест успешного обновления пароля."""
        new_hash = "$2b$12$new_hashed_password_12345"

        await user_repository.update_password(created_user.id, new_hash)

        updated_user = await user_repository.get_by_id(created_user.id)
        assert updated_user is not None
        if updated_user:
            assert updated_user.password_hash == new_hash

    async def test_update_password_updates_updated_at(self, user_repository: UserRepository, created_user: User):
        """Тест обновления updated_at при смене пароля."""
        original_updated_at = created_user.updated_at

        await user_repository.update_password(created_user.id, "new_hash")

        updated_user = await user_repository.get_by_id(created_user.id)
        assert updated_user is not None
        if updated_user:
            assert updated_user.updated_at > original_updated_at


class TestUserRepositoryVerificationToken:
    """Тесты для методов работы с токенами верификации."""

    async def test_update_verification_token(self, user_repository: UserRepository, created_user: User):
        """Тест обновления токена верификации email."""
        token = "test_verification_token_123"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        await user_repository.update_verification_token(created_user.id, token, expires_at)

        updated_user = await user_repository.get_by_id(created_user.id)
        assert updated_user is not None
        if updated_user:
            assert updated_user.email_verification_token == token
            assert updated_user.email_verification_token_expires == expires_at

    async def test_get_by_verification_token(self, user_repository: UserRepository, created_user: User):
        """Тест поиска пользователя по токену верификации."""
        token = "test_verification_token_456"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        await user_repository.update_verification_token(created_user.id, token, expires_at)

        retrieved = await user_repository.get_by_verification_token(token)
        assert retrieved is not None
        if retrieved:
            assert retrieved.id == created_user.id

    async def test_verify_email(self, user_repository: UserRepository, created_user: User):
        """Тест верификации email."""
        assert created_user.is_email_verified is False

        await user_repository.verify_email(created_user.id)

        verified_user = await user_repository.get_by_id(created_user.id)
        assert verified_user is not None
        if verified_user:
            assert verified_user.is_email_verified is True
            assert verified_user.email_verification_token is None
            assert verified_user.email_verification_token_expires is None


class TestUserRepositoryResetToken:
    """Тесты для методов работы с токенами сброса пароля."""

    async def test_update_reset_token(self, user_repository: UserRepository, created_user: User):
        """Тест обновления токена сброса пароля."""
        token = "reset_token_123"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        await user_repository.update_reset_token(created_user.id, token, expires_at)

        updated_user = await user_repository.get_by_id(created_user.id)
        assert updated_user is not None
        if updated_user:
            assert updated_user.reset_password_token == token
            assert updated_user.reset_password_token_expires == expires_at

    async def test_get_by_reset_token(self, user_repository: UserRepository, created_user: User):
        """Тест поиска пользователя по токену сброса."""
        token = "reset_token_456"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        await user_repository.update_reset_token(created_user.id, token, expires_at)

        retrieved = await user_repository.get_by_reset_token(token)
        assert retrieved is not None
        if retrieved:
            assert retrieved.id == created_user.id

    async def test_clear_reset_token(self, user_repository: UserRepository, created_user: User):
        """Тест очистки токена сброса."""
        token = "reset_token_to_clear"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        await user_repository.update_reset_token(created_user.id, token, expires_at)
        cleared_user = await user_repository.clear_reset_token(created_user.id)

        assert cleared_user is not None
        assert cleared_user.reset_password_token is None
        assert cleared_user.reset_password_token_expires is None


class TestUserRepositoryBlockUnblock:
    """Тесты для методов блокировки/разблокировки."""

    async def test_block_user(self, user_repository: UserRepository, created_user: User):
        """Тест блокировки пользователя."""
        assert created_user.is_active is True

        await user_repository.block_user(created_user.id)

        blocked_user = await user_repository.get_by_id(created_user.id)
        assert blocked_user is not None
        if blocked_user:
            assert blocked_user.is_active is False

    async def test_unblock_user(self, user_repository: UserRepository, created_user: User):
        """Тест разблокировки пользователя."""
        await user_repository.block_user(created_user.id)
        blocked_user = await user_repository.get_by_id(created_user.id)
        assert blocked_user is not None
        if blocked_user:
            assert blocked_user.is_active is False

        await user_repository.unblock_user(created_user.id)
        unblocked_user = await user_repository.get_by_id(created_user.id)
        assert unblocked_user is not None
        if unblocked_user:
            assert unblocked_user.is_active is True


class TestUserRepositoryDelete:
    """Тесты для метода delete."""

    async def test_delete_user_success(self, user_repository: UserRepository, created_user: User):
        """Тест успешного удаления пользователя."""
        deleted = await user_repository.delete(created_user.id)

        assert deleted is True
        retrieved = await user_repository.get_by_id(created_user.id)
        assert retrieved is None

    async def test_delete_user_not_found(self, user_repository: UserRepository):
        """Тест удаления несуществующего пользователя."""
        deleted = await user_repository.delete(uuid4())
        assert deleted is False


class TestUserRepositoryListUsers:
    """Тесты для метода list_users."""

    @pytest.fixture
    async def multiple_users(self, user_repository: UserRepository) -> list[User]:
        """Создание нескольких пользователей."""
        users = []
        for i in range(10):
            user_id = uuid4()
            email = f"user{i}@example.com"
            email_hash = User.create_email_hash(email)
            await user_repository.create(
                user_id=user_id,
                email=email,
                email_hash=email_hash,
                password_hash=f"hash_{i}",
                is_active=i % 2 == 0,
                is_email_verified=i % 3 == 0,
            )
            user = await user_repository.get_by_id(user_id)
            if user:
                users.append(user)
        return users

    async def test_list_users_default(self, user_repository: UserRepository, multiple_users: list[User]):
        """Тест списка пользователей с настройками по умолчанию."""
        users = await user_repository.list_users()

        assert len(users) <= 20
        if len(users) > 1:
            assert users[0].created_at >= users[-1].created_at

    async def test_list_users_with_pagination(self, user_repository: UserRepository, multiple_users: list[User]):
        """Тест пагинации при получении списка."""
        page1 = await user_repository.list_users(limit=5, offset=0)
        page2 = await user_repository.list_users(limit=5, offset=5)

        assert len(page1) == 5
        assert len(page2) == 5
        if page1 and page2:
            assert page1[0].id != page2[0].id

    async def test_list_users_filter_by_active(self, user_repository: UserRepository, multiple_users: list[User]):
        """Тест фильтрации по is_active."""
        active_users = await user_repository.list_users(is_active=True)
        inactive_users = await user_repository.list_users(is_active=False)

        for user in active_users:
            assert user.is_active is True
        for user in inactive_users:
            assert user.is_active is False

    async def test_list_users_filter_by_verified(self, user_repository: UserRepository, multiple_users: list[User]):
        """Тест фильтрации по is_email_verified."""
        verified_users = await user_repository.list_users(is_email_verified=True)
        unverified_users = await user_repository.list_users(is_email_verified=False)

        for user in verified_users:
            assert user.is_email_verified is True
        for user in unverified_users:
            assert user.is_email_verified is False


class TestUserRepositoryCountUsers:
    """Тесты для метода count_users."""

    @pytest.fixture
    async def multiple_users(self, user_repository: UserRepository) -> list[User]:
        """Создание нескольких пользователей."""
        users = []
        for i in range(15):
            user_id = uuid4()
            email = f"user{i}@example.com"
            email_hash = User.create_email_hash(email)
            await user_repository.create(
                user_id=user_id,
                email=email,
                email_hash=email_hash,
                password_hash=f"hash_{i}",
                is_active=i % 2 == 0,
                is_email_verified=i % 3 == 0,
            )
            user = await user_repository.get_by_id(user_id)
            if user:
                users.append(user)
        return users

    async def test_count_users_all(self, user_repository: UserRepository, multiple_users: list[User]):
        """Тест подсчёта всех пользователей."""
        count = await user_repository.count_users()
        assert count == 15

    async def test_count_users_filter_by_active(self, user_repository: UserRepository, multiple_users: list[User]):
        """Тест подсчёта активных пользователей."""
        count_active = await user_repository.count_users(is_active=True)
        count_inactive = await user_repository.count_users(is_active=False)

        assert count_active == 8
        assert count_inactive == 7

    async def test_count_users_filter_by_verified(self, user_repository: UserRepository, multiple_users: list[User]):
        """Тест подсчёта верифицированных пользователей."""
        count_verified = await user_repository.count_users(is_email_verified=True)
        assert count_verified == 5


class TestUserSecuritySettingsRepository:
    """Интеграционные тесты для UserSecuritySettingsRepository."""

    @pytest.fixture
    async def settings_repository(self, db_session: AsyncSession) -> UserSecuritySettingsRepository:
        """Фикстура репозитория."""
        return UserSecuritySettingsRepository(db_session)

    async def test_get_or_create_creates_new(self, settings_repository: UserSecuritySettingsRepository, created_user: User):
        """Тест get_or_create создаёт новую запись."""
        settings = await settings_repository.get_or_create(created_user.id)

        assert settings is not None
        assert settings.user_id == created_user.id
        assert settings.id is not None

    async def test_get_or_create_returns_existing(self, settings_repository: UserSecuritySettingsRepository, created_user: User):
        """Тест get_or_create возвращает существующую запись."""
        created = await settings_repository.get_or_create(created_user.id)
        fetched = await settings_repository.get_or_create(created_user.id)

        assert fetched.id == created.id

    async def test_get_by_user_id_found(self, settings_repository: UserSecuritySettingsRepository, created_user: User):
        """Тест получения настроек по user_id."""
        await settings_repository.get_or_create(created_user.id)

        settings = await settings_repository.get_by_user_id(created_user.id)
        assert settings is not None
        assert settings.user_id == created_user.id

    async def test_get_by_user_id_not_found(self, settings_repository: UserSecuritySettingsRepository):
        """Тест получения несуществующих настроек."""
        settings = await settings_repository.get_by_user_id(uuid4())
        assert settings is None

    async def test_update_settings_from_dict(self, settings_repository: UserSecuritySettingsRepository, created_user: User):
        """Тест обновления настроек из словаря (без user_id)."""
        settings = await settings_repository.get_or_create(created_user.id)
        settings_id = settings.id

        updated = await settings_repository.update_from_dict(
            settings_id,
            {"totp_enabled": True, "totp_secret": "encrypted_secret"}
        )

        assert updated is not None
        assert updated.totp_enabled is True
        assert updated.totp_secret == "encrypted_secret"
        assert updated.user_id == created_user.id

    async def test_delete(self, settings_repository: UserSecuritySettingsRepository, created_user: User):
        """Тест удаления настроек."""
        await settings_repository.get_or_create(created_user.id)

        await settings_repository.delete(created_user.id)

        settings = await settings_repository.get_by_user_id(created_user.id)
        assert settings is None


class TestEdgeCases:
    """Тесты для граничных случаев."""

    @pytest.fixture
    async def settings_repo(self, db_session: AsyncSession) -> UserSecuritySettingsRepository:
        """Фикстура для UserSecuritySettingsRepository."""
        return UserSecuritySettingsRepository(db_session)

    async def test_create_user_with_minimal_fields(self, user_repository: UserRepository):
        """Тест создания пользователя с минимальными полями."""
        user_id = uuid4()
        email = "minimal@example.com"
        email_hash = User.create_email_hash(email)

        created = await user_repository.create(
            user_id=user_id,
            email=email,
            email_hash=email_hash,
            password_hash="hash",
        )

        assert created.is_active is True
        assert created.is_email_verified is False

    async def test_update_user_with_empty_values(self, user_repository: UserRepository, created_user: User):
        """Тест обновления с пустыми значениями."""
        updated = await user_repository.update(created_user.id)

        assert updated is not None
        assert updated.is_active == created_user.is_active

    async def test_get_by_empty_tokens(self, user_repository: UserRepository):
        """Тест поиска по пустым токенам."""
        result = await user_repository.get_by_verification_token("")
        assert result is None

        result = await user_repository.get_by_reset_token("")
        assert result is None

    async def test_security_settings_cascade_delete(
        self,
        user_repository: UserRepository,
        settings_repo: UserSecuritySettingsRepository,
        created_user: User,
    ):
        """Тест каскадного удаления настроек при удалении пользователя."""
        await settings_repo.get_or_create(created_user.id)
        await user_repository.delete(created_user.id)
        settings = await settings_repo.get_by_user_id(created_user.id)
        assert settings is None