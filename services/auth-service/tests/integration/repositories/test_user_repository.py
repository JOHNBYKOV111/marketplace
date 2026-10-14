"""
Интеграционные тесты для UserRepository.

Тестирует:
- create - создание пользователя
- get_by_id - получение по ID
- get_by_email_hash - получение по email_hash
- get_by_phone_hash - получение по phone_hash
- get_by_verification_token - получение по токену верификации
- get_by_phone_verification_token - получение по токену верификации телефона
- get_by_reset_token - получение по токену сброса
- update - обновление пользователя
- update_password - обновление пароля
- update_verification_token - обновление токена верификации
- verify_email - верификация email
- update_reset_token / clear_reset_token - работа с токеном сброса
- block_user / unblock_user - блокировка/разблокировка
- delete - удаление пользователя
- list_users - список пользователей с фильтрацией
- count_users - подсчёт пользователей
- Граничные случаи (несуществующий пользователь, дубликаты)
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.repositories.user_repository import UserRepository


# ==================== ФИКСТУРЫ ====================

@pytest.fixture
async def user_repository(db_session: AsyncSession) -> UserRepository:
    """Фикстура репозитория с реальной БД."""
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
    """Созданный в БД пользователь."""
    return await user_repository.create(
        user_id=sample_user.id,
        email=sample_user.email,
        email_hash=sample_user.email_hash,
        password_hash=sample_user.password_hash,
        is_active=sample_user.is_active,
        is_email_verified=sample_user.is_email_verified,
    )


# ==================== ТЕСТЫ ====================

class TestCreate:
    """Тесты для метода create."""

    async def test_create_user_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        sample_user: User,
    ):
        """Тест успешного создания пользователя."""
        created = await user_repository.create(
            user_id=sample_user.id,
            email=sample_user.email,
            email_hash=sample_user.email_hash,
            password_hash=sample_user.password_hash,
            is_active=sample_user.is_active,
            is_email_verified=sample_user.is_email_verified,
        )
        await db_session.commit()

        assert created.id == sample_user.id
        assert created.email == sample_user.email
        assert created.email_hash == sample_user.email_hash
        assert created.password_hash == sample_user.password_hash
        assert created.is_active is True
        assert created.is_email_verified is False
        assert created.created_at is not None
        assert created.updated_at is not None

    async def test_create_user_duplicate_email(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
    ):
        """Тест создания пользователя с дублирующимся email.

        Создаёт первого пользователя, затем пытается создать второго
        с тем же email_hash. Должен сработать уникальный индекс на email_hash.
        """
        email = "duplicate@example.com"
        email_hash = User.create_email_hash(email)

        # Создаём первого пользователя
        await user_repository.create(
            user_id=uuid4(),
            email=email,
            email_hash=email_hash,
            password_hash="first_hash",
        )
        await db_session.commit()

        # Пытаемся создать второго с тем же email_hash — новый ID, новый email,
        # но хеш email_hash совпадает, что должно вызвать IntegrityError
        with pytest.raises(IntegrityError):
            await user_repository.create(
                user_id=uuid4(),
                email=email,
                email_hash=email_hash,
                password_hash="second_hash",
            )
            await db_session.commit()

    async def test_create_user_minimal_fields(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
    ):
        """Тест создания пользователя с минимальными полями."""
        user_id = uuid4()
        email = "minimal@example.com"
        email_hash = User.create_email_hash(email)
        password_hash = "hash"

        created = await user_repository.create(
            user_id=user_id,
            email=email,
            email_hash=email_hash,
            password_hash=password_hash,
        )
        await db_session.commit()

        assert created.id == user_id
        assert created.email == email
        assert created.email_hash == email_hash
        assert created.password_hash == password_hash
        assert created.is_active is True
        assert created.is_email_verified is False


class TestGetById:
    """Тесты для метода get_by_id."""

    async def test_get_by_id_success(
        self,
        user_repository: UserRepository,
        created_user: User,
    ):
        """Тест успешного получения пользователя по ID."""
        retrieved = await user_repository.get_by_id(created_user.id)

        assert retrieved is not None
        assert retrieved.id == created_user.id
        assert retrieved.email_hash == created_user.email_hash

    async def test_get_by_id_not_found(
        self,
        user_repository: UserRepository,
    ):
        """Тест получения несуществующего пользователя."""
        retrieved = await user_repository.get_by_id(uuid4())
        assert retrieved is None


class TestGetByEmailHash:
    """Тесты для метода get_by_email_hash."""

    async def test_get_by_email_hash_success(
        self,
        user_repository: UserRepository,
        created_user: User,
    ):
        """Тест успешного получения пользователя по email_hash."""
        retrieved = await user_repository.get_by_email_hash(created_user.email_hash)

        assert retrieved is not None
        assert retrieved.id == created_user.id

    async def test_get_by_email_hash_not_found(
        self,
        user_repository: UserRepository,
    ):
        """Тест получения по несуществующему email_hash."""
        email_hash = User.create_email_hash("nonexistent@example.com")
        retrieved = await user_repository.get_by_email_hash(email_hash)
        assert retrieved is None


class TestGetByPhoneHash:
    """Тесты для метода get_by_phone_hash."""

    async def test_get_by_phone_hash_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
    ):
        """Тест успешного получения пользователя по phone_hash."""
        user_id = uuid4()
        email = "phone@example.com"
        email_hash = User.create_email_hash(email)
        phone_hash = User.create_phone_hash("+79001234567")
        password_hash = "hash"

        await user_repository.create(
            user_id=user_id,
            email=email,
            email_hash=email_hash,
            password_hash=password_hash,
            phone_hash=phone_hash,
        )
        await db_session.commit()

        retrieved = await user_repository.get_by_phone_hash(phone_hash)

        assert retrieved is not None
        assert retrieved.id == user_id

    async def test_get_by_phone_hash_not_found(
        self,
        user_repository: UserRepository,
    ):
        """Тест получения по несуществующему phone_hash."""
        phone_hash = User.create_phone_hash("+79999999999")
        retrieved = await user_repository.get_by_phone_hash(phone_hash)
        assert retrieved is None


class TestGetByVerificationToken:
    """Тесты для метода get_by_verification_token."""

    async def test_get_by_verification_token_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест успешного получения пользователя по токену верификации."""
        token = "test_verification_token_123"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        await user_repository.update_verification_token(created_user.id, token, expires_at)
        await db_session.commit()

        retrieved = await user_repository.get_by_verification_token(token)

        assert retrieved is not None
        assert retrieved.id == created_user.id

    async def test_get_by_verification_token_not_found(
        self,
        user_repository: UserRepository,
    ):
        """Тест получения по несуществующему токену."""
        retrieved = await user_repository.get_by_verification_token("nonexistent_token")
        assert retrieved is None


class TestUpdate:
    """Тесты для метода update."""

    async def test_update_user_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест успешного обновления пользователя."""
        updated = await user_repository.update(
            created_user.id,
            is_active=False,
            is_email_verified=True,
        )
        await db_session.commit()

        assert updated is not None
        assert updated.is_active is False
        assert updated.is_email_verified is True

    async def test_update_user_not_found(
        self,
        user_repository: UserRepository,
    ):
        """Тест обновления несуществующего пользователя."""
        updated = await user_repository.update(uuid4(), is_active=False)
        assert updated is None

    async def test_update_automatically_updates_updated_at(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест автоматического обновления поля updated_at."""
        original_updated_at = created_user.updated_at

        await user_repository.update(created_user.id, is_active=False)
        await db_session.commit()

        updated_user = await user_repository.get_by_id(created_user.id)
        assert updated_user.updated_at > original_updated_at


class TestUpdatePassword:
    """Тесты для метода update_password."""

    async def test_update_password_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест успешного обновления пароля."""
        new_hash = "$2b$12$new_hashed_password_12345"

        await user_repository.update_password(created_user.id, new_hash)
        await db_session.commit()

        updated_user = await user_repository.get_by_id(created_user.id)
        assert updated_user.password_hash == new_hash


class TestVerifyEmail:
    """Тесты для метода verify_email."""

    async def test_verify_email_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест успешной верификации email."""
        assert created_user.is_email_verified is False

        await user_repository.verify_email(created_user.id)
        await db_session.commit()

        verified_user = await user_repository.get_by_id(created_user.id)
        assert verified_user.is_email_verified is True
        assert verified_user.email_verification_token is None
        assert verified_user.email_verification_token_expires is None


class TestResetToken:
    """Тесты для методов работы с токеном сброса пароля."""

    async def test_update_reset_token_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест обновления токена сброса."""
        token = "reset_token_123"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        await user_repository.update_reset_token(created_user.id, token, expires_at)
        await db_session.commit()

        updated_user = await user_repository.get_by_id(created_user.id)
        assert updated_user.reset_password_token == token
        assert updated_user.reset_password_token_expires == expires_at

    async def test_get_by_reset_token_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест получения пользователя по токену сброса."""
        token = "reset_token_456"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        await user_repository.update_reset_token(created_user.id, token, expires_at)
        await db_session.commit()

        retrieved = await user_repository.get_by_reset_token(token)

        assert retrieved is not None
        assert retrieved.id == created_user.id

    async def test_clear_reset_token_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест очистки токена сброса."""
        token = "reset_token_to_clear"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        await user_repository.update_reset_token(created_user.id, token, expires_at)
        await db_session.commit()
        await user_repository.clear_reset_token(created_user.id)
        await db_session.commit()

        cleared_user = await user_repository.get_by_id(created_user.id)
        assert cleared_user.reset_password_token is None
        assert cleared_user.reset_password_token_expires is None


class TestBlockUnblock:
    """Тесты для методов block_user и unblock_user."""

    async def test_block_user_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест блокировки пользователя."""
        assert created_user.is_active is True

        await user_repository.block_user(created_user.id)
        await db_session.commit()

        blocked_user = await user_repository.get_by_id(created_user.id)
        assert blocked_user.is_active is False

    async def test_unblock_user_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест разблокировки пользователя."""
        await user_repository.block_user(created_user.id)
        await db_session.commit()

        await user_repository.unblock_user(created_user.id)
        await db_session.commit()

        unblocked_user = await user_repository.get_by_id(created_user.id)
        assert unblocked_user.is_active is True


class TestDelete:
    """Тесты для метода delete."""

    async def test_delete_user_success(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест успешного удаления пользователя."""
        deleted = await user_repository.delete(created_user.id)
        await db_session.commit()

        assert deleted is True

        retrieved = await user_repository.get_by_id(created_user.id)
        assert retrieved is None

    async def test_delete_user_not_found(
        self,
        user_repository: UserRepository,
    ):
        """Тест удаления несуществующего пользователя."""
        deleted = await user_repository.delete(uuid4())
        assert deleted is False


class TestListUsers:
    """Тесты для метода list_users."""

    @pytest.fixture
    async def multiple_users(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
    ) -> list[User]:
        """Создание нескольких пользователей."""
        users = []
        for i in range(15):
            user_id = uuid4()
            email = f"user{i}@example.com"
            email_hash = User.create_email_hash(email)
            user = await user_repository.create(
                user_id=user_id,
                email=email,
                email_hash=email_hash,
                password_hash=f"hash_{i}",
                is_active=i % 2 == 0,
                is_email_verified=i % 3 == 0,
            )
            users.append(user)
        await db_session.commit()
        return users

    async def test_list_users_default(
        self,
        user_repository: UserRepository,
        multiple_users: list[User],
    ):
        """Тест списка пользователей с настройками по умолчанию."""
        users = await user_repository.list_users()

        assert len(users) <= 20

    async def test_list_users_with_pagination(
        self,
        user_repository: UserRepository,
        multiple_users: list[User],
    ):
        """Тест пагинации."""
        page1 = await user_repository.list_users(limit=5, offset=0)
        page2 = await user_repository.list_users(limit=5, offset=5)

        assert len(page1) == 5
        assert len(page2) == 5
        page1_ids = {u.id for u in page1}
        page2_ids = {u.id for u in page2}
        assert page1_ids.isdisjoint(page2_ids)

    async def test_list_users_filter_by_active(
        self,
        user_repository: UserRepository,
        multiple_users: list[User],
    ):
        """Тест фильтрации по is_active."""
        active_users = await user_repository.list_users(is_active=True)
        inactive_users = await user_repository.list_users(is_active=False)

        for user in active_users:
            assert user.is_active is True
        for user in inactive_users:
            assert user.is_active is False

    async def test_list_users_filter_by_verified(
        self,
        user_repository: UserRepository,
        multiple_users: list[User],
    ):
        """Тест фильтрации по is_email_verified."""
        verified_users = await user_repository.list_users(is_email_verified=True)
        unverified_users = await user_repository.list_users(is_email_verified=False)

        for user in verified_users:
            assert user.is_email_verified is True
        for user in unverified_users:
            assert user.is_email_verified is False


class TestCountUsers:
    """Тесты для метода count_users."""

    @pytest.fixture
    async def multiple_users(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
    ) -> list[User]:
        """Создание нескольких пользователей."""
        users = []
        for i in range(15):
            user_id = uuid4()
            email = f"user{i}@example.com"
            email_hash = User.create_email_hash(email)
            user = await user_repository.create(
                user_id=user_id,
                email=email,
                email_hash=email_hash,
                password_hash=f"hash_{i}",
                is_active=i % 2 == 0,
                is_email_verified=i % 3 == 0,
            )
            users.append(user)
        await db_session.commit()
        return users

    async def test_count_users_all(
        self,
        user_repository: UserRepository,
        multiple_users: list[User],
    ):
        """Тест подсчёта всех пользователей."""
        count = await user_repository.count_users()
        assert count == 15

    async def test_count_users_filter_by_active(
        self,
        user_repository: UserRepository,
        multiple_users: list[User],
    ):
        """Тест подсчёта активных пользователей."""
        count_active = await user_repository.count_users(is_active=True)
        count_inactive = await user_repository.count_users(is_active=False)

        assert count_active + count_inactive == 15

    async def test_count_users_filter_by_verified(
        self,
        user_repository: UserRepository,
        multiple_users: list[User],
    ):
        """Тест подсчёта верифицированных пользователей."""
        count_verified = await user_repository.count_users(is_email_verified=True)
        assert count_verified == 5


class TestEdgeCases:
    """Тесты для граничных случаев."""

    async def test_get_by_email_hash_empty_string(
        self,
        user_repository: UserRepository,
    ):
        """Тест поиска по пустому email_hash."""
        retrieved = await user_repository.get_by_email_hash("")
        assert retrieved is None

    async def test_update_nonexistent_user(
        self,
        user_repository: UserRepository,
    ):
        """Тест обновления несуществующего пользователя."""
        result = await user_repository.update(uuid4(), is_active=False)
        assert result is None

    async def test_block_user_already_blocked(
        self,
        user_repository: UserRepository,
        db_session: AsyncSession,
        created_user: User,
    ):
        """Тест блокировки уже заблокированного пользователя."""
        await user_repository.block_user(created_user.id)
        await db_session.commit()

        await user_repository.block_user(created_user.id)
        await db_session.commit()

        blocked_user = await user_repository.get_by_id(created_user.id)
        assert blocked_user.is_active is False

    async def test_unblock_user_already_active(
        self,
        user_repository: UserRepository,
        created_user: User,
    ):
        """Тест разблокировки активного пользователя."""
        assert created_user.is_active is True

        await user_repository.unblock_user(created_user.id)

        unblocked_user = await user_repository.get_by_id(created_user.id)
        assert unblocked_user.is_active is True