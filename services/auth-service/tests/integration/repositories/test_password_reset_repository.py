"""
Интеграционные тесты для PasswordResetTokenRepository.

Тестирует:
- create - создание токена сброса пароля
- get_by_token_hash - получение токена по хэшу
- get_by_user_id - получение токена по user_id
- delete_expired - удаление просроченных токенов
- delete_by_user_id - удаление всех токенов пользователя
- Граничные случаи (несуществующий токен, истекший токен, дубликаты)
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.password_reset_token import PasswordResetToken
from app.repositories.password_reset_token_repository import PasswordResetTokenRepository


class TestPasswordResetTokenRepository:
    """Интеграционные тесты для PasswordResetTokenRepository."""

    async def test_create_token_success(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест успешного создания токена сброса пароля."""
        token, raw_token = PasswordResetToken.create_for_user(
            user_id=test_user,
            ttl_hours=1,
        )

        created = await password_reset_repository.create(token)
        await db_session.commit()

        assert created.id is not None
        assert created.user_id == test_user
        assert created.token_hash is not None
        assert created.token_hash == PasswordResetToken.create_token_hash(raw_token)
        assert created.expires_at is not None
        assert created.used_at is None
        assert created.created_at is not None

    async def test_create_token_with_custom_ttl(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест создания токена с кастомным TTL."""
        ttl_seconds = 1800  # 30 минут
        token, raw_token = PasswordResetToken.create_for_user_with_custom_ttl(
            user_id=test_user,
            ttl_seconds=ttl_seconds,
        )

        created = await password_reset_repository.create(token)
        await db_session.commit()

        now = datetime.now(timezone.utc)
        assert (created.expires_at - now).total_seconds() <= ttl_seconds + 1
        assert (created.expires_at - now).total_seconds() >= ttl_seconds - 1

    async def test_get_by_token_hash_success(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест успешного получения токена по хэшу."""
        token, raw_token = PasswordResetToken.create_for_user(
            user_id=test_user,
            ttl_hours=1,
        )
        created = await password_reset_repository.create(token)
        await db_session.commit()

        retrieved = await password_reset_repository.get_by_token_hash(created.token_hash)

        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.user_id == test_user
        assert retrieved.token_hash == created.token_hash

    async def test_get_by_token_hash_not_found(
        self,
        password_reset_repository: PasswordResetTokenRepository,
    ):
        """Тест получения несуществующего токена."""
        retrieved = await password_reset_repository.get_by_token_hash("nonexistent_hash_1234567890")
        assert retrieved is None

    async def test_get_by_user_id_success(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест успешного получения токена по user_id."""
        token, raw_token = PasswordResetToken.create_for_user(
            user_id=test_user,
            ttl_hours=1,
        )
        created = await password_reset_repository.create(token)
        await db_session.commit()

        retrieved = await password_reset_repository.get_by_user_id(test_user)

        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.user_id == test_user

    async def test_get_by_user_id_not_found(
        self,
        password_reset_repository: PasswordResetTokenRepository,
    ):
        """Тест получения токена для пользователя без активного токена."""
        unknown_user = uuid4()
        retrieved = await password_reset_repository.get_by_user_id(unknown_user)
        assert retrieved is None

    async def test_get_by_user_id_multiple_tokens(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест получения токена когда у пользователя несколько токенов."""
        # Создаём первый токен
        token1, _ = PasswordResetToken.create_for_user(user_id=test_user, ttl_hours=1)
        await password_reset_repository.create(token1)

        # Создаём второй токен
        token2, _ = PasswordResetToken.create_for_user(user_id=test_user, ttl_hours=2)
        await password_reset_repository.create(token2)

        await db_session.commit()

        # Должен вернуться первый попавшийся (не детерминировано)
        retrieved = await password_reset_repository.get_by_user_id(test_user)

        assert retrieved is not None
        assert retrieved.user_id == test_user

    async def test_delete_expired_success(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест успешного удаления просроченных токенов."""
        # Создаём активный токен
        active_token, _ = PasswordResetToken.create_for_user(
            user_id=test_user,
            ttl_hours=24,
        )
        await password_reset_repository.create(active_token)

        # Создаём просроченный токен
        expired_token, _ = PasswordResetToken.create_for_user(
            user_id=test_user,
            ttl_hours=-1,  # Истекший
        )
        await password_reset_repository.create(expired_token)

        await db_session.commit()

        deleted = await password_reset_repository.delete_expired()
        await db_session.commit()

        assert deleted == 1

        # Активный токен должен остаться
        active_retrieved = await password_reset_repository.get_by_token_hash(active_token.token_hash)
        assert active_retrieved is not None

        # Просроченный токен должен быть удалён
        expired_retrieved = await password_reset_repository.get_by_token_hash(expired_token.token_hash)
        assert expired_retrieved is None

    async def test_delete_expired_none(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест удаления когда нет просроченных токенов."""
        active_token, _ = PasswordResetToken.create_for_user(
            user_id=test_user,
            ttl_hours=24,
        )
        await password_reset_repository.create(active_token)
        await db_session.commit()

        deleted = await password_reset_repository.delete_expired()
        await db_session.commit()

        assert deleted == 0
        assert await password_reset_repository.get_by_token_hash(active_token.token_hash) is not None

    async def test_delete_by_user_id_success(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест удаления всех токенов пользователя."""
        # Создаём несколько токенов для пользователя
        token1, _ = PasswordResetToken.create_for_user(user_id=test_user, ttl_hours=1)
        token2, _ = PasswordResetToken.create_for_user(user_id=test_user, ttl_hours=2)
        token3, _ = PasswordResetToken.create_for_user(user_id=test_user, ttl_hours=3)

        await password_reset_repository.create(token1)
        await password_reset_repository.create(token2)
        await password_reset_repository.create(token3)
        await db_session.commit()

        await password_reset_repository.delete_by_user_id(test_user)
        await db_session.commit()

        # Все токены должны быть удалены
        assert await password_reset_repository.get_by_token_hash(token1.token_hash) is None
        assert await password_reset_repository.get_by_token_hash(token2.token_hash) is None
        assert await password_reset_repository.get_by_token_hash(token3.token_hash) is None

    async def test_delete_by_user_id_no_tokens(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
    ):
        """Тест удаления когда у пользователя нет токенов."""
        unknown_user = uuid4()

        # Не должно быть ошибки
        await password_reset_repository.delete_by_user_id(unknown_user)
        await db_session.commit()

    async def test_delete_by_user_id_preserves_other_users(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест что удаление не затрагивает токены других пользователей."""
        other_user = uuid4()

        # Создаём токен для пользователя
        user_token, _ = PasswordResetToken.create_for_user(user_id=test_user, ttl_hours=1)
        await password_reset_repository.create(user_token)

        # Создаём токен для другого пользователя
        other_token, _ = PasswordResetToken.create_for_user(user_id=other_user, ttl_hours=1)
        await password_reset_repository.create(other_token)

        await db_session.commit()

        await password_reset_repository.delete_by_user_id(test_user)
        await db_session.commit()

        # Токен пользователя должен быть удалён
        assert await password_reset_repository.get_by_token_hash(user_token.token_hash) is None

        # Токен другого пользователя должен остаться
        assert await password_reset_repository.get_by_token_hash(other_token.token_hash) is not None

    async def test_token_validation_after_creation(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест что созданный токен валиден."""
        token, raw_token = PasswordResetToken.create_for_user(
            user_id=test_user,
            ttl_hours=1,
        )
        created = await password_reset_repository.create(token)
        await db_session.commit()

        assert created.is_valid() is True
        assert created.is_expired() is False
        assert created.is_used() is False

    async def test_token_marked_as_used(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест отметки токена как использованного."""
        token, raw_token = PasswordResetToken.create_for_user(
            user_id=test_user,
            ttl_hours=1,
        )
        created = await password_reset_repository.create(token)
        await db_session.commit()

        created.mark_as_used()
        await db_session.commit()

        retrieved = await password_reset_repository.get_by_token_hash(created.token_hash)

        assert retrieved.is_used() is True
        assert retrieved.is_valid() is False


class TestEdgeCases:
    """Тесты для граничных случаев."""

    async def test_create_token_minimum_ttl(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест создания токена с минимальным TTL."""
        min_ttl = 60  # 1 минута
        token, _ = PasswordResetToken.create_for_user_with_custom_ttl(
            user_id=test_user,
            ttl_seconds=min_ttl,
        )

        created = await password_reset_repository.create(token)
        await db_session.commit()

        now = datetime.now(timezone.utc)
        assert (created.expires_at - now).total_seconds() <= min_ttl + 1

    async def test_create_token_maximum_ttl(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест создания токена с максимальным TTL."""
        max_ttl = 86400  # 24 часа
        token, _ = PasswordResetToken.create_for_user_with_custom_ttl(
            user_id=test_user,
            ttl_seconds=max_ttl,
        )

        created = await password_reset_repository.create(token)
        await db_session.commit()

        now = datetime.now(timezone.utc)
        assert (created.expires_at - now).total_seconds() <= max_ttl + 1

    async def test_get_by_token_hash_case_sensitive(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест что поиск по хэшу регистрозависим."""
        token, raw_token = PasswordResetToken.create_for_user(
            user_id=test_user,
            ttl_hours=1,
        )
        created = await password_reset_repository.create(token)
        await db_session.commit()

        # Хэш в другом регистре
        wrong_hash = created.token_hash.upper()
        retrieved = await password_reset_repository.get_by_token_hash(wrong_hash)
        assert retrieved is None

    async def test_delete_expired_boundary(
        self,
        password_reset_repository: PasswordResetTokenRepository,
        db_session: AsyncSession,
        test_user: UUID,
    ):
        """Тест удаления на границе истечения."""
        # Создаём токен с expires_at = сейчас + 5 секунд
        # Сдвиг на 5 секунд в будущее гарантирует, что даже с учётом
        # задержек выполнения теста токен не станет просроченным
        future_time = datetime.now(timezone.utc) + timedelta(seconds=5)
        
        token = PasswordResetToken(
            user_id=test_user,
            token_hash="hash_boundary_test",
            expires_at=future_time,  # ✅ В будущем
        )
        await password_reset_repository.create(token)
        await db_session.commit()

        deleted = await password_reset_repository.delete_expired()
        await db_session.commit()

        # Токен из будущего не должен быть удалён
        assert deleted == 0
        assert await password_reset_repository.get_by_token_hash("hash_boundary_test") is not None