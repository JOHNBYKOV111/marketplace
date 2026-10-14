"""
Репозиторий для работы с настройками безопасности пользователей.
"""

from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user_security_settings import UserSecuritySettings
from app.repositories.base import BaseRepository


class UserSecuritySettingsRepository(BaseRepository[UserSecuritySettings]):
    """Репозиторий для работы с настройками безопасности пользователей."""

    def __init__(self, session: AsyncSession):
        """Инициализация репозитория настроек безопасности."""
        super().__init__(UserSecuritySettings, session)

    async def get_by_user_id(self, user_id: UUID) -> Optional[UserSecuritySettings]:
        """
        Получает настройки безопасности по ID пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            Optional[UserSecuritySettings]: Найденные настройки или None
        """
        stmt = select(UserSecuritySettings).where(UserSecuritySettings.user_id == user_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_or_create(self, user_id: UUID) -> UserSecuritySettings:
        """
        Получает существующие настройки безопасности или создаёт новые.

        Args:
            user_id: ID пользователя

        Returns:
            UserSecuritySettings: Настройки безопасности
        """
        settings = await self.get_by_user_id(user_id)
        if settings:
            return settings

        settings = UserSecuritySettings(user_id=user_id)
        self.session.add(settings)
        await self.session.commit()
        await self.session.refresh(settings)
        return settings

    async def update(self, settings: UserSecuritySettings) -> UserSecuritySettings:
        """
        Обновляет настройки безопасности.

        Args:
            settings: Объект настроек безопасности

        Returns:
            UserSecuritySettings: Обновлённые настройки
        """
        await self.session.commit()
        await self.session.refresh(settings)
        return settings

    async def update_from_dict(self, obj_id: UUID, update_data: dict) -> Optional[UserSecuritySettings]:
        """
        Обновляет настройки безопасности из словаря.

        Args:
            obj_id: ID записи
            update_data: Словарь с полями для обновления

        Returns:
            Optional[UserSecuritySettings]: Обновлённые настройки или None
        """
        # Белый список разрешенных полей (защита от Mass Assignment)
        allowed_fields = {"totp_enabled", "totp_secret", "totp_backup_codes"}

        # Получаем объект из сессии
        settings = await self.get_by_id(obj_id)
        if not settings:
            return None

        # Мутируем только разрешенные поля
        has_changes = False
        for field, value in update_data.items():
            if field in allowed_fields and hasattr(settings, field):
                if getattr(settings, field) != value:
                    setattr(settings, field, value)
                    has_changes = True

        # Сохраняем только если были изменения
        if has_changes:
            await self.session.commit()
            await self.session.refresh(settings)

        return settings

    async def delete(self, user_id: UUID) -> bool:
        """
        Удаляет настройки безопасности пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            bool: True если удалено, иначе False
        """
        settings = await self.get_by_user_id(user_id)
        if not settings:
            return False

        await self.session.delete(settings)
        await self.session.commit()
        return True

    async def enable_totp(self, user_id: UUID, secret: str) -> Optional[UserSecuritySettings]:
        """
        Включает TOTP для пользователя.

        Args:
            user_id: ID пользователя
            secret: Секретный ключ TOTP

        Returns:
            Optional[UserSecuritySettings]: Обновлённые настройки или None
        """
        settings = await self.get_by_user_id(user_id)
        if not settings:
            return None

        settings.enable_totp(secret)
        await self.session.commit()
        await self.session.refresh(settings)
        return settings

    async def disable_totp(self, user_id: UUID) -> Optional[UserSecuritySettings]:
        """
        Отключает TOTP для пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            Optional[UserSecuritySettings]: Обновлённые настройки или None
        """
        settings = await self.get_by_user_id(user_id)
        if not settings:
            return None

        settings.disable_totp()
        await self.session.commit()
        await self.session.refresh(settings)
        return settings