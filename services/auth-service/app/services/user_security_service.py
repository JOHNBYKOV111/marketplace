"""
Сервис для работы с настройками безопасности пользователя.

Реализует:
- Управление настройками безопасности
- Включение/отключение MFA
- Управление резервными кодами
- Управление доверенными устройствами
- Настройки сессий
"""

from typing import Optional, Dict, Any, List
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppException, NotFoundException
from app.core.logging import get_logger
from app.models.user_security_settings import UserSecuritySettings
from app.repositories.user_security_settings_repository import UserSecuritySettingsRepository
from app.services.totp_service import TOTPService

logger = get_logger(__name__)


class UserSecurityService:
    """
    Сервис для работы с настройками безопасности пользователя.

    Отвечает за:
    - Управление MFA
    - Управление резервными кодами
    - Настройки безопасности
    """

    def __init__(
        self,
        session: AsyncSession,
        settings_repo: Optional[UserSecuritySettingsRepository] = None,
        totp_service: Optional[TOTPService] = None,
    ):
        """
        Инициализация сервиса.

        Args:
            session: Асинхронная сессия БД
            settings_repo: Репозиторий настроек безопасности
            totp_service: Сервис TOTP
        """
        self.session = session
        self.settings_repo = settings_repo or UserSecuritySettingsRepository(session)
        self.totp_service = totp_service or TOTPService()

    async def get_settings(self, user_id: UUID) -> UserSecuritySettings:
        """
        Получение настроек безопасности пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            UserSecuritySettings: Настройки безопасности

        Raises:
            NotFoundException: Если настройки не найдены
        """
        settings = await self.settings_repo.get_by_user_id(user_id)
        if not settings:
            # Создаём настройки по умолчанию
            settings = await self.create_settings(user_id)
        
        return settings

    async def create_settings(self, user_id: UUID) -> UserSecuritySettings:
        """
        Создание настроек безопасности для пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            UserSecuritySettings: Созданные настройки
        """
        settings = UserSecuritySettings(
            user_id=user_id,
            totp_enabled=False,
            totp_secret=None,
            totp_backup_codes=[],
            last_password_change=None,
        )
        self.session.add(settings)
        await self.session.commit()
        await self.session.refresh(settings)

        logger.info(f"Security settings created for user: {user_id}")
        return settings

    async def update_settings(
        self,
        user_id: UUID,
        **kwargs,
    ) -> Optional[UserSecuritySettings]:
        """
        Обновление настроек безопасности пользователя.

        Args:
            user_id: ID пользователя
            **kwargs: Поля для обновления

        Returns:
            Optional[UserSecuritySettings]: Обновлённые настройки или None

        Raises:
            NotFoundException: Если настройки не найдены
        """
        settings = await self.settings_repo.get_by_user_id(user_id)
        if not settings:
            raise NotFoundException(f"Security settings not found for user: {user_id}")

        # Обновление только разрешённых полей
        allowed_fields = {
            "totp_enabled", "totp_secret", "totp_backup_codes",
            "last_password_change",
        }
        
        has_changes = False
        for key, value in kwargs.items():
            if key in allowed_fields and hasattr(settings, key):
                if getattr(settings, key) != value:
                    setattr(settings, key, value)
                    has_changes = True

        if has_changes:
            await self.session.commit()
            await self.session.refresh(settings)
            logger.info(f"Security settings updated for user: {user_id}")

        return settings

    async def enable_mfa(self, user_id: UUID) -> Optional[UserSecuritySettings]:
        """
        Включение MFA для пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            Optional[UserSecuritySettings]: Обновлённые настройки

        Raises:
            NotFoundException: Если настройки не найдены
            AppException: Если MFA уже включен
        """
        settings = await self.settings_repo.get_by_user_id(user_id)
        if not settings:
            raise NotFoundException(f"Security settings not found for user: {user_id}")

        if settings.totp_enabled:
            raise AppException("MFA is already enabled", code="MFA_ALREADY_ENABLED", status_code=409)

        settings.totp_enabled = True
        await self.session.commit()
        await self.session.refresh(settings)

        logger.info(f"MFA enabled for user: {user_id}")
        return settings

    async def disable_mfa(self, user_id: UUID) -> Optional[UserSecuritySettings]:
        """
        Отключение MFA для пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            Optional[UserSecuritySettings]: Обновлённые настройки

        Raises:
            NotFoundException: Если настройки не найдены
            AppException: Если MFA не включен
        """
        settings = await self.settings_repo.get_by_user_id(user_id)
        if not settings:
            raise NotFoundException(f"Security settings not found for user: {user_id}")

        if not settings.totp_enabled:
            raise AppException("MFA is not enabled", code="MFA_NOT_ENABLED", status_code=400)

        settings.totp_enabled = False
        settings.totp_secret = None
        settings.totp_backup_codes = []
        await self.session.commit()
        await self.session.refresh(settings)

        logger.info(f"MFA disabled for user: {user_id}")
        return settings

    async def save_backup_codes(
        self,
        user_id: UUID,
        backup_codes: List[str],
    ) -> Optional[UserSecuritySettings]:
        """
        Сохранение резервных кодов для пользователя.

        Args:
            user_id: ID пользователя
            backup_codes: Список резервных кодов

        Returns:
            Optional[UserSecuritySettings]: Обновлённые настройки

        Raises:
            NotFoundException: Если настройки не найдены
        """
        settings = await self.settings_repo.get_by_user_id(user_id)
        if not settings:
            raise NotFoundException(f"Security settings not found for user: {user_id}")

        settings.totp_backup_codes = backup_codes
        await self.session.commit()
        await self.session.refresh(settings)

        logger.info(f"Backup codes saved for user: {user_id}")
        return settings

    async def get_backup_codes(self, user_id: UUID) -> List[str]:
        """
        Получение резервных кодов пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            List[str]: Список резервных кодов
        """
        settings = await self.settings_repo.get_by_user_id(user_id)
        if not settings:
            return []

        return settings.totp_backup_codes or []

    async def rotate_backup_codes(self, user_id: UUID) -> List[str]:
        """
        Ротация резервных кодов.

        Args:
            user_id: ID пользователя

        Returns:
            List[str]: Новые резервные коды

        Raises:
            NotFoundException: Если настройки не найдены
            AppException: Если MFA не включен
        """
        settings = await self.settings_repo.get_by_user_id(user_id)
        if not settings:
            raise NotFoundException(f"Security settings not found for user: {user_id}")

        if not settings.totp_enabled:
            raise AppException("MFA is not enabled", code="MFA_NOT_ENABLED", status_code=400)

        # Генерация новых кодов
        new_codes = self.totp_service.generate_backup_codes()
        settings.totp_backup_codes = new_codes
        await self.session.commit()
        await self.session.refresh(settings)

        logger.info(f"Backup codes rotated for user: {user_id}")
        return new_codes

    async def verify_backup_code(
        self,
        user_id: UUID,
        code: str,
    ) -> bool:
        """
        Проверка резервного кода.

        Args:
            user_id: ID пользователя
            code: Код для проверки

        Returns:
            bool: True если код валиден
        """
        settings = await self.settings_repo.get_by_user_id(user_id)
        if not settings or not settings.totp_backup_codes:
            return False

        if code in settings.totp_backup_codes:
            # Удаление использованного кода
            settings.totp_backup_codes.remove(code)
            await self.session.commit()
            logger.info(f"Backup code used for user: {user_id}")
            return True

        return False

    async def check_mfa_status(self, user_id: UUID) -> Dict[str, Any]:
        """
        Получение статуса MFA.

        Args:
            user_id: ID пользователя

        Returns:
            Dict[str, Any]: Статус MFA
        """
        settings = await self.settings_repo.get_by_user_id(user_id)
        
        if not settings:
            return {
                "totp_enabled": False,
                "has_backup_codes": False,
                "is_setup_complete": False,
            }

        return {
            "totp_enabled": settings.totp_enabled,
            "has_backup_codes": bool(settings.totp_backup_codes),
            "is_setup_complete": settings.totp_enabled and settings.totp_secret is not None,
            "backup_codes_count": len(settings.totp_backup_codes) if settings.totp_backup_codes else 0,
        }

    async def health_check(self) -> bool:
        """
        Проверка здоровья сервиса.

        Returns:
            bool: True если сервис работает
        """
        try:
            # Проверка подключения к БД
            await self.session.execute("SELECT 1")
            return True
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False