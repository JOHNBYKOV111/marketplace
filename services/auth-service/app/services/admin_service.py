"""
Сервис для административных операций.
"""

from typing import Optional, List, Dict, Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.debug import trace, logger
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditService
from app.services.metrics_service import MetricsService


class AdminService:
    """Сервис для административных операций."""

    def __init__(self, session: AsyncSession):
        """
        Инициализация административного сервиса.

        Args:
            session: Асинхронная сессия
        """
        self.session = session
        self.user_repository = UserRepository(session)
        self.audit_service = AuditService(session)
        self.metrics_service = MetricsService(session)

    @trace()
    async def get_user(self, user_id: UUID) -> Optional[User]:
        """
        Получает пользователя по ID.

        Args:
            user_id: ID пользователя

        Returns:
            Optional[User]: Найденный пользователь или None
        """
        # ПРОД-ЛИД ФИКС: используем метод get_by_id вместо get
        # для корректной работы с новой структурой БД
        user = await self.user_repository.get_by_id(user_id)
        
        if not user:
            logger.debug("User not found", extra={"user_id": str(user_id)})
        
        return user

    @trace()
    async def get_users(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[User]:
        """
        Получает список пользователей.

        Args:
            limit: Количество записей
            offset: Смещение
            filters: Фильтры

        Returns:
            List[User]: Список пользователей
        """
        return await self.user_repository.get_all(
            limit=limit,
            offset=offset,
            filters=filters,
        )

    @trace()
    async def get_users_count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        Получает количество пользователей.

        Args:
            filters: Фильтры

        Returns:
            int: Количество пользователей
        """
        return await self.user_repository.count(filters)

    @trace()
    async def block_user(
        self,
        user_id: UUID,
        reason: str,
        admin_id: UUID,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Блокирует пользователя.

        Args:
            user_id: ID пользователя для блокировки
            reason: Причина блокировки
            admin_id: ID администратора
            ip_address: IP-адрес администратора
            user_agent: User-Agent администратора

        Returns:
            Dict[str, Any]: Результат операции

        Raises:
            ValueError: Если пользователь не найден или блокировка невозможна
        """
        user = await self.user_repository.get_by_id(user_id)

        if not user:
            logger.warning("Block user failed", extra={
                "user_id": str(user_id),
                "reason": "user_not_found"
            })
            raise ValueError("User not found")

        if user.id == admin_id:
            logger.warning("Block user failed", extra={
                "user_id": str(user_id),
                "reason": "cannot_block_self"
            })
            raise ValueError("Cannot block yourself")

        if not user.is_active:
            logger.info("User already blocked", extra={
                "user_id": str(user_id)
            })
            return {
                "success": True,
                "user_id": user_id,
                "message": "User is already blocked",
            }

        # Обновляем статус
        await self.user_repository.update(user_id, is_active=False)

        # Логируем действие
        await self.audit_service.log_action(
            user_id=admin_id,
            action="block_user",
            success=True,
            details={
                "target_user_id": str(user_id),
                "reason": reason,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )

        logger.info("User blocked successfully", extra={
            "user_id": str(user_id),
            "admin_id": str(admin_id)
        })

        return {
            "success": True,
            "user_id": user_id,
            "message": "User blocked successfully",
        }

    @trace()
    async def unblock_user(
        self,
        user_id: UUID,
        reason: str,
        admin_id: UUID,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Разблокирует пользователя.

        Args:
            user_id: ID пользователя для разблокировки
            reason: Причина разблокировки
            admin_id: ID администратора
            ip_address: IP-адрес администратора
            user_agent: User-Agent администратора

        Returns:
            Dict[str, Any]: Результат операции

        Raises:
            ValueError: Если пользователь не найден или разблокировка невозможна
        """
        user = await self.user_repository.get_by_id(user_id)

        if not user:
            logger.warning("Unblock user failed", extra={
                "user_id": str(user_id),
                "reason": "user_not_found"
            })
            raise ValueError("User not found")

        if user.is_active:
            logger.info("User already active", extra={
                "user_id": str(user_id)
            })
            return {
                "success": True,
                "user_id": user_id,
                "message": "User is already active",
            }

        # Обновляем статус
        await self.user_repository.update(user_id, is_active=True)

        # Логируем действие
        await self.audit_service.log_action(
            user_id=admin_id,
            action="unblock_user",
            success=True,
            details={
                "target_user_id": str(user_id),
                "reason": reason,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )

        logger.info("User unblocked successfully", extra={
            "user_id": str(user_id),
            "admin_id": str(admin_id)
        })

        return {
            "success": True,
            "user_id": user_id,
            "message": "User unblocked successfully",
        }

    @trace()
    async def delete_user(
        self,
        user_id: UUID,
        admin_id: UUID,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """
        Удаляет пользователя.

        Args:
            user_id: ID пользователя для удаления
            admin_id: ID администратора
            ip_address: IP-адрес администратора
            user_agent: User-Agent администратора

        Returns:
            bool: True если пользователь удален

        Raises:
            ValueError: Если пользователь не найден
        """
        user = await self.user_repository.get_by_id(user_id)

        if not user:
            logger.warning("Delete user failed", extra={
                "user_id": str(user_id),
                "reason": "user_not_found"
            })
            raise ValueError("User not found")

        if user.id == admin_id:
            logger.warning("Delete user failed", extra={
                "user_id": str(user_id),
                "reason": "cannot_delete_self"
            })
            raise ValueError("Cannot delete yourself")

        # Удаляем пользователя
        await self.user_repository.delete(user_id)

        # Логируем действие
        await self.audit_service.log_action(
            user_id=admin_id,
            action="delete_user",
            success=True,
            details={
                "target_user_id": str(user_id),
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )

        logger.info("User deleted successfully", extra={
            "user_id": str(user_id),
            "admin_id": str(admin_id)
        })

        return True

    @trace()
    async def log_admin_action(
        self,
        admin_id: UUID,
        action: str,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """
        Логирует действие администратора.

        Args:
            admin_id: ID администратора
            action: Действие
            target_id: ID цели
            details: Детали
            ip_address: IP-адрес
            user_agent: User-Agent
        """
        await self.audit_service.log_action(
            user_id=admin_id,
            action=action,
            success=True,
            details={
                "target_id": target_id,
                **(details or {}),
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )

    @trace()
    async def get_metrics(self) -> Dict[str, int]:
        """
        Получает метрики системы.

        Returns:
            Dict[str, int]: Метрики системы
        """
        return await self.metrics_service.get_metrics()