"""
Сервис для сбора метрик системы.
"""

from typing import Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.debug import trace, logger
from app.repositories.user_repository import UserRepository


class MetricsService:
    """Сервис для сбора метрик системы."""

    def __init__(self, session: AsyncSession):
        """
        Инициализация сервиса метрик.

        Args:
            session: Асинхронная сессия
        """
        self.session = session
        self.user_repository = UserRepository(session)

    @trace()
    async def get_metrics(self) -> Dict[str, int]:
        """
        Получает метрики системы.

        Returns:
            Dict[str, int]: Метрики системы
        """
        user_metrics = await self.user_repository.get_metrics()

        logger.debug("Metrics collected", extra={
            "total_users": user_metrics["total_users"],
            "active_users": user_metrics["active_users"],
            "blocked_users": user_metrics["blocked_users"],
        })

        return {
            "total_users": user_metrics["total_users"],
            "active_users": user_metrics["active_users"],
            "blocked_users": user_metrics["blocked_users"],
            "verified_users": user_metrics["verified_users"],
            "superusers": user_metrics["superusers"],
        }