"""
Сервис для работы с аудит-логами.
"""

from uuid import UUID
import csv
import io
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.debug import trace, logger
from app.core.exceptions import ValidationError
from app.models.audit_log import AuditLog
from app.repositories.audit_log_repository import AuditLogRepository
from app.schemas.audit import AuditLogResponse


class AuditService:
    """Сервис для работы с аудит-логами."""

    # Белый список допустимых действий
    ALLOWED_ACTIONS = {
        "LOGIN", "LOGOUT", "REGISTER", "PASSWORD_CHANGE",
        "EMAIL_VERIFY", "PHONE_VERIFY", "MFA_ENABLE", "MFA_DISABLE",
        "PROFILE_UPDATE", "ADMIN_ACTION", "USER_BLOCK", "USER_UNBLOCK",
        "TOKEN_REFRESH", "SESSION_TERMINATE", "ACCOUNT_DELETE",
        "AUDIT_EXPORT", "AUDIT_CLEANUP", "BACKUP_CODES_GENERATE",
        "SECURITY_SETTINGS_UPDATE", "PASSWORD_RESET_REQUEST",
        "PASSWORD_RESET_CONFIRM", "LOGIN_FAILED", "MFA_VERIFY",
        "MFA_SETUP", "MFA_CHALLENGE", "DEVICE_TRUST",
    }

    # Чувствительные поля для маскировки
    SENSITIVE_FIELDS = {
        "password", "password_hash", "current_password",
        "new_password", "token", "refresh_token", "access_token",
        "totp_secret", "totp_code", "backup_codes", "secret",
        "api_key", "api_secret", "private_key",
    }

    def __init__(self, session: AsyncSession):
        """
        Инициализация сервиса аудита.

        Args:
            session: Асинхронная сессия
        """
        self.session = session
        self.repository = AuditLogRepository(session)

    def _mask_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Маскировка чувствительных полей.

        Args:
            data: Данные для маскировки

        Returns:
            Dict[str, Any]: Данные с замаскированными полями
        """
        if not data:
            return data

        masked = {}
        for key, value in data.items():
            if key.lower() in self.SENSITIVE_FIELDS:
                masked[key] = "***MASKED***"
            elif isinstance(value, dict):
                masked[key] = self._mask_sensitive_data(value)
            else:
                masked[key] = value

        return masked

    @trace()
    async def log_action(
        self,
        user_id: Optional[UUID],
        action: str,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditLog:
        """
        Логирует действие пользователя.

        Args:
            user_id: ID пользователя (может быть None для неудачных попыток)
            action: Выполненное действие
            success: Успешно ли выполнено
            details: Дополнительные детали
            ip_address: IP-адрес
            user_agent: User-Agent

        Returns:
            AuditLog: Созданный аудит-лог
        """
        # Маскировка чувствительных данных
        if details:
            details = self._mask_sensitive_data(details)

        logger.info("Audit log created", extra={
            "user_id": str(user_id) if user_id else "unknown",
            "action": action,
            "success": success
        })

        return await self.repository.create_log(
            user_id=user_id,
            action=action,
            success=success,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    @trace()
    async def get_user_logs(
        self,
        user_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """
        Получает аудит-логи пользователя.

        Args:
            user_id: ID пользователя
            limit: Количество записей
            offset: Смещение

        Returns:
            List[AuditLog]: Список аудит-логов
        """
        return await self.repository.get_by_user_id(user_id, limit, offset)

    @trace()
    async def get_user_logs_count(self, user_id: UUID) -> int:
        """
        Получает количество аудит-логов пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            int: Количество аудит-логов
        """
        return await self.repository.count_by_user_id(user_id)

    @trace()
    async def get_all_logs(
        self,
        user_id: Optional[UUID] = None,
        action: Optional[str] = None,
        success: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """
        Получает аудит-логи с фильтрацией.

        Args:
            user_id: ID пользователя
            action: Действие
            success: Статус выполнения
            limit: Количество записей
            offset: Смещение

        Returns:
            List[AuditLog]: Список аудит-логов
        """
        return await self.repository.get_all_with_filters(
            user_id=user_id,
            action=action,
            success=success,
            limit=limit,
            offset=offset,
        )

    @trace()
    async def get_all_logs_count(
        self,
        user_id: Optional[UUID] = None,
        action: Optional[str] = None,
        success: Optional[bool] = None,
    ) -> int:
        """
        Получает количество аудит-логов с фильтрацией.

        Args:
            user_id: ID пользователя
            action: Действие
            success: Статус выполнения

        Returns:
            int: Количество аудит-логов
        """
        return await self.repository.count_with_filters(
            user_id=user_id,
            action=action,
            success=success,
        )

    @trace()
    async def get_actions(self) -> List[str]:
        """
        Получает список уникальных действий.

        Returns:
            List[str]: Список уникальных действий
        """
        return await self.repository.get_distinct_actions()

    # ==================== НОВЫЕ МЕТОДЫ (добавлены) ====================

    def format_export(
        self,
        logs: List[AuditLog],
        format_type: str = "json",
    ) -> Union[str, bytes]:
        """
        Форматирование логов для экспорта.

        Args:
            logs: Список логов
            format_type: Формат экспорта (json или csv)

        Returns:
            Union[str, bytes]: Данные в выбранном формате

        Raises:
            ValidationError: Неподдерживаемый формат
        """
        if not logs:
            return "[]" if format_type == "json" else ""

        log_dicts = [
            {
                "id": log.id,
                "user_id": str(log.user_id) if log.user_id else None,
                "action": log.action,
                "details": log.details,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "success": log.success,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ]

        if format_type == "json":
            return json.dumps(log_dicts, indent=2, ensure_ascii=False)

        elif format_type == "csv":
            output = io.StringIO()
            if log_dicts:
                headers = list(log_dicts[0].keys())
                writer = csv.DictWriter(output, fieldnames=headers)
                writer.writeheader()
                writer.writerows(log_dicts)
            return output.getvalue()

        else:
            raise ValidationError(f"Unsupported export format: {format_type}")

    @trace()
    async def get_logs_with_pagination(
        self,
        user_id: Optional[UUID] = None,
        action: Optional[str] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        success: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AuditLogResponse], int]:
        """
        Получение логов с фильтрацией и пагинацией.

        Args:
            user_id: ID пользователя
            action: Действие
            from_date: Дата начала
            to_date: Дата окончания
            success: Успешность
            limit: Количество записей
            offset: Смещение

        Returns:
            Tuple[List[AuditLogResponse], int]: Список логов и общее количество
        """
        filters = {}
        if action:
            filters["action"] = action
        if success is not None:
            filters["success"] = success

        logs, total = await self.repository.get_with_filters(
            user_id=str(user_id) if user_id else None,
            filters=filters,
            from_date=from_date,
            to_date=to_date,
            limit=limit,
            offset=offset,
        )

        return [AuditLogResponse.model_validate(log) for log in logs], total

    @trace()
    async def get_statistics(
        self,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Получение статистики по аудиту.

        Args:
            from_date: Дата начала
            to_date: Дата окончания

        Returns:
            Dict[str, Any]: Статистика
        """
        stats = await self.repository.get_statistics(
            from_date=from_date,
            to_date=to_date,
        )

        if from_date:
            period_days = (datetime.now() - from_date).days
        else:
            period_days = 30

        return {
            **stats,
            "period_days": period_days,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @trace()
    async def cleanup_old_logs(self, days: int = 90) -> int:
        """
        Удаление старых аудит-логов.

        Args:
            days: Срок хранения в днях

        Returns:
            int: Количество удаленных записей
        """
        if days < 30:
            raise ValidationError("Cannot delete logs younger than 30 days")

        logger.info(f"Cleaning up audit logs older than {days} days")

        deleted_count = await self.repository.cleanup_old_logs(days)

        logger.info(f"Deleted {deleted_count} audit logs")

        return deleted_count

    # ==================== СПЕЦИАЛИЗИРОВАННЫЕ МЕТОДЫ ДЛЯ ЛОГИРОВАНИЯ ====================

    @trace()
    async def log_login(
        self,
        user_id: UUID,
        ip_address: str,
        user_agent: str,
        success: bool = True,
        error: Optional[str] = None,
    ) -> AuditLog:
        """Логирование попытки входа."""
        return await self.log_action(
            user_id=user_id,
            action="LOGIN",
            success=success,
            details={"error": error} if error else None,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    @trace()
    async def log_logout(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование выхода."""
        return await self.log_action(
            user_id=user_id,
            action="LOGOUT",
            ip_address=ip_address,
        )

    @trace()
    async def log_logout_all(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование выхода на всех устройствах."""
        return await self.log_action(
            user_id=user_id,
            action="LOGOUT",
            details={"type": "logout_all"},
            ip_address=ip_address,
        )

    @trace()
    async def log_password_change(
        self,
        user_id: UUID,
        ip_address: str,
        success: bool = True,
        error: Optional[str] = None,
    ) -> AuditLog:
        """Логирование смены пароля."""
        return await self.log_action(
            user_id=user_id,
            action="PASSWORD_CHANGE",
            success=success,
            details={"error": error} if error else None,
            ip_address=ip_address,
        )

    @trace()
    async def log_mfa_enable(
        self,
        user_id: UUID,
        ip_address: str,
        success: bool = True,
        error: Optional[str] = None,
    ) -> AuditLog:
        """Логирование включения MFA."""
        return await self.log_action(
            user_id=user_id,
            action="MFA_ENABLE",
            success=success,
            details={"error": error} if error else None,
            ip_address=ip_address,
        )

    @trace()
    async def log_mfa_disable(
        self,
        user_id: UUID,
        ip_address: str,
        success: bool = True,
        error: Optional[str] = None,
    ) -> AuditLog:
        """Логирование отключения MFA."""
        return await self.log_action(
            user_id=user_id,
            action="MFA_DISABLE",
            success=success,
            details={"error": error} if error else None,
            ip_address=ip_address,
        )

    @trace()
    async def log_admin_action(
        self,
        user_id: UUID,
        target_user_id: Optional[UUID],
        action: str,
        ip_address: str,
        details: Optional[Dict] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> AuditLog:
        """Логирование действий администратора."""
        log_details = {
            "target_user_id": str(target_user_id) if target_user_id else None,
            "action": action,
            **(details or {}),
        }
        if error:
            log_details["error"] = error

        return await self.log_action(
            user_id=user_id,
            action="ADMIN_ACTION",
            success=success,
            details=log_details,
            ip_address=ip_address,
        )

    @trace()
    async def log_audit_export(
        self,
        user_id: UUID,
        ip_address: str,
        records_count: int,
    ) -> AuditLog:
        """Логирование экспорта аудит-логов."""
        return await self.log_action(
            user_id=user_id,
            action="AUDIT_EXPORT",
            details={"records_count": records_count},
            ip_address=ip_address,
        )

    @trace()
    async def log_audit_cleanup(
        self,
        user_id: UUID,
        ip_address: str,
        deleted_count: int,
    ) -> AuditLog:
        """Логирование очистки аудит-логов."""
        return await self.log_action(
            user_id=user_id,
            action="AUDIT_CLEANUP",
            details={"deleted_count": deleted_count},
            ip_address=ip_address,
        )

    @trace()
    async def log_profile_update(
        self,
        user_id: UUID,
        ip_address: str,
        updated_fields: Dict[str, Any],
    ) -> AuditLog:
        """Логирование обновления профиля."""
        # Маскировка чувствительных полей
        masked_fields = self._mask_sensitive_data(updated_fields)

        return await self.log_action(
            user_id=user_id,
            action="PROFILE_UPDATE",
            details={"updated_fields": list(masked_fields.keys())},
            ip_address=ip_address,
        )

    @trace()
    async def log_failed_login(
        self,
        ip_address: str,
        email: str,
        reason: str,
    ) -> AuditLog:
        """Логирование неудачной попытки входа."""
        return await self.log_action(
            user_id=None,
            action="LOGIN_FAILED",
            success=False,
            details={"email": email, "reason": reason},
            ip_address=ip_address,
        )

    @trace()
    async def log_blocked_login(
        self,
        email: str,
        ip_address: str,
    ) -> AuditLog:
        """Логирование попытки входа заблокированного пользователя."""
        return await self.log_action(
            user_id=None,
            action="LOGIN_FAILED",
            success=False,
            details={"email": email, "reason": "USER_BLOCKED"},
            ip_address=ip_address,
        )

    @trace()
    async def log_mfa_required(
        self,
        email: str,
        ip_address: str,
    ) -> AuditLog:
        """Логирование требования MFA."""
        return await self.log_action(
            user_id=None,
            action="MFA_CHALLENGE",
            success=True,
            details={"email": email},
            ip_address=ip_address,
        )

    @trace()
    async def log_mfa_verification_failed(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование неудачной верификации MFA."""
        return await self.log_action(
            user_id=user_id,
            action="MFA_VERIFY",
            success=False,
            details={"error": "Invalid TOTP code"},
            ip_address=ip_address,
        )

    @trace()
    async def log_mfa_disable_failed(
        self,
        user_id: UUID,
        ip_address: str,
        reason: str,
    ) -> AuditLog:
        """Логирование неудачной попытки отключения MFA."""
        return await self.log_action(
            user_id=user_id,
            action="MFA_DISABLE",
            success=False,
            details={"error": reason},
            ip_address=ip_address,
        )

    @trace()
    async def log_failed_password_change(
        self,
        user_id: UUID,
        ip_address: str,
        reason: str,
    ) -> AuditLog:
        """Логирование неудачной смены пароля."""
        return await self.log_action(
            user_id=user_id,
            action="PASSWORD_CHANGE",
            success=False,
            details={"error": reason},
            ip_address=ip_address,
        )

    @trace()
    async def log_successful_password_change(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование успешной смены пароля."""
        return await self.log_action(
            user_id=user_id,
            action="PASSWORD_CHANGE",
            success=True,
            ip_address=ip_address,
        )

    @trace()
    async def log_failed_account_deletion(
        self,
        user_id: UUID,
        ip_address: str,
        reason: str,
    ) -> AuditLog:
        """Логирование неудачного удаления аккаунта."""
        return await self.log_action(
            user_id=user_id,
            action="ACCOUNT_DELETE",
            success=False,
            details={"error": reason},
            ip_address=ip_address,
        )

    @trace()
    async def log_account_deletion(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование удаления аккаунта."""
        return await self.log_action(
            user_id=user_id,
            action="ACCOUNT_DELETE",
            success=True,
            ip_address=ip_address,
        )

    @trace()
    async def log_token_refresh(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование обновления токена."""
        return await self.log_action(
            user_id=user_id,
            action="TOKEN_REFRESH",
            success=True,
            ip_address=ip_address,
        )

    @trace()
    async def log_invalid_refresh_token(
        self,
        ip_address: str,
    ) -> AuditLog:
        """Логирование использования невалидного refresh токена."""
        return await self.log_action(
            user_id=None,
            action="TOKEN_REFRESH",
            success=False,
            details={"error": "Invalid refresh token"},
            ip_address=ip_address,
        )

    @trace()
    async def log_mfa_setup_started(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование начала настройки MFA."""
        return await self.log_action(
            user_id=user_id,
            action="MFA_SETUP",
            success=True,
            ip_address=ip_address,
        )

    @trace()
    async def log_mfa_enabled(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование успешного включения MFA."""
        return await self.log_action(
            user_id=user_id,
            action="MFA_ENABLE",
            success=True,
            ip_address=ip_address,
        )

    @trace()
    async def log_backup_codes_generated(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование генерации резервных кодов."""
        return await self.log_action(
            user_id=user_id,
            action="BACKUP_CODES_GENERATE",
            success=True,
            ip_address=ip_address,
        )

    @trace()
    async def log_security_settings_updated(
        self,
        user_id: UUID,
        ip_address: str,
        updated_fields: Dict[str, Any],
    ) -> AuditLog:
        """Логирование обновления настроек безопасности."""
        masked_fields = self._mask_sensitive_data(updated_fields)
        return await self.log_action(
            user_id=user_id,
            action="SECURITY_SETTINGS_UPDATE",
            details={"updated_fields": list(masked_fields.keys())},
            ip_address=ip_address,
        )

    @trace()
    async def log_session_terminated(
        self,
        user_id: UUID,
        session_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование завершения сессии."""
        return await self.log_action(
            user_id=user_id,
            action="SESSION_TERMINATE",
            details={"session_id": str(session_id)},
            ip_address=ip_address,
        )

    @trace()
    async def log_email_verified(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование верификации email."""
        return await self.log_action(
            user_id=user_id,
            action="EMAIL_VERIFY",
            success=True,
            ip_address=ip_address,
        )

    @trace()
    async def log_phone_verified(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> AuditLog:
        """Логирование верификации телефона."""
        return await self.log_action(
            user_id=user_id,
            action="PHONE_VERIFY",
            success=True,
            ip_address=ip_address,
        )