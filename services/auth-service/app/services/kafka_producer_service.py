"""
Сервис для работы с Kafka продюсером.

Обеспечивает:
- Публикацию доменных событий
- Маскирование чувствительных данных
- Пакетную отправку событий
- Единую точку входа для всех Kafka событий
"""

from typing import Optional, List, Tuple, Dict, Any
from uuid import UUID

from app.core.config import settings
from app.core.kafka_client import KafkaProducerClient, KafkaEvent
from app.core.logging import get_logger


logger = get_logger(__name__)


class KafkaProducerService:
    """
    Сервис для публикации событий в Kafka.
    
    Предоставляет высокоуровневые методы для отправки доменных событий
    с автоматическим маскированием чувствительных данных.
    """
    
    def __init__(self, producer: Optional[KafkaProducerClient] = None):
        """
        Инициализация сервиса.
        
        Args:
            producer: Экземпляр KafkaProducerClient (если None, используется глобальный)
        """
        from app.core.kafka_client import kafka_producer
        self._producer = producer or kafka_producer
        self._service_name = settings.APP_NAME
        self._environment = settings.ENVIRONMENT
    
    async def publish_verification_code(
        self,
        user_id: str,
        code: str,
        channel: str,
        recipient: str,
        ttl_seconds: int = 300,
        trace_id: Optional[str] = None,
    ) -> bool:
        """
        Публикация события о генерации верификационного кода.
        
        Args:
            user_id: ID пользователя
            code: Код верификации (будет замаскирован в логах)
            channel: Канал отправки (email, sms)
            recipient: Получатель (email или телефон)
            ttl_seconds: Время жизни кода в секундах
            trace_id: ID трассировки
        
        Returns:
            bool: True если событие опубликовано успешно
        """
        # Lead-защита: если продюсер отключен, не даем Python упасть с AttributeError
        if self._producer is None:
            logger.error("Kafka producer is not available")
            return False

        # Маскируем получателя для логов
        masked_recipient = self._mask_recipient(recipient, channel)
        logger.debug(
            f"Publishing verification code for user {user_id} via {channel} "
            f"to {masked_recipient}, ttl={ttl_seconds}s"
        )
        
        event = KafkaEvent(
            event_type="verification_code",
            data={
                "user_id": user_id,
                "code": code,
                "channel": channel,
                "recipient": recipient,
                "ttl_seconds": ttl_seconds,
                "environment": self._environment,
            },
            user_id=user_id,
            trace_id=trace_id,
        )
        
        return await self._producer.send_event(
            topic="verification_codes",
            event=event,
            key=user_id,
        )
    
    async def publish_user_blocked(
        self,
        user_id: UUID,
        blocked_by: str,
        reason: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> bool:
        """
        Публикация события о блокировке пользователя.
        
        Args:
            user_id: ID пользователя
            blocked_by: Кто заблокировал (admin email или system)
            reason: Причина блокировки
            trace_id: ID трассировки
        
        Returns:
            bool: True если событие опубликовано успешно
        """
        # Lead-защита: если продюсер отключен, не даем Python упасть с AttributeError
        if self._producer is None:
            logger.error("Kafka producer is not available")
            return False

        logger.info(
            f"Publishing user.blocked event for user {user_id} by {blocked_by}, "
            f"reason: {reason or 'no reason provided'}"
        )
        
        event = KafkaEvent(
            event_type="user.blocked",
            data={
                "user_id": str(user_id),
                "blocked_by": blocked_by,
                "reason": reason,
                "environment": self._environment,
            },
            user_id=str(user_id),
            trace_id=trace_id,
        )
        
        return await self._producer.send_event(
            topic="user.blocked",
            event=event,
            key=str(user_id),
        )
    
    async def publish_user_unblocked(
        self,
        user_id: UUID,
        unblocked_by: str,
        reason: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> bool:
        """
        Публикация события о разблокировке пользователя.
        
        Args:
            user_id: ID пользователя
            unblocked_by: Кто разблокировал (admin email или system)
            reason: Причина разблокировки
            trace_id: ID трассировки
        
        Returns:
            bool: True если событие опубликовано успешно
        """
        # Lead-защита: если продюсер отключен, не даем Python упасть с AttributeError
        if self._producer is None:
            logger.error("Kafka producer is not available")
            return False

        logger.info(
            f"Publishing user.unblocked event for user {user_id} by {unblocked_by}, "
            f"reason: {reason or 'no reason provided'}"
        )
        
        event = KafkaEvent(
            event_type="user.unblocked",
            data={
                "user_id": str(user_id),
                "unblocked_by": unblocked_by,
                "reason": reason,
                "environment": self._environment,
            },
            user_id=str(user_id),
            trace_id=trace_id,
        )
        
        return await self._producer.send_event(
            topic="user.unblocked",
            event=event,
            key=str(user_id),
        )
    
    async def publish_password_changed(
        self,
        user_id: UUID,
        source: str = "user",
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> bool:
        """
        Публикация события о смене пароля.
        
        Args:
            user_id: ID пользователя
            source: Источник изменения (user, admin, system)
            ip: IP адрес
            user_agent: User-Agent
            trace_id: ID трассировки
        
        Returns:
            bool: True если событие опубликовано успешно
        """
        # Lead-защита: если продюсер отключен, не даем Python упасть с AttributeError
        if self._producer is None:
            logger.error("Kafka producer is not available")
            return False

        logger.info(
            f"Publishing password.changed event for user {user_id} from {source}, "
            f"ip: {ip or 'unknown'}"
        )
        
        event = KafkaEvent(
            event_type="password.changed",
            data={
                "user_id": str(user_id),
                "source": source,
                "ip": ip,
                "user_agent": user_agent,
                "environment": self._environment,
            },
            user_id=str(user_id),
            trace_id=trace_id,
        )
        
        return await self._producer.send_event(
            topic="password.changed",
            event=event,
            key=str(user_id),
        )
    
    async def publish_session_revoked(
        self,
        user_id: UUID,
        session_id: Optional[str] = None,
        all_sessions: bool = False,
        reason: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> bool:
        """
        Публикация события об отзыве сессии.
        
        Args:
            user_id: ID пользователя
            session_id: ID сессии (если None и all_sessions=False, то текущая)
            all_sessions: Отозваны ли все сессии
            reason: Причина отзыва
            trace_id: ID трассировки
        
        Returns:
            bool: True если событие опубликовано успешно
        """
        # Lead-защита: если продюсер отключен, не даем Python упасть с AttributeError
        if self._producer is None:
            logger.error("Kafka producer is not available")
            return False

        logger.info(
            f"Publishing session.revoked event for user {user_id}, "
            f"all_sessions={all_sessions}, reason: {reason or 'user action'}"
        )
        
        event = KafkaEvent(
            event_type="session.revoked",
            data={
                "user_id": str(user_id),
                "session_id": session_id,
                "all_sessions": all_sessions,
                "reason": reason,
                "environment": self._environment,
            },
            user_id=str(user_id),
            trace_id=trace_id,
        )
        
        return await self._producer.send_event(
            topic="session.revoked",
            event=event,
            key=str(user_id),
        )
    
    async def publish_user_created(
        self,
        user_id: UUID,
        email_hash: str,
        trace_id: Optional[str] = None,
    ) -> bool:
        """
        Публикация события о создании пользователя.
        
        Args:
            user_id: ID пользователя
            email_hash: Хеш email
            trace_id: ID трассировки
        
        Returns:
            bool: True если событие опубликовано успешно
        """
        # Lead-защита: если продюсер отключен, не даем Python упасть с AttributeError
        if self._producer is None:
            logger.error("Kafka producer is not available")
            return False

        logger.info(f"Publishing user.created event for user {user_id}")
        
        event = KafkaEvent(
            event_type="user.created",
            data={
                "user_id": str(user_id),
                "email_hash": email_hash,
                "environment": self._environment,
            },
            user_id=str(user_id),
            trace_id=trace_id,
        )
        
        return await self._producer.send_event(
            topic="user.created",
            event=event,
            key=str(user_id),
        )
    
    async def publish_user_deleted(
        self,
        user_id: UUID,
        email_hash: str,
        trace_id: Optional[str] = None,
    ) -> bool:
        """
        Публикация события об удалении пользователя.
        
        Args:
            user_id: ID пользователя
            email_hash: Хеш email
            trace_id: ID трассировки
        
        Returns:
            bool: True если событие опубликовано успешно
        """
        # Lead-защита: если продюсер отключен, не даем Python упасть с AttributeError
        if self._producer is None:
            logger.error("Kafka producer is not available")
            return False

        logger.info(f"Publishing user.deleted event for user {user_id}")
        
        event = KafkaEvent(
            event_type="user.deleted",
            data={
                "user_id": str(user_id),
                "email_hash": email_hash,
                "environment": self._environment,
            },
            user_id=str(user_id),
            trace_id=trace_id,
        )
        
        return await self._producer.send_event(
            topic="user.deleted",
            event=event,
            key=str(user_id),
        )
    
    async def publish_email_verified(
        self,
        user_id: UUID,
        email_hash: str,
        trace_id: Optional[str] = None,
    ) -> bool:
        """
        Публикация события о верификации email.
        
        Args:
            user_id: ID пользователя
            email_hash: Хеш email
            trace_id: ID трассировки
        
        Returns:
            bool: True если событие опубликовано успешно
        """
        # Lead-защита: если продюсер отключен, не даем Python упасть с AttributeError
        if self._producer is None:
            logger.error("Kafka producer is not available")
            return False

        logger.info(f"Publishing email.verified event for user {user_id}")
        
        event = KafkaEvent(
            event_type="user.email.verified",
            data={
                "user_id": str(user_id),
                "email_hash": email_hash,
                "environment": self._environment,
            },
            user_id=str(user_id),
            trace_id=trace_id,
        )
        
        return await self._producer.send_event(
            topic="user.email.verified",
            event=event,
            key=str(user_id),
        )
    
    async def publish_batch(
        self,
        events: List[Tuple[str, str, Dict[str, Any], Optional[str]]],
        trace_id: Optional[str] = None,
    ) -> int:
        """
        Пакетная отправка событий.
        
        Args:
            events: Список кортежей (topic, event_type, data, user_id)
            trace_id: ID трассировки (будет применён ко всем событиям)
        
        Returns:
            int: Количество успешно отправленных событий
        """
        # Lead-защита: если продюсер отключен, не даем Python упасть с AttributeError
        if self._producer is None:
            logger.error("Kafka producer is not available")
            return 0

        if not events:
            logger.debug("Batch events list is empty, skipping")
            return 0
        
        logger.info(f"Publishing batch of {len(events)} events")
        
        success_count = 0
        
        for topic, event_type, data, user_id in events:
            event = KafkaEvent(
                event_type=event_type,
                data=data,
                user_id=user_id,
                trace_id=trace_id,
            )
            
            success = await self._producer.send_event(
                topic=topic,
                event=event,
                key=user_id,
            )
            
            if success:
                success_count += 1
        
        logger.debug(f"Batch published: {success_count}/{len(events)} events successful")
        return success_count
    
    def _mask_recipient(self, recipient: str, channel: str) -> str:
        """
        Маскирование получателя для логов.
        
        Args:
            recipient: Email или телефон
            channel: Канал (email, sms)
        
        Returns:
            str: Замаскированный получатель
        """
        if not recipient:
            return "[EMPTY]"
        
        if channel == "email":
            if "@" in recipient:
                local, domain = recipient.split("@", 1)
                if len(local) <= 2:
                    masked_local = local[0] + "***"
                else:
                    masked_local = local[:3] + "***"
                return f"{masked_local}@{domain}"
            return "***@***"
        
        elif channel == "sms":
            if len(recipient) >= 7:
                return f"+***{recipient[-4:]}"
            return "***"
        
        return "[REDACTED]"