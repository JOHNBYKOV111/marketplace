"""
Kafka клиент для auth-service.

Обеспечивает:
- Подключение к Kafka
- Публикацию событий
- Потребление событий
- Healthcheck
- Graceful shutdown
- Обработку ошибок и retry
- Производство и потребление сообщений
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List, Callable, Awaitable, Union
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from aiokafka.errors import KafkaError, KafkaConnectionError, KafkaTimeoutError
from aiokafka.helpers import create_ssl_context

from app.core.config import settings
from app.core.logging import get_logger


logger = get_logger(__name__)


# ==================== KAFKA EVENT DATACLASS ====================

@dataclass
class KafkaEvent:
    """
    Датакласс для события Kafka.
    
    Attributes:
        event_type: Тип события
        data: Данные события
        trace_id: ID трассировки (опционально)
        user_id: ID пользователя (опционально)
        source: Источник события (по умолчанию auth-service)
        version: Версия (по умолчанию 1.0)
        timestamp: Временная метка (автоматически)
    """
    event_type: str
    data: Dict[str, Any]
    trace_id: Optional[str] = None
    user_id: Optional[str] = None
    source: str = "auth-service"
    version: str = "1.0"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    
    def to_json(self) -> str:
        """
        Преобразование события в JSON строку.
        
        Returns:
            str: JSON строка
        """
        return json.dumps({
            "event_type": self.event_type,
            "data": self.data,
            "trace_id": self.trace_id,
            "user_id": self.user_id,
            "source": self.source,
            "version": self.version,
            "timestamp": self.timestamp,
        }, ensure_ascii=False)


# ==================== KAFKA PRODUCER CLIENT ====================

class KafkaProducerClient:
    """
    Клиент для работы с Kafka продюсером.
    
    Предоставляет методы для отправки событий,
    управления соединением и healthcheck.
    """
    
    def __init__(self):
        """Инициализация клиента Kafka."""
        self._producer: Optional[AIOKafkaProducer] = None
        self._initialized = False
        self._bootstrap_servers: Optional[str] = None
        self._client_id = f"auth-service-{settings.ENVIRONMENT}"
    
    async def start(self, bootstrap_servers: Optional[str] = None) -> None:
        """
        Запуск Kafka продюсера.
        
        Args:
            bootstrap_servers: Адреса брокеров Kafka
        
        Raises:
            RuntimeError: Если bootstrap_servers не указан
            Exception: При ошибке подключения
        """
        if bootstrap_servers:
            self._bootstrap_servers = bootstrap_servers
        elif settings.KAFKA_ENABLED:
            self._bootstrap_servers = settings.KAFKA_BOOTSTRAP_SERVERS
        else:
            logger.info("Kafka is disabled, skipping start")
            return
        
        if not self._bootstrap_servers:
            raise RuntimeError("Kafka bootstrap servers not provided")
        
        if self._producer is not None:
            logger.warning("Kafka producer already initialized")
            return
        
        try:
            # Настройка SSL если нужно
            ssl_context = None
            if settings.KAFKA_USE_SSL:
                ssl_context = create_ssl_context(
                    cafile=settings.KAFKA_SSL_CAFILE,
                    certfile=settings.KAFKA_SSL_CERTFILE,
                    keyfile=settings.KAFKA_SSL_KEYFILE,
                )
            
            # Создаем продюсера
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                client_id=self._client_id,
                acks=settings.KAFKA_PRODUCER_ACKS,
                max_batch_size=settings.KAFKA_PRODUCER_MAX_BATCH_SIZE,
                compression_type=settings.KAFKA_PRODUCER_COMPRESSION_TYPE,
                linger_ms=settings.KAFKA_PRODUCER_LINGER_MS,
                ssl_context=ssl_context,
                security_protocol=settings.KAFKA_SECURITY_PROTOCOL,
                sasl_mechanism=settings.KAFKA_SASL_MECHANISM,
                sasl_plain_username=settings.KAFKA_SASL_USERNAME,
                sasl_plain_password=settings.KAFKA_SASL_PASSWORD,
                request_timeout_ms=settings.KAFKA_REQUEST_TIMEOUT_MS,
                max_request_size=settings.KAFKA_MAX_REQUEST_SIZE,
                enable_idempotence=settings.KAFKA_ENABLE_IDEMPOTENCE,
                retry_backoff_ms=settings.KAFKA_RETRY_BACKOFF_MS,
            )
            
            # Запускаем продюсера
            await self._producer.start()
            self._initialized = True
            logger.info(f"Kafka producer started at {self._bootstrap_servers}")
            
        except Exception as e:
            self._initialized = False
            self._producer = None
            logger.error(f"Failed to start Kafka producer: {e}")
            raise
    
    async def stop(self, flush_timeout: float = 60.0) -> None:
        """
        Остановка Kafka продюсера.
        
        Args:
            flush_timeout: Таймаут для flush в секундах
        """
        if not self._producer:
            return
        
        try:
            # Flush всех ожидающих сообщений
            await asyncio.wait_for(self._producer.flush(), timeout=flush_timeout)
            logger.debug("Kafka producer flushed")
        except asyncio.TimeoutError:
            logger.warning(f"Kafka producer flush timeout after {flush_timeout}s")
        except Exception as e:
            logger.warning(f"Error during Kafka producer flush: {e}")
        
        try:
            await self._producer.stop()
            logger.info("Kafka producer stopped")
        except Exception as e:
            logger.warning(f"Error stopping Kafka producer: {e}")
        finally:
            self._producer = None
            self._initialized = False
    
    @property
    def is_initialized(self) -> bool:
        """
        Проверка статуса инициализации.
        
        Returns:
            bool: True если продюсер инициализирован
        """
        return self._initialized and self._producer is not None
    
    async def send_event(
        self,
        topic: str,
        event: KafkaEvent,
        key: Optional[str] = None,
        partition: Optional[int] = None,
        headers: Optional[List[tuple]] = None,
    ) -> bool:
        """
        Отправка события в топик.
        
        Args:
            topic: Название топика
            event: Событие KafkaEvent
            key: Ключ для партиционирования
            partition: Номер партиции
            headers: Дополнительные заголовки
        
        Returns:
            bool: True если отправлено успешно
        """
        if not self.is_initialized:
            logger.error(f"Kafka producer not initialized, cannot send to {topic}")
            return False
        
        try:
            # Формируем заголовки
            all_headers = [
                ("event_type", event.event_type),
                ("source", event.source),
                ("version", event.version),
            ]
            if event.user_id:
                all_headers.append(("user_id", event.user_id))
            if event.trace_id:
                all_headers.append(("trace_id", event.trace_id))
            if headers:
                all_headers.extend(headers)
            
            # Отправляем сообщение
            future = await self._producer.send(
                topic=topic,
                value=event.to_json().encode("utf-8"),
                key=key.encode("utf-8") if key else None,
                partition=partition,
                headers=all_headers,
                timestamp_ms=int(datetime.now(timezone.utc).timestamp() * 1000),
            )
            
            # Ждем подтверждения
            record_metadata = await future
            logger.debug(
                f"Event {event.event_type} sent to topic={topic}, "
                f"partition={record_metadata.partition}, offset={record_metadata.offset}"
            )
            return True
            
        except KafkaError as e:
            logger.error(f"Kafka error sending event to {topic}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending event to {topic}: {e}")
            return False
    
    async def send_raw(
        self,
        topic: str,
        data: Dict[str, Any],
        key: Optional[str] = None,
        partition: Optional[int] = None,
        headers: Optional[List[tuple]] = None,
    ) -> bool:
        """
        Отправка сырого словаря в топик.
        
        Args:
            topic: Название топика
            data: Данные для отправки
            key: Ключ для партиционирования
            partition: Номер партиции
            headers: Заголовки
        
        Returns:
            bool: True если отправлено успешно
        """
        if not self.is_initialized:
            logger.error(f"Kafka producer not initialized, cannot send to {topic}")
            return False
        
        # Добавляем timestamp если нет
        if "timestamp" not in data:
            data["timestamp"] = datetime.now(timezone.utc).isoformat() + "Z"
        
        try:
            # Формируем заголовки
            all_headers = [("content-type", "application/json")]
            if headers:
                all_headers.extend(headers)
            
            # Отправляем сообщение
            future = await self._producer.send(
                topic=topic,
                value=json.dumps(data, ensure_ascii=False).encode("utf-8"),
                key=key.encode("utf-8") if key else None,
                partition=partition,
                headers=all_headers,
                timestamp_ms=int(datetime.now(timezone.utc).timestamp() * 1000),
            )
            
            # Ждем подтверждения
            record_metadata = await future
            logger.debug(
                f"Raw data sent to topic={topic}, "
                f"partition={record_metadata.partition}, offset={record_metadata.offset}"
            )
            return True
            
        except KafkaError as e:
            logger.error(f"Kafka error sending raw data to {topic}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending raw data to {topic}: {e}")
            return False
    
    async def send_verification_code(
        self,
        user_id: str,
        code: str,
        channel: str,
        trace_id: Optional[str] = None,
    ) -> bool:
        """
        Отправка события верификации кода.
        
        Args:
            user_id: ID пользователя
            code: Код верификации
            channel: Канал (email, sms)
            trace_id: ID трассировки
        
        Returns:
            bool: True если отправлено успешно
        """
        topic = "verification_codes"
        
        event = KafkaEvent(
            event_type="verification_code",
            data={
                "user_id": user_id,
                "code": code,
                "channel": channel,
                "ttl_seconds": settings.OTP_TTL_SECONDS,
            },
            user_id=user_id,
            trace_id=trace_id,
        )
        
        return await self.send_event(topic, event, key=user_id)
    
    async def health_check(self) -> bool:
        """
        Проверка доступности Kafka.
        
        Returns:
            bool: True если Kafka доступна
        """
        if not self.is_initialized:
            return False
        
        try:
            metadata = await self._producer.metadata()
            return len(metadata.brokers) > 0
        except Exception as e:
            logger.warning(f"Kafka health check failed: {e}")
            return False
    
    async def get_metadata(self) -> Dict[str, Any]:
        """
        Получение метаданных Kafka.
        
        Returns:
            Dict: Метаданные с брокерами и топиками
        """
        if not self.is_initialized:
            return {
                "brokers": [],
                "topics": [],
                "error": "Producer not initialized",
                "controller_id": None,
            }
        
        try:
            metadata = await self._producer.metadata()
            
            return {
                "brokers": [
                    {"id": broker.nodeId, "host": broker.host, "port": broker.port}
                    for broker in metadata.brokers
                ],
                "topics": [
                    {
                        "name": topic,
                        "partitions": len(metadata.topics[topic].partitions)
                        if topic in metadata.topics else 0
                    }
                    for topic in metadata.topics
                    if not topic.startswith("_")
                ],
                "controller_id": metadata.controller_id,
                "error": None,
            }
        except Exception as e:
            logger.error(f"Failed to get Kafka metadata: {e}")
            return {
                "brokers": [],
                "topics": [],
                "controller_id": None,
                "error": str(e),
            }


# ==================== ГЛОБАЛЬНЫЙ ПРОДЮСЕР ====================

kafka_producer = KafkaProducerClient()


# ==================== ИНИЦИАЛИЗАЦИЯ И ЗАКРЫТИЕ ПРОДЮСЕРА ====================

async def init_kafka_producer() -> None:
    """Инициализация Kafka продюсера при старте приложения."""
    if settings.KAFKA_ENABLED:
        await kafka_producer.start()


async def close_kafka_producer() -> None:
    """Закрытие Kafka продюсера при завершении приложения."""
    await kafka_producer.stop()


# ==================== СТАРЫЙ КЛИЕНТ ДЛЯ HEALTH CHECKS ====================

class KafkaClient:
    """
    Клиент для работы с Kafka.
    
    Предоставляет методы для публикации событий,
    управления топиками и healthcheck.
    """
    
    def __init__(self):
        """Инициализация клиента Kafka."""
        self._producer: Optional[AIOKafkaProducer] = None
        self._consumer: Optional[AIOKafkaConsumer] = None
        self._connected = False
        self._bootstrap_servers = settings.KAFKA_BOOTSTRAP_SERVERS
        self._client_id = f"auth-service-{settings.ENVIRONMENT}"
    
    async def connect(self) -> None:
        """
        Установка соединения с Kafka.
        
        Raises:
            KafkaConnectionError: Если не удалось подключиться
        """
        # Проверяем включена ли Kafka
        if not settings.KAFKA_ENABLED:
            logger.info("Kafka is disabled, skipping connection")
            self._connected = False
            return
        
        if self._producer is not None:
            return
        
        try:
            # Настройка SSL если нужно
            ssl_context = None
            if settings.KAFKA_USE_SSL:
                ssl_context = create_ssl_context(
                    cafile=settings.KAFKA_SSL_CAFILE,
                    certfile=settings.KAFKA_SSL_CERTFILE,
                    keyfile=settings.KAFKA_SSL_KEYFILE,
                )
            
            # Создаем продюсера
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                client_id=self._client_id,
                acks=settings.KAFKA_ACKS,
                max_batch_size=settings.KAFKA_MAX_BATCH_SIZE,
                compression_type=settings.KAFKA_COMPRESSION_TYPE,
                ssl_context=ssl_context,
                security_protocol=settings.KAFKA_SECURITY_PROTOCOL,
                sasl_mechanism=settings.KAFKA_SASL_MECHANISM,
                sasl_plain_username=settings.KAFKA_SASL_USERNAME,
                sasl_plain_password=settings.KAFKA_SASL_PASSWORD,
                request_timeout_ms=settings.KAFKA_REQUEST_TIMEOUT_MS,
                max_request_size=settings.KAFKA_MAX_REQUEST_SIZE,
                enable_idempotence=settings.KAFKA_ENABLE_IDEMPOTENCE,
                retry_backoff_ms=settings.KAFKA_RETRY_BACKOFF_MS,
            )
            
            # Запускаем продюсера
            await self._producer.start()
            self._connected = True
            logger.info(f"Connected to Kafka at {self._bootstrap_servers}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Kafka: {e}")
            self._connected = False
            raise KafkaConnectionError(f"Kafka connection failed: {e}")
    
    async def close(self) -> None:
        """Закрытие соединения с Kafka."""
        # Закрываем продюсера
        if self._producer:
            try:
                await self._producer.stop()
                logger.info("Kafka producer closed")
            except Exception as e:
                logger.warning(f"Error closing Kafka producer: {e}")
            finally:
                self._producer = None
        
        # Закрываем консьюмера
        if self._consumer:
            try:
                await self._consumer.stop()
                logger.info("Kafka consumer closed")
            except Exception as e:
                logger.warning(f"Error closing Kafka consumer: {e}")
            finally:
                self._consumer = None
        
        self._connected = False
    
    @property
    def is_connected(self) -> bool:
        """
        Проверка статуса подключения.
        
        Returns:
            bool: True если подключение установлено
        """
        if not settings.KAFKA_ENABLED:
            return False
        return self._connected and self._producer is not None
    
    @property
    def producer(self) -> Optional[AIOKafkaProducer]:
        """
        Получение сырого продюсера Kafka.
        
        Returns:
            Optional[AIOKafkaProducer]: Продюсер или None
        """
        return self._producer
    
    async def produce(
        self,
        topic: str,
        message: Any,
        key: Optional[str] = None,
        partition: Optional[int] = None,
        headers: Optional[List[tuple]] = None,
        timestamp_ms: Optional[int] = None,
    ) -> bool:
        """
        Публикация сообщения в топик.
        """
        if not settings.KAFKA_ENABLED:
            logger.debug(f"Kafka disabled, skipping message to {topic}")
            return True
        
        if not self._producer:
            logger.warning(f"Kafka producer not available, skipping message to {topic}")
            return False
        
        try:
            if isinstance(message, (dict, list)):
                value = json.dumps(message, ensure_ascii=False).encode("utf-8")
            elif isinstance(message, str):
                value = message.encode("utf-8")
            elif isinstance(message, bytes):
                value = message
            else:
                value = str(message).encode("utf-8")
            
            if headers is None:
                headers = []
            headers.append(("content-type", "application/json"))
            
            future = await self._producer.send(
                topic=topic,
                value=value,
                key=key.encode("utf-8") if key else None,
                partition=partition,
                headers=headers,
                timestamp_ms=timestamp_ms or int(datetime.now(timezone.utc).timestamp() * 1000),
            )
            
            record_metadata = await future
            logger.debug(
                f"Message sent to topic={topic}, partition={record_metadata.partition}, "
                f"offset={record_metadata.offset}"
            )
            return True
            
        except KafkaError as e:
            logger.error(f"Kafka error sending to {topic}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending to {topic}: {e}")
            return False
    
    async def produce_event(
        self,
        event_type: str,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> bool:
        """
        Публикация событийного сообщения.
        """
        topic = f"auth.{event_type}"
        
        event = {
            "event_type": event_type,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "service": "auth-service",
            "environment": settings.ENVIRONMENT,
        }
        
        if user_id:
            event["user_id"] = user_id
        if correlation_id:
            event["correlation_id"] = correlation_id
        
        headers = [
            ("event_type", event_type),
            ("service", "auth-service"),
        ]
        if user_id:
            headers.append(("user_id", user_id))
        
        return await self.produce(
            topic=topic,
            message=event,
            key=user_id,
            headers=headers,
        )
    
    async def consume(
        self,
        topics: List[str],
        group_id: str,
        callback: Callable[[Dict[str, Any]], Awaitable[None]],
        auto_offset_reset: str = "earliest",
        enable_auto_commit: bool = True,
        max_poll_interval_ms: int = 300000,
        session_timeout_ms: int = 10000,
        heartbeat_interval_ms: int = 3000,
    ) -> None:
        """
        Потребление сообщений из топиков.
        """
        if not settings.KAFKA_ENABLED:
            logger.info("Kafka disabled, skipping consume")
            return
        
        try:
            self._consumer = AIOKafkaConsumer(
                *topics,
                bootstrap_servers=self._bootstrap_servers,
                group_id=group_id,
                client_id=f"{self._client_id}-consumer",
                auto_offset_reset=auto_offset_reset,
                enable_auto_commit=enable_auto_commit,
                max_poll_interval_ms=max_poll_interval_ms,
                session_timeout_ms=session_timeout_ms,
                heartbeat_interval_ms=heartbeat_interval_ms,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                key_deserializer=lambda k: k.decode("utf-8") if k else None,
            )
            
            await self._consumer.start()
            logger.info(f"Started consuming from topics: {topics}")
            
            async for msg in self._consumer:
                try:
                    await callback({
                        "topic": msg.topic,
                        "partition": msg.partition,
                        "offset": msg.offset,
                        "key": msg.key,
                        "value": msg.value,
                        "timestamp": msg.timestamp,
                        "headers": dict(msg.headers) if msg.headers else {},
                    })
                except Exception as e:
                    logger.error(f"Error processing message from {msg.topic}: {e}")
                    if not enable_auto_commit:
                        continue
            
        except Exception as e:
            logger.error(f"Kafka consumer error: {e}")
            raise
        finally:
            if self._consumer:
                await self._consumer.stop()
                logger.info("Kafka consumer stopped")
    
    async def get_metadata(self, topic: Optional[str] = None) -> Dict[str, Any]:
        """
        Получение метаданных о топиках.
        """
        if not settings.KAFKA_ENABLED:
            return {
                "brokers": [],
                "topics": [],
                "error": "Kafka disabled",
            }
        
        if not self._producer:
            return {
                "brokers": [],
                "topics": [],
                "error": "Producer not connected",
            }
        
        try:
            metadata = await self._producer.metadata()
            
            result = {
                "brokers": [
                    {"id": broker.nodeId, "host": broker.host, "port": broker.port}
                    for broker in metadata.brokers
                ],
                "topics": [],
            }
            
            if topic:
                topic_metadata = metadata.topics.get(topic)
                if topic_metadata:
                    result["topic_metadata"] = {
                        "partitions": [
                            {
                                "partition": p.partition,
                                "leader": p.leader,
                                "replicas": p.replicas,
                                "isr": p.isr,
                            }
                            for p in topic_metadata.partitions
                        ],
                        "error": str(topic_metadata.error) if topic_metadata.error else None,
                    }
            else:
                for topic_name, topic_metadata in metadata.topics.items():
                    if not topic_name.startswith("_"):
                        result["topics"].append({
                            "name": topic_name,
                            "partitions": len(topic_metadata.partitions),
                            "error": str(topic_metadata.error) if topic_metadata.error else None,
                        })
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to get Kafka metadata: {e}")
            return {
                "brokers": [],
                "topics": [],
                "error": str(e),
            }
    
    async def healthcheck(self) -> bool:
        """
        Проверка доступности Kafka.
        """
        if not settings.KAFKA_ENABLED:
            return True
        
        if not self._producer:
            return False
        try:
            metadata = await self.get_metadata()
            return len(metadata.get("brokers", [])) > 0
        except Exception:
            return False
    
    async def topic_exists(self, topic: str) -> bool:
        """
        Проверка существования топика.
        """
        if not settings.KAFKA_ENABLED:
            return False
        
        if not self._producer:
            return False
        try:
            metadata = await self._producer.metadata()
            return topic in metadata.topics
        except Exception:
            return False
    
    async def create_topic_if_not_exists(
        self,
        topic: str,
        num_partitions: int = 1,
        replication_factor: int = 1,
    ) -> bool:
        """
        Создание топика если он не существует.
        """
        if not settings.KAFKA_ENABLED:
            return True
        
        if await self.topic_exists(topic):
            return True
        
        try:
            logger.warning(f"Topic {topic} does not exist, will be created on first send")
            return True
        except Exception as e:
            logger.error(f"Failed to create topic {topic}: {e}")
            return False


# ==================== ГЛОБАЛЬНЫЙ КЛИЕНТ ДЛЯ HEALTH CHECKS ====================

kafka_client = KafkaClient()


# ==================== ИНИЦИАЛИЗАЦИЯ И ЗАКРЫТИЕ (HEALTH CHECKS) ====================

async def init_kafka() -> None:
    """Инициализация Kafka клиента при старте приложения."""
    await kafka_client.connect()


async def close_kafka() -> None:
    """Закрытие Kafka клиента при завершении приложения."""
    await kafka_client.close()


# ==================== HELPER ФУНКЦИИ ====================

async def publish_event(
    event_type: str,
    data: Dict[str, Any],
    user_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> bool:
    """
    Быстрая публикация события в Kafka.
    """
    return await kafka_client.produce_event(
        event_type=event_type,
        data=data,
        user_id=user_id,
        correlation_id=correlation_id,
    )


@asynccontextmanager
async def kafka_consumer_context(
    topics: List[str],
    group_id: str,
    auto_offset_reset: str = "earliest",
):
    """
    Контекстный менеджер для потребления сообщений из Kafka.
    """
    if not settings.KAFKA_ENABLED:
        yield None
        return
    
    consumer = AIOKafkaConsumer(
        *topics,
        bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
        group_id=group_id,
        auto_offset_reset=auto_offset_reset,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        key_deserializer=lambda k: k.decode("utf-8") if k else None,
    )
    try:
        await consumer.start()
        yield consumer
    finally:
        await consumer.stop()


# ==================== НОВЫЕ МЕТОДЫ ДЛЯ INTERNAL API ====================

async def publish_user_created_event(
    user_id: str,
    email_hash: str,
    is_active: bool = True,
) -> bool:
    """
    Публикация события о создании пользователя.
    """
    return await publish_event(
        event_type="user_created",
        data={
            "user_id": user_id,
            "email_hash": email_hash,
            "is_active": is_active,
        },
        user_id=user_id,
    )


async def publish_user_deleted_event(
    user_id: str,
) -> bool:
    """
    Публикация события об удалении пользователя.
    """
    return await publish_event(
        event_type="user_deleted",
        data={
            "user_id": user_id,
        },
        user_id=user_id,
    )


async def publish_password_changed_event(
    user_id: str,
    revoked_sessions_count: int = 0,
) -> bool:
    """
    Публикация события о смене пароля.
    """
    return await publish_event(
        event_type="password_changed",
        data={
            "user_id": user_id,
            "revoked_sessions_count": revoked_sessions_count,
        },
        user_id=user_id,
    )


async def publish_sessions_revoked_event(
    user_id: str,
    revoked_sessions_count: int,
    reason: Optional[str] = None,
) -> bool:
    """
    Публикация события об отзыве сессий.
    """
    return await publish_event(
        event_type="sessions_revoked",
        data={
            "user_id": user_id,
            "revoked_sessions_count": revoked_sessions_count,
            "reason": reason,
        },
        user_id=user_id,
    )