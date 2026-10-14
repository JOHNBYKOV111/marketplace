"""
Redis клиент для auth-service.

Обеспечивает:
- Подключение к Redis
- Кэширование данных
- Хранение сессий
- Rate limiting
- Идемпотентность операций
- Healthcheck
- Graceful shutdown
- Pub/Sub для событий

Совместимость с тестами MFA:
- test_totp_verify_success: get_json() для получения TOTP сессии
- test_sms_send_success: get_idempotency_result() для проверки идемпотентности
- test_email_send_success: get_idempotency_result() для проверки идемпотентности
- test_mfa_verify_success: get_json() для получения MFA сессии
- RateLimitService.check_rate_limit(): incr() с TTL для атомарного инкремента
- test_redis_resilience: set_json() для размещения TOTP-секрета в Redis

Связанные модули:
- app.services.rate_limit_service - использует incr(), ttl(), set(), delete()
- app.routers.mfa - использует get_json(), get_idempotency_result()
- app.services.mfa_service - использует set(), get(), delete()
"""

import json
import time
from typing import Any, Dict, Optional, List, Union
from datetime import timedelta

import redis.asyncio as redis
from redis.asyncio import Redis
from redis.exceptions import RedisError, ConnectionError, TimeoutError

from app.core.config import settings
from app.core.logging import get_logger


logger = get_logger(__name__)


class RedisClient:
    """
    Клиент для работы с Redis.
    
    Предоставляет методы для кэширования, работы с сессиями,
    rate limiting, идемпотентности и pub/sub.
    """
    
    def __init__(self):
        """Инициализация клиента Redis."""
        self._client: Optional[Redis] = None
        self._initialized = False
    
    async def initialize(self, url: Optional[str] = None) -> None:
        """
        Инициализация соединения с Redis.
        
        Args:
            url: URL для подключения (если None, используется из настроек)
        
        Raises:
            RuntimeError: Если URL не указан
            ConnectionError: Если не удалось подключиться
        """
        if self._initialized:
            logger.warning("Redis already initialized")
            return
        
        redis_url = url or settings.REDIS_URL
        if not redis_url:
            raise RuntimeError("Redis URL not provided")
        
        try:
            self._client = redis.from_url(
                redis_url,
                decode_responses=True,
                max_connections=getattr(settings, "REDIS_MAX_CONNECTIONS", 10),
                socket_connect_timeout=getattr(settings, "REDIS_CONNECT_TIMEOUT", 5),
                socket_timeout=getattr(settings, "REDIS_TIMEOUT", 5),
                retry_on_timeout=True,
                health_check_interval=30,
            )
            
            await self._client.ping()
            self._initialized = True
            logger.info(f"Connected to Redis at {redis_url}")
            
        except Exception as e:
            self._client = None
            self._initialized = False
            logger.error(f"Failed to connect to Redis: {e}")
            raise ConnectionError(f"Redis connection failed: {e}")
    
    async def close(self) -> None:
        """Закрытие соединения с Redis."""
        if self._client:
            try:
                await self._client.close()
                self._initialized = False
                logger.info("Redis connection closed")
            except Exception as e:
                logger.warning(f"Error closing Redis connection: {e}")
            finally:
                self._client = None
    
    async def ping(self) -> bool:
        """
        Проверка доступности Redis.
        
        Returns:
            bool: True если Redis доступен
        """
        if not self._client or not self._initialized:
            return False
        try:
            return await self._client.ping()
        except Exception:
            return False
    
    @property
    def is_initialized(self) -> bool:
        """Проверка статуса инициализации."""
        return self._initialized and self._client is not None
    
    @property
    def client(self) -> Optional[Redis]:
        """Получение сырого клиента Redis."""
        return self._client
    
    async def flushdb(self) -> bool:
        """
        Очистка текущей базы данных Redis.
        
        Returns:
            bool: True если успешно
        """
        if not self._client:
            return False
        try:
            await self._client.flushdb()
            logger.debug("Redis FLUSHDB completed")
            return True
        except Exception as e:
            logger.error(f"Redis FLUSHDB failed: {e}")
            return False
    
    async def get(self, key: str) -> Optional[str]:
        """
        Получение значения по ключу.
        
        Args:
            key: Ключ
        
        Returns:
            Optional[str]: Значение или None
        """
        if not self._client:
            return None
        try:
            return await self._client.get(key)
        except Exception as e:
            logger.error(f"Redis GET failed for {key}: {e}")
            return None
    
    async def get_json(self, key: str) -> Optional[Any]:
        """
        Получение и десериализация JSON значения.
        
        Используется в MFA роутере для:
        - Получения TOTP сессии (test_totp_verify_success)
        - Получения MFA сессии (test_mfa_verify_success)
        
        Args:
            key: Ключ
        
        Returns:
            Optional[Any]: Десериализованное значение или None
        """
        value = await self.get(key)
        if value is None:
            return None
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            logger.warning(f"Failed to decode JSON for key {key}")
            return None
    
    async def set_json(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Сохранение значения в JSON формате.
        
        Сериализует dict/list в JSON строку и сохраняет в Redis.
        
        Используется в тестах отказоустойчивости для размещения
        TOTP-секрета в Redis перед тестированием fail-open сценариев.
        
        Args:
            key: Ключ
            value: Значение (сериализуется в JSON)
            ttl: Время жизни в секундах
        
        Returns:
            bool: True если сохранено успешно
        """
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        return await self.set(key, value, ttl=ttl)
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        nx: bool = False,
        xx: bool = False,
    ) -> bool:
        """
        Установка значения по ключу.
        
        Args:
            key: Ключ
            value: Значение (строки, dict и list сериализуются в JSON)
            ttl: Время жизни в секундах
            nx: Установить только если ключ не существует
            xx: Установить только если ключ существует
        
        Returns:
            bool: True если успешно
        """
        if not self._client:
            return False
        
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False)
            
            if ttl is not None and ttl > 0:
                result = await self._client.set(key, value, ex=ttl, nx=nx, xx=xx)
            else:
                result = await self._client.set(key, value, nx=nx, xx=xx)
            
            return bool(result)
        except Exception as e:
            logger.error(f"Redis SET failed for {key}: {e}")
            return False
    
    async def setex(self, key: str, ttl: int, value: Any) -> bool:
        """
        Установка значения с TTL.
        
        Args:
            key: Ключ
            ttl: Время жизни в секундах
            value: Значение
        
        Returns:
            bool: True если успешно
        """
        return await self.set(key, value, ttl=ttl)
    
    async def delete(self, *keys: str) -> int:
        """
        Удаление одного или нескольких ключей.
        
        Args:
            keys: Ключи для удаления
        
        Returns:
            int: Количество удаленных ключей
        """
        if not self._client or not keys:
            return 0
        try:
            return await self._client.delete(*keys)
        except Exception as e:
            logger.error(f"Redis DELETE failed for {keys}: {e}")
            return 0
    
    async def exists(self, key: str) -> bool:
        """
        Проверка существования ключа.
        
        Args:
            key: Ключ
        
        Returns:
            bool: True если ключ существует
        """
        if not self._client:
            return False
        try:
            return await self._client.exists(key) > 0
        except Exception as e:
            logger.error(f"Redis EXISTS failed for {key}: {e}")
            return False
    
    async def expire(self, key: str, ttl: int) -> bool:
        """
        Установка времени жизни ключа.
        
        Args:
            key: Ключ
            ttl: Время жизни в секундах
        
        Returns:
            bool: True если успешно
        """
        if not self._client:
            return False
        try:
            return await self._client.expire(key, ttl)
        except Exception as e:
            logger.error(f"Redis EXPIRE failed for {key}: {e}")
            return False
    
    async def ttl(self, key: str) -> int:
        """
        Получение оставшегося времени жизни ключа.
        
        Используется в RateLimitService._is_blocked() для проверки
        длительности блокировки.
        
        Returns:
            int: Оставшееся время в секундах (-1 если без TTL, -2 если не существует)
        """
        if not self._client:
            return -2
        try:
            return await self._client.ttl(key)
        except Exception as e:
            logger.error(f"Redis TTL failed for {key}: {e}")
            return -2
    
    async def incr(self, key: str, ttl: Optional[int] = None) -> int:
        """
        Инкремент счётчика.
        
        Используется в RateLimitService.check_rate_limit() для атомарного
        инкремента и проверки лимита запросов.
        
        При первом инкременте (value == 1) устанавливает TTL для
        автоматического сброса счётчика через указанное окно.
        
        Args:
            key: Ключ счётчика
            ttl: Время жизни (устанавливается при первом инкременте)
        
        Returns:
            int: Новое значение счётчика
        """
        if not self._client:
            return 0
        try:
            value = await self._client.incr(key)
            if ttl is not None and value == 1:
                await self._client.expire(key, ttl)
            return value
        except Exception as e:
            logger.error(f"Redis INCR failed for {key}: {e}")
            return 0
    
    async def incr_by(self, key: str, amount: int = 1, ttl: Optional[int] = None) -> int:
        """
        Инкремент счётчика на определённую величину.
        
        Args:
            key: Ключ счётчика
            amount: Величина инкремента
            ttl: Время жизни (устанавливается при первом инкременте)
        
        Returns:
            int: Новое значение счётчика
        """
        if not self._client:
            return 0
        try:
            value = await self._client.incrby(key, amount)
            if ttl is not None and value == amount:
                await self._client.expire(key, ttl)
            return value
        except Exception as e:
            logger.error(f"Redis INCRBY failed for {key}: {e}")
            return 0
    
    async def get_counter(self, key: str) -> int:
        """
        Получение значения счётчика.
        
        Args:
            key: Ключ счётчика
        
        Returns:
            int: Значение счётчика (0 если не существует)
        """
        if not self._client:
            return 0
        try:
            value = await self._client.get(key)
            return int(value) if value is not None else 0
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to get counter {key}: {e}")
            return 0
    
    async def get_idempotency_result(self, key: str) -> Optional[Any]:
        """
        Получение результата идемпотентной операции.
        
        Используется в MFA роутере для проверки повторных запросов:
        - test_sms_send_success: проверка отправки SMS
        - test_email_send_success: проверка отправки Email
        
        Возвращает сохранённый результат операции или None,
        если операция ещё не выполнялась.
        
        Args:
            key: Ключ идемпотентности
        
        Returns:
            Optional[Any]: Результат предыдущей операции или None
        """
        full_key = f"idempotency:{key}"
        return await self.get_json(full_key)
    
    async def set_idempotency_result(
        self, key: str, result: Any, ttl: int = 86400
    ) -> bool:
        """
        Сохранение результата идемпотентной операции.
        
        Args:
            key: Ключ идемпотентности
            result: Результат операции
            ttl: Время жизни в секундах (по умолчанию 24 часа)
        
        Returns:
            bool: True если сохранено успешно
        """
        full_key = f"idempotency:{key}"
        return await self.set(full_key, result, ttl=ttl)
    
    async def sadd(self, key: str, *values: str) -> int:
        """
        Добавление элементов в множество.
        
        Args:
            key: Ключ множества
            values: Элементы для добавления
        
        Returns:
            int: Количество добавленных элементов
        """
        if not self._client:
            return 0
        try:
            return await self._client.sadd(key, *values)
        except Exception as e:
            logger.error(f"Redis SADD failed for {key}: {e}")
            return 0
    
    async def srem(self, key: str, *values: str) -> int:
        """
        Удаление элементов из множества.
        
        Args:
            key: Ключ множества
            values: Элементы для удаления
        
        Returns:
            int: Количество удаленных элементов
        """
        if not self._client:
            return 0
        try:
            return await self._client.srem(key, *values)
        except Exception as e:
            logger.error(f"Redis SREM failed for {key}: {e}")
            return 0
    
    async def smembers(self, key: str) -> set:
        """
        Получение всех элементов множества.
        
        Args:
            key: Ключ множества
        
        Returns:
            set: Множество элементов
        """
        if not self._client:
            return set()
        try:
            return await self._client.smembers(key)
        except Exception as e:
            logger.error(f"Redis SMEMBERS failed for {key}: {e}")
            return set()
    
    async def sismember(self, key: str, value: str) -> bool:
        """
        Проверка наличия элемента в множестве.
        
        Args:
            key: Ключ множества
            value: Элемент для проверки
        
        Returns:
            bool: True если элемент есть в множестве
        """
        if not self._client:
            return False
        try:
            result = await self._client.sismember(key, value)
            return bool(result)
        except Exception as e:
            logger.error(f"Redis SISMEMBER failed for {key}: {e}")
            return False
    
    async def rate_limit_atomic(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> tuple:
        """
        Атомарная проверка rate limit с использованием Lua скрипта.
        
        Args:
            key: Ключ для rate limit
            limit: Максимальное количество запросов
            window_seconds: Временное окно в секундах
        
        Returns:
            tuple: (allowed: bool, count: int) - разрешено и текущее количество
        """
        if not self._client:
            return True, 0
        
        try:
            lua_script = """
                local key = KEYS[1]
                local limit = tonumber(ARGV[1])
                local window = tonumber(ARGV[2])
                local now = tonumber(ARGV[3])
                
                redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
                
                local current = redis.call('ZCARD', key)
                local allowed = current < limit
                
                if allowed then
                    redis.call('ZADD', key, now, now .. ':' .. math.random())
                    redis.call('EXPIRE', key, window)
                    current = current + 1
                end
                
                return {allowed and 1 or 0, current}
            """
            
            now = int(time.time())
            result = await self._client.eval(
                lua_script,
                1,
                f"rate:{key}",
                limit,
                window_seconds,
                now,
            )
            
            allowed = bool(result[0])
            count = int(result[1])
            return allowed, count
            
        except Exception as e:
            logger.error(f"Rate limit check failed for {key}: {e}")
            return True, 0
    
    async def save_otp(self, key: str, code: str, ttl: int = 300) -> bool:
        """
        Сохранение OTP кода.
        
        Args:
            key: Ключ OTP
            code: Код
            ttl: Время жизни в секундах
        
        Returns:
            bool: True если сохранено успешно
        """
        return await self.set(f"otp:{key}", code, ttl=ttl)
    
    async def verify_otp(self, key: str, code: str, delete_on_success: bool = True) -> bool:
        """
        Верификация OTP кода.
        
        Args:
            key: Ключ OTP
            code: Код для проверки
            delete_on_success: Удалить код после успешной верификации
        
        Returns:
            bool: True если код верный
        """
        full_key = f"otp:{key}"
        stored = await self.get(full_key)
        
        if stored is None:
            return False
        
        if stored == code:
            if delete_on_success:
                await self.delete(full_key)
            return True
        
        return False
    
    async def save_refresh_token(self, token_id: str, user_id: str, ttl: int = 86400) -> bool:
        """
        Сохранение Refresh Token.
        
        Args:
            token_id: ID токена
            user_id: ID пользователя
            ttl: Время жизни в секундах
        
        Returns:
            bool: True если сохранено успешно
        """
        return await self.set(f"refresh:{token_id}", user_id, ttl=ttl)
    
    async def get_refresh_token_user(self, token_id: str) -> Optional[str]:
        """
        Получение user_id по Refresh Token.
        
        Args:
            token_id: ID токена
        
        Returns:
            Optional[str]: user_id или None
        """
        return await self.get(f"refresh:{token_id}")
    
    async def revoke_refresh_token(self, token_id: str) -> bool:
        """
        Отзыв Refresh Token.
        
        Args:
            token_id: ID токена
        
        Returns:
            bool: True если удалено успешно
        """
        deleted = await self.delete(f"refresh:{token_id}")
        return deleted > 0
    
    async def blacklist_jwt(self, jti: str, ttl: int = 900) -> bool:
        """
        Добавление JWT в черный список.
        
        Args:
            jti: JWT ID
            ttl: Время жизни в секундах
        
        Returns:
            bool: True если добавлено успешно
        """
        return await self.setex(f"blacklist:{jti}", ttl, "1")
    
    async def is_jwt_blacklisted(self, jti: str) -> bool:
        """
        Проверка JWT в черном списке.
        
        Args:
            jti: JWT ID
        
        Returns:
            bool: True если токен в черном списке
        """
        return await self.exists(f"blacklist:{jti}")
    
    async def save_idempotency_result(self, key: str, result: Any, ttl: int = 86400) -> bool:
        """
        Сохранение idempotency результата.
        
        Args:
            key: Ключ idempotency
            result: Результат операции
            ttl: Время жизни в секундах
        
        Returns:
            bool: True если сохранено успешно
        """
        return await self.set(f"idempotency:{key}", result, ttl=ttl)
    
    async def scan_keys(self, pattern: str, count: int = 100) -> List[str]:
        """
        Сканирование ключей по паттерну.
        
        Args:
            pattern: Паттерн для поиска
            count: Количество ключей за итерацию
        
        Returns:
            List[str]: Список ключей
        """
        if not self._client:
            return []
        try:
            keys = []
            async for key in self._client.scan_iter(match=pattern, count=count):
                keys.append(key)
            return keys
        except Exception as e:
            logger.error(f"Redis SCAN failed for {pattern}: {e}")
            return []
    
    async def delete_by_pattern(self, pattern: str) -> int:
        """
        Удаление ключей по паттерну.
        
        Args:
            pattern: Паттерн для удаления
        
        Returns:
            int: Количество удаленных ключей
        """
        keys = await self.scan_keys(pattern)
        if not keys:
            return 0
        try:
            return await self.delete(*keys)
        except Exception as e:
            logger.error(f"Failed to delete by pattern {pattern}: {e}")
            return 0
    
    def pipeline(self):
        """
        Получение pipeline для пакетного выполнения команд.
        
        Returns:
            Pipeline: Pipeline объект Redis
        """
        if not self._client:
            raise RuntimeError("Redis client not initialized")
        return self._client.pipeline()
    
    async def info(self, section: Optional[str] = None) -> Dict[str, Any]:
        """
        Получение информации о Redis.
        
        Args:
            section: Секция info (например, "memory", "stats")
        
        Returns:
            Dict[str, Any]: Информация о Redis
        """
        if not self._client:
            return {}
        try:
            return await self._client.info(section)
        except Exception as e:
            logger.error(f"Failed to get Redis info: {e}")
            return {}


# Глобальный экземпляр клиента Redis
redis_client = RedisClient()


async def init_redis(url: Optional[str] = None) -> None:
    """Инициализация Redis клиента при старте приложения."""
    await redis_client.initialize(url)


async def close_redis() -> None:
    """Закрытие Redis клиента при завершении приложения."""
    await redis_client.close()


def get_redis_client() -> RedisClient:
    """Получение глобального клиента Redis."""
    return redis_client