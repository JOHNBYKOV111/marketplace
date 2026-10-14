"""
Сервис для работы с Redis.

Обеспечивает:
- Получение значений из Redis
- Установку значений с TTL
- Инкремент счётчиков
- Получение TTL ключей
- Удаление ключей
- Проверку существования ключей
- Работу с множествами (SADD, SREM, SMEMBERS, SISMEMBER)
"""

from typing import Any, Optional, List, Set
from datetime import datetime, timedelta

from app.core.logging import get_logger
from app.core.redis_client import redis_client


logger = get_logger(__name__)


class RedisService:
    """
    Сервис для работы с Redis.

    Предоставляет высокоуровневые методы для работы с Redis,
    включая кэширование, счётчики, множества и TTL.
    """

    @staticmethod
    async def get(key: str) -> Optional[str]:
        """
        Получение значения по ключу.

        Args:
            key: Ключ

        Returns:
            Optional[str]: Значение или None
        """
        try:
            return await redis_client.get(key)
        except Exception as e:
            logger.error(f"Failed to get key {key}: {e}")
            return None

    @staticmethod
    async def get_json(key: str) -> Optional[Any]:
        """
        Получение и десериализация JSON значения.

        Args:
            key: Ключ

        Returns:
            Optional[Any]: Десериализованное значение или None
        """
        try:
            return await redis_client.get_json(key)
        except Exception as e:
            logger.error(f"Failed to get JSON for key {key}: {e}")
            return None

    @staticmethod
    async def set(
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
            value: Значение
            ttl: Время жизни в секундах
            nx: Установить только если ключ не существует
            xx: Установить только если ключ существует

        Returns:
            bool: True если успешно
        """
        try:
            return await redis_client.set(key, value, ttl=ttl, nx=nx, xx=xx)
        except Exception as e:
            logger.error(f"Failed to set key {key}: {e}")
            return False

    @staticmethod
    async def setex(key: str, ttl: int, value: Any) -> bool:
        """
        Установка значения с TTL.

        Args:
            key: Ключ
            ttl: Время жизни в секундах
            value: Значение

        Returns:
            bool: True если успешно
        """
        try:
            return await redis_client.setex(key, ttl, value)
        except Exception as e:
            logger.error(f"Failed to setex key {key}: {e}")
            return False

    @staticmethod
    async def delete(*keys: str) -> int:
        """
        Удаление одного или нескольких ключей.

        Args:
            keys: Ключи для удаления

        Returns:
            int: Количество удаленных ключей
        """
        if not keys:
            return 0
        try:
            return await redis_client.delete(*keys)
        except Exception as e:
            logger.error(f"Failed to delete keys {keys}: {e}")
            return 0

    @staticmethod
    async def exists(key: str) -> bool:
        """
        Проверка существования ключа.

        Args:
            key: Ключ

        Returns:
            bool: True если ключ существует
        """
        try:
            return await redis_client.exists(key)
        except Exception as e:
            logger.error(f"Failed to check existence of key {key}: {e}")
            return False

    @staticmethod
    async def expire(key: str, ttl: int) -> bool:
        """
        Установка времени жизни ключа.

        Args:
            key: Ключ
            ttl: Время жизни в секундах

        Returns:
            bool: True если успешно
        """
        try:
            return await redis_client.expire(key, ttl)
        except Exception as e:
            logger.error(f"Failed to expire key {key}: {e}")
            return False

    @staticmethod
    async def ttl(key: str) -> int:
        """
        Получение оставшегося времени жизни ключа.

        Args:
            key: Ключ

        Returns:
            int: Оставшееся время в секундах (-1 если без TTL, -2 если не существует)
        """
        try:
            return await redis_client.ttl(key)
        except Exception as e:
            logger.error(f"Failed to get TTL for key {key}: {e}")
            return -2

    @staticmethod
    async def incr(key: str, ttl: Optional[int] = None) -> int:
        """
        Инкремент счётчика.

        Args:
            key: Ключ счётчика
            ttl: Время жизни (устанавливается при первом инкременте)

        Returns:
            int: Новое значение счётчика
        """
        try:
            return await redis_client.incr(key, ttl=ttl)
        except Exception as e:
            logger.error(f"Failed to increment key {key}: {e}")
            return 0

    @staticmethod
    async def get_rate_limit(key: str) -> int:
        """
        Получение значения rate limit счётчика.

        Args:
            key: Ключ счётчика

        Returns:
            int: Значение счётчика (0 если не существует)
        """
        try:
            return await redis_client.get_counter(key)
        except Exception as e:
            logger.error(f"Failed to get rate limit for key {key}: {e}")
            return 0

    @staticmethod
    async def sadd(key: str, *values: str) -> int:
        """
        Добавление элементов в множество.

        Args:
            key: Ключ множества
            values: Элементы для добавления

        Returns:
            int: Количество добавленных элементов
        """
        try:
            return await redis_client.sadd(key, *values)
        except Exception as e:
            logger.error(f"Failed to add to set {key}: {e}")
            return 0

    @staticmethod
    async def srem(key: str, *values: str) -> int:
        """
        Удаление элементов из множества.

        Args:
            key: Ключ множества
            values: Элементы для удаления

        Returns:
            int: Количество удаленных элементов
        """
        try:
            return await redis_client.srem(key, *values)
        except Exception as e:
            logger.error(f"Failed to remove from set {key}: {e}")
            return 0

    @staticmethod
    async def smembers(key: str) -> Set[str]:
        """
        Получение всех элементов множества.

        Args:
            key: Ключ множества

        Returns:
            Set[str]: Множество элементов
        """
        try:
            return await redis_client.smembers(key)
        except Exception as e:
            logger.error(f"Failed to get set members for key {key}: {e}")
            return set()

    @staticmethod
    async def sismember(key: str, value: str) -> bool:
        """
        Проверка наличия элемента в множестве.

        Args:
            key: Ключ множества
            value: Элемент для проверки

        Returns:
            bool: True если элемент есть в множестве
        """
        try:
            return await redis_client.sismember(key, value)
        except Exception as e:
            logger.error(f"Failed to check set member for key {key}: {e}")
            return False

    @staticmethod
    async def flushdb() -> bool:
        """
        Очистка текущей базы данных Redis.

        Returns:
            bool: True если успешно
        """
        try:
            return await redis_client.flushdb()
        except Exception as e:
            logger.error(f"Failed to flush Redis DB: {e}")
            return False

    @staticmethod
    async def scan_keys(pattern: str, count: int = 100) -> List[str]:
        """
        Сканирование ключей по паттерну.

        Args:
            pattern: Паттерн для поиска
            count: Количество ключей за итерацию

        Returns:
            List[str]: Список ключей
        """
        try:
            return await redis_client.scan_keys(pattern, count=count)
        except Exception as e:
            logger.error(f"Failed to scan keys with pattern {pattern}: {e}")
            return []

    @staticmethod
    async def delete_by_pattern(pattern: str) -> int:
        """
        Удаление ключей по паттерну.

        Args:
            pattern: Паттерн для удаления

        Returns:
            int: Количество удаленных ключей
        """
        try:
            return await redis_client.delete_by_pattern(pattern)
        except Exception as e:
            logger.error(f"Failed to delete keys by pattern {pattern}: {e}")
            return 0