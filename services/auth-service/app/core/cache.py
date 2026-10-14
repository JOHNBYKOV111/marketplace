"""
Кэш-клиент для приложения.

Обеспечивает:
- Асинхронное кэширование данных
- Поддержку Redis
- Декораторы для кэширования
- Инвалидацию кэша
- Graceful degradation при недоступности Redis
"""

import json
import hashlib
from typing import Optional, Any, Callable, TypeVar, Awaitable
from functools import wraps
from datetime import timedelta

from app.core.redis_client import redis_client
from app.core.logging import get_logger


logger = get_logger(__name__)

# Тип для декоратора
F = TypeVar('F', bound=Callable[..., Awaitable[Any]])


class CacheClient:
    """
    Клиент для работы с кэшем.
    
    Предоставляет методы для кэширования данных,
    инвалидации и декораторы для автоматического кэширования.
    """
    
    def __init__(self):
        """Инициализация клиента кэша."""
        self._redis = redis_client
        self._prefix = "cache:"
        self._default_ttl = 300  # 5 минут
    
    async def get(self, key: str) -> Optional[Any]:
        """
        Получение значения из кэша.
        
        Args:
            key: Ключ кэша
            
        Returns:
            Optional[Any]: Значение из кэша или None
        """
        try:
            full_key = f"{self._prefix}{key}"
            value = await self._redis.get(full_key)
            
            if value is None:
                return None
            
            # Пытаемся десериализовать JSON
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return value
                
        except Exception as e:
            logger.warning(f"Failed to get cache key {key}: {e}")
            return None
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        ttl_delta: Optional[timedelta] = None,
    ) -> bool:
        """
        Установка значения в кэш.
        
        Args:
            key: Ключ кэша
            value: Значение
            ttl: Время жизни в секундах
            ttl_delta: Время жизни как timedelta
            
        Returns:
            bool: True если успешно
        """
        try:
            full_key = f"{self._prefix}{key}"
            
            # Если передан timedelta, преобразуем в секунды
            if ttl_delta is not None:
                ttl = int(ttl_delta.total_seconds())
            
            # Используем дефолтный TTL если не указан
            if ttl is None:
                ttl = self._default_ttl
            
            # Сериализуем значение
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False)
            
            await self._redis.set(full_key, value, ttl)
            return True
            
        except Exception as e:
            logger.warning(f"Failed to set cache key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """
        Удаление значения из кэша.
        
        Args:
            key: Ключ кэша
            
        Returns:
            bool: True если удалено
        """
        try:
            full_key = f"{self._prefix}{key}"
            await self._redis.delete(full_key)
            return True
            
        except Exception as e:
            logger.warning(f"Failed to delete cache key {key}: {e}")
            return False
    
    async def delete_pattern(self, pattern: str) -> int:
        """
        Удаление всех ключей по паттерну.
        
        Args:
            pattern: Паттерн для поиска
            
        Returns:
            int: Количество удаленных ключей
        """
        try:
            full_pattern = f"{self._prefix}{pattern}"
            count = await self._redis.delete_pattern(full_pattern)
            return count
            
        except Exception as e:
            logger.warning(f"Failed to delete cache pattern {pattern}: {e}")
            return 0
    
    async def incr(self, key: str, amount: int = 1) -> int:
        """
        Инкремент значения в кэше.
        
        Args:
            key: Ключ кэша
            amount: Значение инкремента
            
        Returns:
            int: Новое значение
        """
        try:
            full_key = f"{self._prefix}{key}"
            result = await self._redis._client.incrby(full_key, amount)
            
            # Устанавливаем TTL если ключ был создан
            await self._redis._client.expire(full_key, self._default_ttl)
            
            return result
            
        except Exception as e:
            logger.warning(f"Failed to increment cache key {key}: {e}")
            return 0
    
    async def expire(self, key: str, ttl: int) -> bool:
        """
        Установка времени жизни ключа.
        
        Args:
            key: Ключ кэша
            ttl: Время жизни в секундах
            
        Returns:
            bool: True если успешно
        """
        try:
            full_key = f"{self._prefix}{key}"
            await self._redis.expire(full_key, ttl)
            return True
            
        except Exception as e:
            logger.warning(f"Failed to set expire for cache key {key}: {e}")
            return False
    
    def generate_key(self, *args, **kwargs) -> str:
        """
        Генерация ключа кэша на основе аргументов.
        
        Args:
            *args: Позиционные аргументы
            **kwargs: Именованные аргументы
            
        Returns:
            str: Сгенерированный ключ
        """
        # Собираем все аргументы в строку
        parts = []
        
        for arg in args:
            if isinstance(arg, (dict, list)):
                parts.append(json.dumps(arg, sort_keys=True))
            else:
                parts.append(str(arg))
        
        for key, value in sorted(kwargs.items()):
            if isinstance(value, (dict, list)):
                parts.append(f"{key}={json.dumps(value, sort_keys=True)}")
            else:
                parts.append(f"{key}={value}")
        
        # Создаем хеш
        key_string = ":".join(parts)
        return hashlib.md5(key_string.encode()).hexdigest()


# ==================== ДЕКОРАТОРЫ ====================

def cached(
    ttl: Optional[int] = None,
    ttl_delta: Optional[timedelta] = None,
    key_prefix: Optional[str] = None,
) -> Callable[[F], F]:
    """
    Декоратор для автоматического кэширования результата функции.
    
    Args:
        ttl: Время жизни в секундах
        ttl_delta: Время жизни как timedelta
        key_prefix: Префикс ключа кэша
        
    Returns:
        Callable: Обернутая функция
    """
    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Генерируем ключ кэша
            cache_key = cache.generate_key(func.__name__, *args, **kwargs)
            if key_prefix:
                cache_key = f"{key_prefix}:{cache_key}"
            
            # Пытаемся получить из кэша
            cached_value = await cache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Выполняем функцию
            result = await func(*args, **kwargs)
            
            # Сохраняем в кэш
            await cache.set(cache_key, result, ttl=ttl, ttl_delta=ttl_delta)
            
            return result
        
        return wrapper
    
    return decorator


# ==================== ГЛОБАЛЬНЫЙ КЛИЕНТ ====================

cache = CacheClient()


# ==================== ИНИЦИАЛИЗАЦИЯ ====================

async def init_cache() -> None:
    """Инициализация кэша при старте приложения."""
    # Проверяем подключение к Redis
    try:
        await cache._redis.ping()
        logger.info("Cache client initialized with Redis")
    except Exception as e:
        logger.warning(f"Cache client initialized without Redis: {e}")


async def close_cache() -> None:
    """Закрытие кэша при завершении приложения."""
    logger.info("Cache client closed")


# ==================== HELPER ФУНКЦИИ ====================

async def clear_cache(pattern: Optional[str] = None) -> int:
    """
    Очистка кэша.
    
    Args:
        pattern: Паттерн для удаления (опционально)
        
    Returns:
        int: Количество удаленных ключей
    """
    if pattern:
        return await cache.delete_pattern(pattern)
    else:
        # Удаляем все ключи с префиксом cache:
        return await cache.delete_pattern("*")


# ==================== ЭКСПОРТ ====================

__all__ = [
    "CacheClient",
    "cache",
    "cached",
    "init_cache",
    "close_cache",
    "clear_cache",
]