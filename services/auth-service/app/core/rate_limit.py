"""
Сервис для Rate Limiting.

Реализует:
- Ограничение количества запросов по IP и User ID
- Алгоритм Token Bucket для гибкого ограничения
- Поддержку Redis для распределенного rate limiting
- Настраиваемые лимиты для разных эндпоинтов
- Защиту от DDoS и брутфорс-атак
- Мониторинг и метрики
"""

import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Set, Tuple, Any, Callable
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import Request, HTTPException, status

from app.core.config import settings
from app.core.logging import get_logger
from app.core.metrics import rate_limit_metrics

logger = get_logger(__name__)


class RateLimitStrategy(str, Enum):
    """Стратегии ограничения запросов."""

    FIXED_WINDOW = "fixed_window"      # Фиксированное окно
    SLIDING_WINDOW = "sliding_window"  # Скользящее окно
    TOKEN_BUCKET = "token_bucket"      # Token Bucket
    LEAKY_BUCKET = "leaky_bucket"      # Leaky Bucket


@dataclass
class RateLimitConfig:
    """Конфигурация rate limit."""

    limit: int
    window: int
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW
    key_prefix: str = "rate_limit"


class RateLimiter:
    """
    Реализация rate limiting.

    Поддерживает:
    - Распределенный rate limit через Redis
    - Локальный rate limit для разработки
    - Разные стратегии ограничения
    - Белый список IP
    """

    def __init__(
        self,
        limit: int,
        window: int,
        strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW,
        key_prefix: str = "rate_limit",
        redis_client: Optional[aioredis.Redis] = None,
    ):
        """
        Инициализация rate limiter.

        Args:
            limit: Максимальное количество запросов
            window: Временное окно в секундах
            strategy: Стратегия ограничения
            key_prefix: Префикс для ключей в Redis
            redis_client: Клиент Redis (для распределенного лимита)
        """
        self.limit = limit
        self.window = window
        self.strategy = strategy
        self.key_prefix = key_prefix
        self.redis = redis_client

        # Локальный кэш для ин-мемори лимита (разработка)
        self._local_cache: Dict[str, list] = {}

        # Белый список IP
        self._whitelist: Set[str] = set()

    def add_to_whitelist(self, ip: str) -> None:
        """
        Добавление IP в белый список.

        Args:
            ip: IP адрес
        """
        self._whitelist.add(ip)
        logger.info(f"IP {ip} added to rate limit whitelist")

    def remove_from_whitelist(self, ip: str) -> None:
        """
        Удаление IP из белого списка.

        Args:
            ip: IP адрес
        """
        self._whitelist.discard(ip)
        logger.info(f"IP {ip} removed from rate limit whitelist")

    async def allow(
        self,
        key: str,
        limit: Optional[int] = None,
        window: Optional[int] = None,
        skip: bool = False,
    ) -> Tuple[bool, int, int]:
        """
        Проверка разрешения запроса.

        Args:
            key: Ключ для идентификации (IP, user_id, endpoint)
            limit: Переопределение лимита
            window: Переопределение окна
            skip: Пропустить проверку лимита (для тестов)

        Returns:
            Tuple[bool, int, int]: (разрешено, оставшиеся попытки, время до сброса)
        """
        # Пропуск проверки для тестов (bypass header)
        if skip:
            return True, self.limit, 0

        # Проверка белого списка
        if key in self._whitelist:
            return True, self.limit, 0

        limit = limit or self.limit
        window = window or self.window

        if self.redis:
            return await self._allow_redis(key, limit, window)

        return await self._allow_local(key, limit, window)

    async def _allow_redis(
        self,
        key: str,
        limit: int,
        window: int,
    ) -> Tuple[bool, int, int]:
        """
        Проверка через Redis (распределенный rate limit).

        Args:
            key: Ключ
            limit: Лимит
            window: Окно

        Returns:
            Tuple[bool, int, int]: (разрешено, оставшиеся, время до сброса)
        """
        try:
            now = time.time()

            if self.strategy == RateLimitStrategy.FIXED_WINDOW:
                return await self._fixed_window_redis(key, limit, window, now)

            elif self.strategy == RateLimitStrategy.TOKEN_BUCKET:
                return await self._token_bucket_redis(key, limit, window, now)

            else:
                # По умолчанию sliding window
                return await self._sliding_window_redis(key, limit, window, now)

        except Exception as e:
            logger.error(f"Redis rate limit error: {e}, allowing request")
            return True, limit - 1, 0

    async def _sliding_window_redis(
        self,
        key: str,
        limit: int,
        window: int,
        now: float,
    ) -> Tuple[bool, int, int]:
        """
        Скользящее окно через Redis (Sorted Set).

        Args:
            key: Ключ
            limit: Лимит
            window: Окно
            now: Текущее время

        Returns:
            Tuple[bool, int, int]: (разрешено, оставшиеся, время до сброса)
        """
        redis_key = f"{self.key_prefix}:{key}"
        window_start = now - window

        # Луа скрипт для атомарной операции
        lua_script = """
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local window_start = tonumber(ARGV[2])
            local limit = tonumber(ARGV[3])

            -- Удаление старых записей
            redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

            -- Подсчет текущих запросов
            local current = redis.call('ZCARD', key)

            if current < limit then
                -- Добавление нового запроса
                redis.call('ZADD', key, now, now .. ':' .. redis.call('INCR', key .. ':counter'))
                redis.call('EXPIRE', key, 60)
                return {1, limit - current - 1, 0}
            else
                -- Получение времени истечения
                local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
                local reset_time = 0
                if #oldest > 0 then
                    reset_time = tonumber(oldest[2]) + tonumber(ARGV[4])
                end
                return {0, 0, reset_time}
            end
        """

        # Выполнение скрипта
        result = await self.redis.eval(
            lua_script,
            1,
            redis_key,
            str(now),
            str(window_start),
            str(limit),
            str(window),
        )

        allowed = bool(result[0])
        remaining = int(result[1]) if result[1] else 0
        reset_at = int(result[2]) if result[2] else 0

        if allowed:
            rate_limit_metrics.increment_allowed()

        return allowed, remaining, max(0, int(reset_at - now))

    async def _fixed_window_redis(
        self,
        key: str,
        limit: int,
        window: int,
        now: float,
    ) -> Tuple[bool, int, int]:
        """
        Фиксированное окно через Redis.

        Args:
            key: Ключ
            limit: Лимит
            window: Окно
            now: Текущее время

        Returns:
            Tuple[bool, int, int]: (разрешено, оставшиеся, время до сброса)
        """
        current_window = int(now / window)
        redis_key = f"{self.key_prefix}:{key}:{current_window}"

        # Атомарное увеличение счетчика
        count = await self.redis.incr(redis_key)

        if count == 1:
            await self.redis.expire(redis_key, window)

        remaining = max(0, limit - count)
        reset_at = (current_window + 1) * window

        if count <= limit:
            rate_limit_metrics.increment_allowed()
            return True, remaining, max(0, int(reset_at - now))

        rate_limit_metrics.increment_blocked()
        return False, 0, max(0, int(reset_at - now))

    async def _token_bucket_redis(
        self,
        key: str,
        limit: int,
        window: int,
        now: float,
    ) -> Tuple[bool, int, int]:
        """
        Token Bucket через Redis.

        Args:
            key: Ключ
            limit: Лимит
            window: Окно
            now: Текущее время

        Returns:
            Tuple[bool, int, int]: (разрешено, оставшиеся, время до сброса)
        """
        rate = limit / window  # токенов в секунду

        redis_key = f"{self.key_prefix}:{key}:bucket"

        lua_script = """
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local rate = tonumber(ARGV[2])
            local capacity = tonumber(ARGV[3])

            local data = redis.call('HMGET', key, 'tokens', 'last_update')
            local tokens = tonumber(data[1]) or capacity
            local last_update = tonumber(data[2]) or now

            local delta = now - last_update
            local new_tokens = math.min(capacity, tokens + delta * rate)

            if new_tokens >= 1 then
                new_tokens = new_tokens - 1
                redis.call('HMSET', key, 'tokens', new_tokens, 'last_update', now)
                redis.call('EXPIRE', key, 60)
                local remaining = math.floor(new_tokens)
                return {1, remaining, 0}
            else
                local wait_time = (1 - new_tokens) / rate
                return {0, 0, wait_time}
            end
        """

        result = await self.redis.eval(
            lua_script,
            1,
            redis_key,
            str(now),
            str(rate),
            str(limit),
        )

        allowed = bool(result[0])
        remaining = int(result[1]) if result[1] else 0
        wait_time = float(result[2]) if result[2] else 0

        if allowed:
            rate_limit_metrics.increment_allowed()

        return allowed, remaining, int(wait_time)

    async def _allow_local(
        self,
        key: str,
        limit: int,
        window: int,
    ) -> Tuple[bool, int, int]:
        """
        Локальный rate limit (для разработки).

        Args:
            key: Ключ
            limit: Лимит
            window: Окно

        Returns:
            Tuple[bool, int, int]: (разрешено, оставшиеся, время до сброса)
        """
        now = time.time()

        if key not in self._local_cache:
            self._local_cache[key] = []

        # Очистка старых записей
        self._local_cache[key] = [
            t for t in self._local_cache[key] if t > now - window
        ]

        if len(self._local_cache[key]) >= limit:
            # Расчет времени до сброса
            oldest = self._local_cache[key][0]
            reset_at = oldest + window
            rate_limit_metrics.increment_blocked()
            return False, 0, max(0, int(reset_at - now))

        self._local_cache[key].append(now)
        remaining = limit - len(self._local_cache[key])
        rate_limit_metrics.increment_allowed()
        return True, remaining, 0


class RateLimitManager:
    """
    Менеджер для управления несколькими rate limiters.

    Позволяет:
    - Управлять разными лимитами для разных эндпоинтов
    - Группировать лимиты по типу
    - Получать метрики
    """

    def __init__(self, redis_client: Optional[aioredis.Redis] = None):
        """
        Инициализация менеджера.

        Args:
            redis_client: Клиент Redis
        """
        self.redis = redis_client
        self._limiters: Dict[str, RateLimiter] = {}
        self._default_config = RateLimitConfig(
            limit=100,
            window=60,
        )

    def get_limiter(
        self,
        name: str,
        config: Optional[RateLimitConfig] = None,
    ) -> RateLimiter:
        """
        Получение или создание rate limiter.

        Args:
            name: Имя лимитера
            config: Конфигурация лимитера

        Returns:
            RateLimiter: Rate limiter
        """
        if name not in self._limiters:
            config = config or self._default_config
            self._limiters[name] = RateLimiter(
                limit=config.limit,
                window=config.window,
                strategy=config.strategy,
                key_prefix=config.key_prefix,
                redis_client=self.redis,
            )

        return self._limiters[name]

    async def check_limit(
        self,
        name: str,
        key: str,
        config: Optional[RateLimitConfig] = None,
    ) -> Tuple[bool, int, int]:
        """
        Проверка лимита для конкретного эндпоинта.

        Args:
            name: Имя лимитера
            key: Ключ для идентификации
            config: Конфигурация лимитера

        Returns:
            Tuple[bool, int, int]: (разрешено, оставшиеся, время до сброса)
        """
        limiter = self.get_limiter(name, config)
        return await limiter.allow(key)

    async def reset_limit(self, name: str, key: str) -> bool:
        """
        Сброс лимита для ключа.

        Args:
            name: Имя лимитера
            key: Ключ

        Returns:
            bool: True если успешно
        """
        if name in self._limiters:
            limiter = self._limiters[name]
            if limiter.redis:
                redis_key = f"{limiter.key_prefix}:{key}"
                await limiter.redis.delete(redis_key)
                return True
            elif key in limiter._local_cache:
                del limiter._local_cache[key]
                return True
        return False


# ==================== MIDDLEWARE ====================

class RateLimitMiddleware:
    """
    Middleware для rate limiting.

    Применяет rate limit ко всем запросам.
    """

    def __init__(
        self,
        app: Any,
        redis_client: Optional[aioredis.Redis] = None,
        default_limit: int = 100,
        default_window: int = 60,
    ):
        """
        Инициализация middleware.

        Args:
            app: FastAPI приложение
            redis_client: Клиент Redis
            default_limit: Лимит по умолчанию
            default_window: Окно по умолчанию
        """
        self.app = app
        self.manager = RateLimitManager(redis_client)
        self.default_limit = default_limit
        self.default_window = default_window

    async def __call__(self, scope: Dict, receive: Any, send: Any) -> None:
        """
        Обработка запроса.

        Args:
            scope: ASGI scope
            receive: Receive callback
            send: Send callback
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        # Получение ключа (IP + User ID если есть)
        client_ip = request.client.host if request.client else "unknown"
        user_id = request.headers.get("X-User-ID", "")

        key = f"{client_ip}:{user_id}" if user_id else client_ip

        # Проверка лимита
        allowed, remaining, reset_at = await self.manager.check_limit(
            "default",
            key,
            RateLimitConfig(
                limit=self.default_limit,
                window=self.default_window,
            ),
        )

        if not allowed:
            response = HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests",
                headers={"Retry-After": str(reset_at)},
            )
            await self._send_response(response, scope, receive, send)
            return

        # Добавляем заголовки с информацией о лимите
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers[b"X-RateLimit-Limit"] = str(self.default_limit).encode()
                headers[b"X-RateLimit-Remaining"] = str(remaining).encode()
                if reset_at:
                    headers[b"X-RateLimit-Reset"] = str(reset_at).encode()
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_wrapper)

    async def _send_response(
        self,
        response: HTTPException,
        scope: Dict,
        receive: Any,
        send: Any,
    ) -> None:
        """
        Отправка ответа с ошибкой.

        Args:
            response: HTTP исключение
            scope: ASGI scope
            receive: Receive callback
            send: Send callback
        """
        from fastapi.responses import JSONResponse

        headers = {}
        if response.headers:
            headers = response.headers

        resp = JSONResponse(
            content={"detail": response.detail},
            status_code=response.status_code,
            headers=headers,
        )
        await resp(scope, receive, send)


# ==================== ДЕКОРАТОР ДЛЯ RATE LIMIT ====================

def rate_limit(
    limit: int,
    window: int,
    key_func: Optional[Callable] = None,
) -> Callable:
    """
    Декоратор для rate limiting.

    Args:
        limit: Максимальное количество запросов
        window: Временное окно в секундах
        key_func: Функция для генерации ключа (по умолчанию IP)

    Returns:
        Callable: Декорированная функция
    """
    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            # Получение ключа
            if key_func:
                key = await key_func(*args, **kwargs) if asyncio.iscoroutinefunction(key_func) else key_func(*args, **kwargs)
            else:
                # По умолчанию IP из request
                request = None
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

                if not request:
                    raise ValueError("Request not found for rate limiting")

                client_ip = request.client.host if request.client else "unknown"
                user_id = request.headers.get("X-User-ID", "")
                key = f"{client_ip}:{user_id}" if user_id else client_ip

            # Проверка лимита
            limiter = RateLimiter(limit, window)
            allowed, remaining, reset_at = await limiter.allow(key)

            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests",
                    headers={"Retry-After": str(reset_at)},
                )

            return await func(*args, **kwargs)

        return wrapper
    return decorator


# ==================== ПРЕДНАСТРОЕННЫЕ ЛИМИТЕРЫ ====================

# Глобальный экземпляр менеджера
rate_limit_manager = RateLimitManager()

# Преднастроенные лимиты
AUTH_LIMIT = RateLimitConfig(limit=10, window=60)  # 10 попыток входа в минуту
API_LIMIT = RateLimitConfig(limit=1000, window=60)  # 1000 запросов в минуту для API
ADMIN_LIMIT = RateLimitConfig(limit=100, window=60)  # 100 запросов в минуту для админки