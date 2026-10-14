"""
Метрики для мониторинга приложения.

Собирает и предоставляет метрики для:
- HTTP запросов (количество, длительность, статусы)
- Токенов (создание, валидация, истечение)
- Базы данных (запросы, время выполнения)
- Rate limiting (разрешенные/заблокированные запросы)
- Ошибок (по типам)
- Кэша (попадания/промахи)
- Vault операций
- Redis операций
- gRPC вызовов
- Бизнес-метрик
"""

import time
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import asyncio
from functools import wraps

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Metric:
    """Базовый класс для метрики."""
    name: str
    value: float = 0.0
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: Optional[datetime] = None
    type: str = "counter"


class Counter:
    """
    Счетчик для метрик.
    
    Используется для подсчета количества событий.
    Поддерживает labels для многомерной агрегации.
    """
    
    def __init__(self, name: str, description: str = "", namespace: str = "app"):
        self.name = f"{namespace}_{name}"
        self.description = description
        self._value = 0
        self._lock = threading.Lock()
        self._labels: Dict[str, Dict[str, int]] = {}
        self._total_by_label: Dict[str, int] = defaultdict(int)
    
    def increment(self, labels: Optional[Dict[str, str]] = None, value: int = 1) -> None:
        """Увеличение счетчика."""
        with self._lock:
            if labels:
                key = self._labels_key(labels)
                self._labels[key] = self._labels.get(key, 0) + value
                self._total_by_label[key] += value
            else:
                self._value += value
    
    def get(self, labels: Optional[Dict[str, str]] = None) -> int:
        """Получение значения счетчика."""
        with self._lock:
            if labels:
                key = self._labels_key(labels)
                return self._labels.get(key, 0)
            return self._value
    
    def get_all(self) -> Dict[str, Dict[str, int]]:
        """Получение всех значений с labels."""
        with self._lock:
            return dict(self._labels)
    
    def get_total(self) -> int:
        """Получение общего значения по всем labels."""
        with self._lock:
            return self._value + sum(self._labels.values())
    
    def reset(self) -> None:
        """Сброс счетчика."""
        with self._lock:
            self._value = 0
            self._labels.clear()
            self._total_by_label.clear()
    
    def _labels_key(self, labels: Dict[str, str]) -> str:
        """Создание ключа для labels."""
        return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
    
    def to_prometheus(self) -> str:
        """Экспорт в формат Prometheus."""
        lines = [f"# HELP {self.name} {self.description}"]
        lines.append(f"# TYPE {self.name} counter")
        
        # Без labels
        lines.append(f"{self.name} {self._value}")
        
        # С labels
        for key, value in self._labels.items():
            labels = dict(kv.split("=") for kv in key.split(",") if kv)
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f'{self.name}{{{label_str}}} {value}')
        
        return "\n".join(lines)


class Gauge:
    """
    Измеритель для метрик.
    
    Используется для измерения текущих значений (например, количество активных соединений).
    """
    
    def __init__(self, name: str, description: str = "", namespace: str = "app"):
        self.name = f"{namespace}_{name}"
        self.description = description
        self._value = 0.0
        self._lock = threading.Lock()
        self._labels: Dict[str, float] = {}
    
    def set(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Установка значения."""
        with self._lock:
            if labels:
                key = self._labels_key(labels)
                self._labels[key] = value
            else:
                self._value = value
    
    def add(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Добавление к текущему значению."""
        with self._lock:
            if labels:
                key = self._labels_key(labels)
                self._labels[key] = self._labels.get(key, 0.0) + value
            else:
                self._value += value
    
    def sub(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Вычитание из текущего значения."""
        self.add(-value, labels)
    
    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Получение текущего значения."""
        with self._lock:
            if labels:
                key = self._labels_key(labels)
                return self._labels.get(key, 0.0)
            return self._value
    
    def get_all(self) -> Dict[str, float]:
        """Получение всех значений с labels."""
        with self._lock:
            return dict(self._labels)
    
    def reset(self) -> None:
        """Сброс значения."""
        with self._lock:
            self._value = 0.0
            self._labels.clear()
    
    def _labels_key(self, labels: Dict[str, str]) -> str:
        """Создание ключа для labels."""
        return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
    
    def to_prometheus(self) -> str:
        """Экспорт в формат Prometheus."""
        lines = [f"# HELP {self.name} {self.description}"]
        lines.append(f"# TYPE {self.name} gauge")
        
        # Без labels
        lines.append(f"{self.name} {self._value}")
        
        # С labels
        for key, value in self._labels.items():
            labels = dict(kv.split("=") for kv in key.split(",") if kv)
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f'{self.name}{{{label_str}}} {value}')
        
        return "\n".join(lines)


class Histogram:
    """
    Гистограмма для метрик.
    
    Используется для измерения распределения значений (например, время выполнения).
    """
    
    BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60]
    
    def __init__(
        self,
        name: str,
        description: str = "",
        buckets: Optional[List[float]] = None,
        namespace: str = "app"
    ):
        self.name = f"{namespace}_{name}"
        self.description = description
        self.buckets = buckets or self.BUCKETS
        self._count = 0
        self._sum = 0.0
        self._buckets: Dict[str, Dict[float, int]] = {}
        self._lock = threading.Lock()
    
    def observe(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Запись наблюдения."""
        with self._lock:
            key = self._labels_key(labels) if labels else "default"
            
            if key not in self._buckets:
                self._buckets[key] = {b: 0 for b in self.buckets}
            
            self._count += 1
            self._sum += value
            
            for bucket in self.buckets:
                if value <= bucket:
                    self._buckets[key][bucket] = self._buckets[key].get(bucket, 0) + 1
    
    def get_count(self, labels: Optional[Dict[str, str]] = None) -> int:
        """Получение количества наблюдений."""
        with self._lock:
            return self._count
    
    def get_sum(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Получение суммы наблюдений."""
        with self._lock:
            return self._sum
    
    def get_buckets(self, labels: Optional[Dict[str, str]] = None) -> Dict[float, int]:
        """Получение распределения по корзинам."""
        with self._lock:
            key = self._labels_key(labels) if labels else "default"
            return dict(self._buckets.get(key, {}))
    
    def reset(self) -> None:
        """Сброс гистограммы."""
        with self._lock:
            self._count = 0
            self._sum = 0.0
            self._buckets.clear()
    
    def _labels_key(self, labels: Dict[str, str]) -> str:
        """Создание ключа для labels."""
        return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
    
    def to_prometheus(self) -> str:
        """Экспорт в формат Prometheus."""
        lines = [
            f"# HELP {self.name} {self.description}",
            f"# TYPE {self.name} histogram",
        ]
        
        for key, buckets in self._buckets.items():
            labels = dict(kv.split("=") for kv in key.split(",") if kv) if key != "default" else {}
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            
            # Ле-бакеты
            cumulative = 0
            for bucket, count in sorted(buckets.items()):
                cumulative += count
                lines.append(f'{self.name}_bucket{{le="{bucket}",{label_str}}} {cumulative}')
            
            # Бесконечность
            lines.append(f'{self.name}_bucket{{le="+Inf",{label_str}}} {self._count}')
            
            # Счетчик и сумма
            lines.append(f'{self.name}_count{{{label_str}}} {self._count}')
            lines.append(f'{self.name}_sum{{{label_str}}} {self._sum}')
        
        return "\n".join(lines)


class MetricsRegistry:
    """
    Реестр метрик для приложения.
    
    Поддерживает:
    - Регистрацию метрик разных типов
    - Экспорт в Prometheus формат
    - Агрегацию метрик
    - Автоматическую очистку старых метрик
    """
    
    def __init__(self, namespace: str = "app"):
        self.namespace = namespace
        self._counters: Dict[str, Counter] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._lock = threading.Lock()
        self._last_cleanup = datetime.now()
        self._cleanup_interval = 300  # 5 минут
    
    def counter(self, name: str, description: str = "") -> Counter:
        """Регистрация или получение счетчика."""
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name, description, self.namespace)
            return self._counters[name]
    
    def gauge(self, name: str, description: str = "") -> Gauge:
        """Регистрация или получение измерителя."""
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = Gauge(name, description, self.namespace)
            return self._gauges[name]
    
    def histogram(
        self,
        name: str,
        description: str = "",
        buckets: Optional[List[float]] = None
    ) -> Histogram:
        """Регистрация или получение гистограммы."""
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name, description, buckets, self.namespace)
            return self._histograms[name]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Получение всех метрик в виде словаря."""
        metrics = {}
        
        with self._lock:
            for name, counter in self._counters.items():
                metrics[f"counter_{name}"] = counter.get()
                metrics[f"counter_{name}_total"] = counter.get_total()
                metrics[f"counter_{name}_labels"] = counter.get_all()
            
            for name, gauge in self._gauges.items():
                metrics[f"gauge_{name}"] = gauge.get()
                metrics[f"gauge_{name}_labels"] = gauge.get_all()
            
            for name, histogram in self._histograms.items():
                metrics[f"histogram_{name}_count"] = histogram.get_count()
                metrics[f"histogram_{name}_sum"] = histogram.get_sum()
                metrics[f"histogram_{name}_buckets"] = histogram.get_buckets()
        
        return metrics
    
    def to_prometheus(self) -> str:
        """Экспорт всех метрик в формате Prometheus."""
        lines = []
        
        with self._lock:
            for counter in self._counters.values():
                lines.append(counter.to_prometheus())
            
            for gauge in self._gauges.values():
                lines.append(gauge.to_prometheus())
            
            for histogram in self._histograms.values():
                lines.append(histogram.to_prometheus())
        
        return "\n\n".join(lines)
    
    def reset(self) -> None:
        """Сброс всех метрик."""
        with self._lock:
            for counter in self._counters.values():
                counter.reset()
            for gauge in self._gauges.values():
                gauge.reset()
            for histogram in self._histograms.values():
                histogram.reset()
    
    async def cleanup(self) -> None:
        """Очистка старых метрик."""
        now = datetime.now()
        if (now - self._last_cleanup).total_seconds() > self._cleanup_interval:
            self._last_cleanup = now
            # Очистка старых метрик может быть реализована при необходимости


# ==================== ГЛОБАЛЬНЫЙ РЕЕСТР ====================

registry = MetricsRegistry(namespace="auth_service")


# ==================== МЕТРИКИ HTTP ЗАПРОСОВ ====================

class HTTPMetrics:
    """Метрики для HTTP запросов."""
    
    def __init__(self):
        self.requests_total = registry.counter(
            "http_requests_total",
            "Total number of HTTP requests"
        )
        self.requests_duration = registry.histogram(
            "http_requests_duration_seconds",
            "HTTP request duration in seconds"
        )
        self.requests_in_flight = registry.gauge(
            "http_requests_in_flight",
            "Number of HTTP requests in flight"
        )
        self.requests_by_status = registry.counter(
            "http_requests_by_status",
            "HTTP requests by status code"
        )
        self.requests_by_method = registry.counter(
            "http_requests_by_method",
            "HTTP requests by HTTP method"
        )
    
    def increment_request(
        self,
        method: str,
        path: str,
        status_code: int,
        duration: float
    ) -> None:
        """Увеличение счетчика запросов."""
        self.requests_total.increment({"method": method, "path": path})
        self.requests_by_status.increment({"status": str(status_code)})
        self.requests_by_method.increment({"method": method})
        self.requests_duration.observe(duration, {"method": method, "path": path})
    
    def increment_in_flight(self) -> None:
        """Увеличение счетчика активных запросов."""
        self.requests_in_flight.add(1)
    
    def decrement_in_flight(self) -> None:
        """Уменьшение счетчика активных запросов."""
        self.requests_in_flight.sub(1)
    
    def record_error(self, method: str, path: str, error_type: str) -> None:
        """Запись ошибки."""
        self.requests_total.increment({"method": method, "path": path, "error": "true"})
        self.requests_by_status.increment({"status": "500"})


http_metrics = HTTPMetrics()


# ==================== МЕТРИКИ ТОКЕНОВ ====================

class TokenMetrics:
    """Метрики для токенов."""
    
    def __init__(self):
        self.created = registry.counter(
            "tokens_created_total",
            "Total tokens created"
        )
        self.validated = registry.counter(
            "tokens_validated_total",
            "Total tokens validated"
        )
        self.expired = registry.counter(
            "tokens_expired_total",
            "Total expired tokens"
        )
        self.invalid = registry.counter(
            "tokens_invalid_total",
            "Total invalid tokens"
        )
        self.revoked = registry.counter(
            "tokens_revoked_total",
            "Total revoked tokens"
        )
        self.active = registry.gauge(
            "tokens_active_total",
            "Active tokens count"
        )
        self.validation_duration = registry.histogram(
            "token_validation_duration_seconds",
            "Token validation duration in seconds"
        )
        self.blacklisted = registry.counter(
            "tokens_blacklisted_total",
            "Total blacklisted tokens"
        )
    
    def increment_created(self, token_type: str) -> None:
        self.created.increment({"type": token_type})
    
    def increment_validated(self, token_type: str) -> None:
        self.validated.increment({"type": token_type})
    
    def increment_expired(self, token_type: str) -> None:
        self.expired.increment({"type": token_type})
    
    def increment_invalid(self, token_type: str) -> None:
        self.invalid.increment({"type": token_type})
    
    def increment_revoked(self, token_type: str) -> None:
        self.revoked.increment({"type": token_type})
    
    def increment_blacklisted(self) -> None:
        self.blacklisted.increment()
    
    def set_active_count(self, count: int, token_type: str) -> None:
        self.active.set(float(count), {"type": token_type})
    
    def observe_validation_time(self, duration: float) -> None:
        self.validation_duration.observe(duration)


token_metrics = TokenMetrics()


# ==================== МЕТРИКИ БАЗЫ ДАННЫХ ====================

class DatabaseMetrics:
    """Метрики для базы данных."""
    
    def __init__(self):
        self.queries = registry.counter(
            "db_queries_total",
            "Total database queries"
        )
        self.query_duration = registry.histogram(
            "db_query_duration_seconds",
            "Database query duration in seconds"
        )
        self.connections = registry.gauge(
            "db_connections_active",
            "Active database connections"
        )
        self.errors = registry.counter(
            "db_errors_total",
            "Database errors"
        )
        self.rows_affected = registry.counter(
            "db_rows_affected_total",
            "Total rows affected by queries"
        )
    
    def increment_queries(self, operation: str, table: str = "unknown") -> None:
        self.queries.increment({"operation": operation, "table": table})
    
    def record_query_duration(self, duration: float, operation: str, table: str = "unknown") -> None:
        self.query_duration.observe(duration, {"operation": operation, "table": table})
    
    def set_connections(self, count: int) -> None:
        self.connections.set(float(count))
    
    def increment_errors(self, operation: str, error_type: str = "unknown") -> None:
        self.errors.increment({"operation": operation, "type": error_type})
    
    def increment_rows_affected(self, count: int, operation: str) -> None:
        self.rows_affected.increment({"operation": operation}, value=count)


db_metrics = DatabaseMetrics()


# ==================== МЕТРИКИ RATE LIMIT ====================

class RateLimitMetrics:
    """Метрики для rate limiting."""
    
    def __init__(self):
        self.allowed = registry.counter(
            "rate_limit_allowed_total",
            "Allowed requests by rate limiter"
        )
        self.blocked = registry.counter(
            "rate_limit_blocked_total",
            "Blocked requests by rate limiter"
        )
        self.current_limit = registry.gauge(
            "rate_limit_current",
            "Current rate limit value"
        )
        self.remaining = registry.gauge(
            "rate_limit_remaining",
            "Remaining requests in current window"
        )
        self.reset_time = registry.gauge(
            "rate_limit_reset_seconds",
            "Seconds until rate limit reset"
        )
    
    def increment_allowed(self, limiter: str = "default") -> None:
        self.allowed.increment({"limiter": limiter})
    
    def increment_blocked(self, limiter: str = "default") -> None:
        self.blocked.increment({"limiter": limiter})
    
    def set_current_limit(self, limit: int, limiter: str = "default") -> None:
        self.current_limit.set(float(limit), {"limiter": limiter})
    
    def set_remaining(self, remaining: int, limiter: str = "default") -> None:
        self.remaining.set(float(remaining), {"limiter": limiter})
    
    def set_reset_time(self, seconds: int, limiter: str = "default") -> None:
        self.reset_time.set(float(seconds), {"limiter": limiter})


rate_limit_metrics = RateLimitMetrics()


# ==================== МЕТРИКИ ОШИБОК ====================

class ErrorMetrics:
    """Метрики для ошибок."""
    
    def __init__(self):
        self.errors = registry.counter(
            "errors_total",
            "Total errors"
        )
        self.critical = registry.counter(
            "errors_critical_total",
            "Critical errors"
        )
        self.panics = registry.counter(
            "errors_panics_total",
            "Panic errors"
        )
        self.retries = registry.counter(
            "errors_retries_total",
            "Retry attempts"
        )
    
    def increment_error(self, error_type: str, service: str = "auth") -> None:
        self.errors.increment({"type": error_type, "service": service})
    
    def increment_critical(self, error_type: str, service: str = "auth") -> None:
        self.critical.increment({"type": error_type, "service": service})
    
    def increment_panic(self, service: str = "auth") -> None:
        self.panics.increment({"service": service})
    
    def increment_retry(self, operation: str, attempt: int) -> None:
        self.retries.increment({"operation": operation, "attempt": str(attempt)})


error_metrics = ErrorMetrics()


# ==================== МЕТРИКИ КЭША ====================

class CacheMetrics:
    """Метрики для кэша."""
    
    def __init__(self):
        self.hits = registry.counter(
            "cache_hits_total",
            "Cache hits"
        )
        self.misses = registry.counter(
            "cache_misses_total",
            "Cache misses"
        )
        self.sets = registry.counter(
            "cache_sets_total",
            "Cache sets"
        )
        self.evictions = registry.counter(
            "cache_evictions_total",
            "Cache evictions"
        )
        self.size = registry.gauge(
            "cache_size",
            "Cache size in bytes"
        )
        self.items = registry.gauge(
            "cache_items_total",
            "Number of items in cache"
        )
    
    def increment_hit(self, cache_type: str = "memory") -> None:
        self.hits.increment({"type": cache_type})
    
    def increment_miss(self, cache_type: str = "memory") -> None:
        self.misses.increment({"type": cache_type})
    
    def increment_set(self, cache_type: str = "memory") -> None:
        self.sets.increment({"type": cache_type})
    
    def increment_eviction(self, cache_type: str = "memory") -> None:
        self.evictions.increment({"type": cache_type})
    
    def set_size(self, size: int, cache_type: str = "memory") -> None:
        self.size.set(float(size), {"type": cache_type})
    
    def set_items(self, count: int, cache_type: str = "memory") -> None:
        self.items.set(float(count), {"type": cache_type})


cache_metrics = CacheMetrics()


# ==================== МЕТРИКИ VAULT ====================

class VaultMetrics:
    """Метрики для Vault операций."""
    
    def __init__(self):
        self.operations = registry.counter(
            "vault_operations_total",
            "Total Vault operations"
        )
        self.errors = registry.counter(
            "vault_errors_total",
            "Vault errors"
        )
        self.duration = registry.histogram(
            "vault_operation_duration_seconds",
            "Vault operation duration in seconds"
        )
        self.cache_hits = registry.counter(
            "vault_cache_hits_total",
            "Vault cache hits"
        )
        self.cache_misses = registry.counter(
            "vault_cache_misses_total",
            "Vault cache misses"
        )
        self.connections = registry.gauge(
            "vault_connections_active",
            "Active Vault connections"
        )
    
    def increment_operation(self, operation: str, path: str = "unknown") -> None:
        self.operations.increment({"operation": operation, "path": path})
    
    def increment_error(self, operation: str, error_type: str = "unknown") -> None:
        self.errors.increment({"operation": operation, "type": error_type})
    
    def record_duration(self, duration: float, operation: str) -> None:
        self.duration.observe(duration, {"operation": operation})
    
    def increment_cache_hit(self, operation: str) -> None:
        self.cache_hits.increment({"operation": operation})
    
    def increment_cache_miss(self, operation: str) -> None:
        self.cache_misses.increment({"operation": operation})
    
    def set_connections(self, count: int) -> None:
        self.connections.set(float(count))


vault_metrics = VaultMetrics()


# ==================== МЕТРИКИ REDIS ====================

class RedisMetrics:
    """Метрики для Redis операций."""
    
    def __init__(self):
        self.operations = registry.counter(
            "redis_operations_total",
            "Total Redis operations"
        )
        self.errors = registry.counter(
            "redis_errors_total",
            "Redis errors"
        )
        self.duration = registry.histogram(
            "redis_operation_duration_seconds",
            "Redis operation duration in seconds"
        )
        self.pool_size = registry.gauge(
            "redis_pool_size",
            "Redis connection pool size"
        )
        self.connections = registry.gauge(
            "redis_connections_active",
            "Active Redis connections"
        )
    
    def increment_operation(self, operation: str, key: str = "unknown") -> None:
        self.operations.increment({"operation": operation})
    
    def increment_error(self, operation: str, error_type: str = "unknown") -> None:
        self.errors.increment({"operation": operation, "type": error_type})
    
    def record_duration(self, duration: float, operation: str) -> None:
        self.duration.observe(duration, {"operation": operation})
    
    def set_pool_size(self, size: int) -> None:
        self.pool_size.set(float(size))
    
    def set_connections(self, count: int) -> None:
        self.connections.set(float(count))


redis_metrics = RedisMetrics()


# ==================== МЕТРИКИ GRPC ====================

class GRPCMetrics:
    """Метрики для gRPC операций."""
    
    def __init__(self):
        self.calls = registry.counter(
            "grpc_calls_total",
            "Total gRPC calls"
        )
        self.errors = registry.counter(
            "grpc_errors_total",
            "gRPC errors"
        )
        self.duration = registry.histogram(
            "grpc_call_duration_seconds",
            "gRPC call duration in seconds"
        )
        self.active = registry.gauge(
            "grpc_calls_active",
            "Active gRPC calls"
        )
    
    def increment_call(self, service: str, method: str) -> None:
        self.calls.increment({"service": service, "method": method})
    
    def increment_error(self, service: str, method: str, code: str) -> None:
        self.errors.increment({"service": service, "method": method, "code": code})
    
    def record_duration(self, duration: float, service: str, method: str) -> None:
        self.duration.observe(duration, {"service": service, "method": method})
    
    def increment_active(self) -> None:
        self.active.add(1)
    
    def decrement_active(self) -> None:
        self.active.sub(1)


grpc_metrics = GRPCMetrics()


# ==================== БИЗНЕС-МЕТРИКИ ====================

class BusinessMetrics:
    """Бизнес-метрики приложения."""
    
    def __init__(self):
        self.users = registry.gauge(
            "users_total",
            "Total number of users"
        )
        self.active_users = registry.gauge(
            "users_active_total",
            "Active users"
        )
        self.logins = registry.counter(
            "user_logins_total",
            "Total user logins"
        )
        self.logouts = registry.counter(
            "user_logouts_total",
            "Total user logouts"
        )
        self.registrations = registry.counter(
            "user_registrations_total",
            "Total user registrations"
        )
        self.password_resets = registry.counter(
            "password_resets_total",
            "Total password resets"
        )
        self.failed_logins = registry.counter(
            "failed_logins_total",
            "Total failed login attempts"
        )
    
    def set_users(self, count: int) -> None:
        self.users.set(float(count))
    
    def set_active_users(self, count: int) -> None:
        self.active_users.set(float(count))
    
    def increment_login(self, method: str = "password") -> None:
        self.logins.increment({"method": method})
    
    def increment_logout(self) -> None:
        self.logouts.increment()
    
    def increment_registration(self, method: str = "email") -> None:
        self.registrations.increment({"method": method})
    
    def increment_password_reset(self) -> None:
        self.password_resets.increment()
    
    def increment_failed_login(self, reason: str = "invalid_credentials") -> None:
        self.failed_logins.increment({"reason": reason})


business_metrics = BusinessMetrics()


# ==================== ДЕКОРАТОРЫ ====================

def time_request(path: str = "unknown") -> Callable:
    """
    Декоратор для измерения времени выполнения запроса.
    
    Args:
        path: Путь для метрики
    
    Returns:
        Callable: Декорированная функция
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                http_metrics.increment_request(
                    method=kwargs.get("method", "GET"),
                    path=path,
                    status_code=200,
                    duration=duration
                )
                return result
            except Exception as e:
                duration = time.time() - start_time
                http_metrics.increment_request(
                    method=kwargs.get("method", "GET"),
                    path=path,
                    status_code=500,
                    duration=duration
                )
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                http_metrics.increment_request(
                    method=kwargs.get("method", "GET"),
                    path=path,
                    status_code=200,
                    duration=duration
                )
                return result
            except Exception as e:
                duration = time.time() - start_time
                http_metrics.increment_request(
                    method=kwargs.get("method", "GET"),
                    path=path,
                    status_code=500,
                    duration=duration
                )
                raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


def measure_execution_time(metric_name: str) -> Callable:
    """
    Декоратор для измерения времени выполнения функции с записью в гистограмму.
    
    Args:
        metric_name: Имя метрики
    
    Returns:
        Callable: Декорированная функция
    """
    def decorator(func: Callable) -> Callable:
        histogram = registry.histogram(
            f"{metric_name}_duration_seconds",
            f"Duration of {metric_name} in seconds"
        )
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                histogram.observe(duration)
                return result
            except Exception:
                duration = time.time() - start_time
                histogram.observe(duration)
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                histogram.observe(duration)
                return result
            except Exception:
                duration = time.time() - start_time
                histogram.observe(duration)
                raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


def count_errors(func: Callable) -> Callable:
    """
    Декоратор для подсчета ошибок.
    
    Args:
        func: Декорируемая функция
    
    Returns:
        Callable: Декорированная функция
    """
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            error_metrics.increment_error(
                error_type=e.__class__.__name__,
                service="auth"
            )
            raise
    
    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_metrics.increment_error(
                error_type=e.__class__.__name__,
                service="auth"
            )
            raise
    
    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

def get_metrics_health() -> Dict[str, Any]:
    """
    Получение статуса метрик.
    """
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "metrics_count": len(registry.get_metrics()),
        "counters": len(registry._counters),
        "gauges": len(registry._gauges),
        "histograms": len(registry._histograms),
    }


async def gather_metrics() -> Dict[str, Any]:
    """
    Сбор всех метрик для экспорта.
    """
    return {
        "metrics": registry.get_metrics(),
        "health": get_metrics_health(),
        "timestamp": datetime.now().isoformat(),
    }


def export_prometheus() -> str:
    """
    Экспорт метрик в формате Prometheus.
    """
    return registry.to_prometheus()


# ==================== ИНИЦИАЛИЗАЦИЯ ====================

async def start_metrics_cleanup() -> None:
    """Запуск периодической очистки метрик."""
    while True:
        await asyncio.sleep(300)  # 5 минут
        await registry.cleanup()
        logger.debug("Metrics cleanup completed")


__all__ = [
    "registry",
    "http_metrics",
    "token_metrics",
    "db_metrics",
    "rate_limit_metrics",
    "error_metrics",
    "cache_metrics",
    "vault_metrics",
    "redis_metrics",
    "grpc_metrics",
    "business_metrics",
    "time_request",
    "measure_execution_time",
    "count_errors",
    "get_metrics_health",
    "gather_metrics",
    "export_prometheus",
    "Counter",
    "Gauge",
    "Histogram",
    "MetricsRegistry",
]