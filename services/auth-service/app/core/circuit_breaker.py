"""
Circuit Breaker для защиты от каскадных отказов.

Реализует паттерн Circuit Breaker для внешних зависимостей:
- Redis
- Kafka
- PostgreSQL
- Внешние OAuth API

Состояния:
- CLOSED: нормальная работа, запросы проходят
- OPEN: цепь разомкнута, запросы отклоняются без вызова зависимости
- HALF_OPEN: пробный запрос для проверки восстановления

Совместимость с тестами:
- test_circuit_breaker_opens_after_5_redis_failures: 5 отказов → OPEN
- test_circuit_breaker_half_open_after_timeout: OPEN → HALF_OPEN → CLOSED
- test_circuit_breaker_reset_on_successful_recovery: сброс счётчика после успеха
- test_circuit_breaker_ignores_single_transient_failure: одиночный отказ не OPEN
- test_circuit_breaker_timeout_reset: автоматический сброс по таймауту
- test_circuit_breaker_state_in_health_check: состояние в health/detailed
- test_circuit_breaker_metrics_prometheus_format: метрики для Prometheus

Связанные модули:
- app.core.redis_client - клиент Redis (использует Circuit Breaker)
- app.routers.health - health check (отображает состояние цепей)
- app.core.config - настройки таймаутов и порогов
"""

import time
from enum import Enum
from typing import Dict, Optional

from app.core.logging import get_logger

logger = get_logger(__name__)


class CircuitState(Enum):
    """Состояния Circuit Breaker."""
    CLOSED = "closed"        # Нормальная работа
    OPEN = "open"            # Цепь разомкнута, запросы блокируются
    HALF_OPEN = "half_open"  # Пробный запрос для проверки восстановления


class CircuitBreaker:
    """
    Реализация паттерна Circuit Breaker.

    Защищает сервис от каскадных отказов при проблемах с зависимостями.
    После N последовательных отказов цепь размыкается на timeout секунд.
    """

    # Настройки по умолчанию
    DEFAULT_FAILURE_THRESHOLD = 5     # Количество отказов для размыкания
    DEFAULT_TIMEOUT_SECONDS = 30      # Время в OPEN до перехода в HALF_OPEN
    DEFAULT_HALF_OPEN_MAX_REQUESTS = 1  # Количество пробных запросов в HALF_OPEN

    def __init__(
        self,
        name: str,
        failure_threshold: int = None,
        timeout_seconds: int = None,
        half_open_max_requests: int = None,
    ):
        """
        Инициализация Circuit Breaker для конкретной зависимости.

        Args:
            name: Имя зависимости (redis, kafka, postgresql, oauth_google)
            failure_threshold: Количество отказов для размыкания (по умолчанию 5)
            timeout_seconds: Таймаут в OPEN состоянии (по умолчанию 30)
            half_open_max_requests: Количество пробных запросов в HALF_OPEN (по умолчанию 1)
        """
        self.name = name
        self.failure_threshold = failure_threshold or self.DEFAULT_FAILURE_THRESHOLD
        self.timeout_seconds = timeout_seconds or self.DEFAULT_TIMEOUT_SECONDS
        self.half_open_max_requests = half_open_max_requests or self.DEFAULT_HALF_OPEN_MAX_REQUESTS

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._opened_at: Optional[float] = None
        self._half_open_requests = 0

    # ==================== СВОЙСТВА ====================

    @property
    def state(self) -> CircuitState:
        """Текущее состояние цепи."""
        self._transition_state()
        return self._state

    @property
    def is_open(self) -> bool:
        """True если цепь разомкнута (запросы не проходят)."""
        return self.state == CircuitState.OPEN

    @property
    def failure_count(self) -> int:
        """Количество последовательных отказов."""
        return self._failure_count

    # ==================== ОСНОВНЫЕ МЕТОДЫ ====================

    def record_failure(self) -> None:
        """
        Запись отказа зависимости.

        Увеличивает счётчик отказов. При достижении порога размыкает цепь.
        Вызывается при ConnectionError, TimeoutError, OperationalError.
        """
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        logger.warning(
            f"Circuit Breaker '{self.name}': failure {self._failure_count}/{self.failure_threshold}"
        )

        if self._failure_count >= self.failure_threshold:
            self._open_circuit()

    def record_success(self) -> None:
        """
        Запись успешного вызова зависимости.

        Сбрасывает счётчик отказов. В HALF_OPEN — закрывает цепь.
        Вызывается при успешном ответе от зависимости.
        """
        self._success_count += 1

        if self._state == CircuitState.HALF_OPEN:
            self._half_open_requests += 1
            if self._half_open_requests >= self.half_open_max_requests:
                self._close_circuit()
                logger.info(f"Circuit Breaker '{self.name}': CLOSED after successful HALF_OPEN")
        else:
            # В CLOSED состоянии сбрасываем счётчик отказов при успехе
            if self._failure_count > 0:
                logger.debug(
                    f"Circuit Breaker '{self.name}': reset failure count "
                    f"(was {self._failure_count})"
                )
            self._failure_count = 0

    def allow_request(self) -> bool:
        """
        Проверка, можно ли выполнить запрос к зависимости.

        Returns:
            bool: True если запрос разрешён

        Используется перед вызовом зависимости:
            if circuit_breaker.allow_request():
                try:
                    result = await redis.get(key)
                    circuit_breaker.record_success()
                except Exception:
                    circuit_breaker.record_failure()
                    raise
            else:
                raise CircuitBreakerOpenError(dependency_name)
        """
        self._transition_state()

        if self._state == CircuitState.OPEN:
            return False

        if self._state == CircuitState.HALF_OPEN:
            # В HALF_OPEN разрешаем ограниченное количество пробных запросов
            return self._half_open_requests < self.half_open_max_requests

        return True  # CLOSED

    # ==================== УПРАВЛЕНИЕ СОСТОЯНИЯМИ ====================

    def _open_circuit(self) -> None:
        """Размыкание цепи."""
        self._state = CircuitState.OPEN
        self._opened_at = time.monotonic()
        self._half_open_requests = 0
        logger.warning(
            f"Circuit Breaker '{self.name}': OPEN "
            f"(failures: {self._failure_count}, timeout: {self.timeout_seconds}s)"
        )

    def _close_circuit(self) -> None:
        """Замыкание цепи (возврат к нормальной работе)."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._half_open_requests = 0
        self._opened_at = None
        logger.info(f"Circuit Breaker '{self.name}': CLOSED (normal operation)")

    def _half_open_circuit(self) -> None:
        """Переход в HALF_OPEN для проверки восстановления."""
        self._state = CircuitState.HALF_OPEN
        self._half_open_requests = 0
        logger.info(f"Circuit Breaker '{self.name}': HALF_OPEN (testing recovery)")

    def _transition_state(self) -> None:
        """
        Проверка необходимости перехода между состояниями.

        Вызывается при каждом allow_request() и state.
        Автоматически переводит OPEN → HALF_OPEN по истечении таймаута.
        """
        if self._state == CircuitState.OPEN and self._opened_at is not None:
            elapsed = time.monotonic() - self._opened_at
            if elapsed >= self.timeout_seconds:
                self._half_open_circuit()

    # ==================== СБРОС ====================

    def reset(self) -> None:
        """
        Принудительный сброс цепи в CLOSED.

        Используется для ручного восстановления или в тестах.
        """
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_requests = 0
        self._opened_at = None
        self._last_failure_time = None
        logger.info(f"Circuit Breaker '{self.name}': manually reset to CLOSED")

    # ==================== ИНФОРМАЦИЯ О СОСТОЯНИИ ====================

    def get_state_info(self) -> dict:
        """
        Получение информации о состоянии для health check и метрик.

        Returns:
            dict: {
                "name": "redis",
                "state": "closed",
                "failure_count": 0,
                "failure_threshold": 5,
                "timeout_seconds": 30,
                "opened_at": None
            }

        Используется в:
        - health/detailed для отображения состояния
        - Prometheus метриках circuit_breaker_state
        """
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "failure_threshold": self.failure_threshold,
            "timeout_seconds": self.timeout_seconds,
            "opened_at": self._opened_at,
            "last_failure_time": self._last_failure_time,
        }


# ==================== ГЛОБАЛЬНЫЙ РЕЕСТР CIRCUIT BREAKER'ОВ ====================

class CircuitBreakerRegistry:
    """
    Реестр всех Circuit Breaker'ов в приложении.

    Предоставляет централизованный доступ к состоянию всех цепей
    для health check и мониторинга.
    """

    def __init__(self):
        """Инициализация реестра."""
        self._breakers: Dict[str, CircuitBreaker] = {}

    def get_or_create(
        self,
        name: str,
        failure_threshold: int = None,
        timeout_seconds: int = None,
    ) -> CircuitBreaker:
        """
        Получение или создание Circuit Breaker по имени.

        Args:
            name: Имя зависимости
            failure_threshold: Порог отказов
            timeout_seconds: Таймаут OPEN

        Returns:
            CircuitBreaker: экземпляр для указанной зависимости
        """
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(
                name=name,
                failure_threshold=failure_threshold,
                timeout_seconds=timeout_seconds,
            )
            logger.info(f"Circuit Breaker '{name}' created in registry")

        return self._breakers[name]

    def get_all_states(self) -> dict:
        """
        Получение состояния всех цепей для health check.

        Returns:
            dict: {"redis": "closed", "kafka": "closed", ...}

        Используется в health/detailed для отображения:
        {
            "circuit_breakers": {
                "redis": "closed",
                "kafka": "closed",
                "postgresql": "closed"
            }
        }
        """
        return {
            name: breaker.state.value
            for name, breaker in self._breakers.items()
        }

    def get_all_info(self) -> list:
        """
        Получение детальной информации о всех цепях.

        Returns:
            list: список словарей с информацией о каждом Circuit Breaker

        Используется для Prometheus метрик и детального health check.
        """
        return [breaker.get_state_info() for breaker in self._breakers.values()]

    def reset_all(self) -> None:
        """Сброс всех цепей в CLOSED (для тестов)."""
        for breaker in self._breakers.values():
            breaker.reset()
        logger.info("All Circuit Breakers reset to CLOSED")


# Глобальный экземпляр реестра
circuit_breaker_registry = CircuitBreakerRegistry()


# ==================== ПРЕДНАСТРОЕННЫЕ CIRCUIT BREAKER'Ы ====================

def get_redis_circuit_breaker() -> CircuitBreaker:
    """
    Circuit Breaker для Redis.

    Настройки:
    - 5 отказов для размыкания
    - 30 секунд в OPEN
    - 1 пробный запрос в HALF_OPEN

    Используется в app.core.redis_client.
    """
    return circuit_breaker_registry.get_or_create(
        name="redis",
        failure_threshold=5,
        timeout_seconds=30,
    )


def get_kafka_circuit_breaker() -> CircuitBreaker:
    """
    Circuit Breaker для Kafka.

    Настройки:
    - 3 отказа для размыкания (Kafka менее критична)
    - 60 секунд в OPEN (дольше восстанавливается)
    - 1 пробный запрос в HALF_OPEN

    Используется в app.core.kafka_client.
    """
    return circuit_breaker_registry.get_or_create(
        name="kafka",
        failure_threshold=3,
        timeout_seconds=60,
    )


def get_postgresql_circuit_breaker() -> CircuitBreaker:
    """
    Circuit Breaker для PostgreSQL.

    Настройки:
    - 3 отказа для размыкания (БД критична, быстро реагируем)
    - 15 секунд в OPEN (быстрее пробуем восстановиться)
    - 1 пробный запрос в HALF_OPEN

    Используется в app.core.database.
    """
    return circuit_breaker_registry.get_or_create(
        name="postgresql",
        failure_threshold=3,
        timeout_seconds=15,
    )


def get_oauth_circuit_breaker(provider: str) -> CircuitBreaker:
    """
    Circuit Breaker для внешнего OAuth провайдера.

    Настройки:
    - 5 отказов для размыкания
    - 120 секунд в OPEN (внешние API долго восстанавливаются)
    - 1 пробный запрос в HALF_OPEN

    Args:
        provider: Имя провайдера (google, vk, apple)

    Используется в app.services.oauth_service.
    """
    return circuit_breaker_registry.get_or_create(
        name=f"oauth_{provider}",
        failure_threshold=5,
        timeout_seconds=120,
    )


class CircuitBreakerOpenError(Exception):
    """
    Исключение, выбрасываемое при попытке вызова зависимости с OPEN цепью.

    Позволяет вызывающему коду обработать отказ без попытки реального вызова.
    """

    def __init__(self, dependency_name: str):
        self.dependency_name = dependency_name
        super().__init__(
            f"Circuit breaker is OPEN for '{dependency_name}'. "
            f"Request rejected to protect the service."
        )