"""
Health check роутер.

Обеспечивает:
- Liveness probe - проверка живости сервиса (Kubernetes)
- Readiness probe - проверка готовности и всех зависимостей
- Detailed health - детальная информация с метриками
- Prometheus metrics - метрики в формате Prometheus
- Graceful shutdown - поддержка завершения
- Dependency checks - БД, Redis, Kafka, Vault
- Circuit breaker states - состояние защитных цепей
- Timeout handling - защита от зависаний
- Status codes - правильные HTTP статусы для K8s
"""

import asyncio
import time
from datetime import datetime
from typing import Dict, Any, Optional

from fastapi import APIRouter, status, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from app.core.debug import LoggingRoute
from app.core.config import settings
from app.core.logging import get_logger
from app.services.health_service import HealthService


logger = get_logger(__name__)
router = APIRouter(route_class=LoggingRoute)

# Время старта сервиса для расчета uptime
_startup_time = time.time()


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

def get_uptime_seconds() -> float:
    """Возвращает количество секунд с момента старта сервиса."""
    return time.time() - _startup_time


def get_service_info() -> Dict[str, Any]:
    """Возвращает базовую информацию о сервисе."""
    return {
        "service": "auth-service",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ==================== ЭНДПОИНТЫ ====================

@router.get("/", status_code=status.HTTP_200_OK)
async def health_check() -> Dict[str, Any]:
    """
    Простая проверка работоспособности сервиса.

    Используется для базового мониторинга.
    Всегда возвращает 200 OK, если сервис запущен.
    """
    return {
        "status": "ok",
        "service": "auth-service",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/liveness", status_code=status.HTTP_200_OK)
async def liveness_check() -> Dict[str, Any]:
    """
    Проверка живости сервиса (Kubernetes liveness probe).

    Проверяет, что сервис работает и не завис.
    Возвращает 200 OK, если сервис жив.
    В случае зависания процесс будет перезапущен K8s.
    """
    return {
        "status": "alive",
        "service": "auth-service",
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "uptime_seconds": get_uptime_seconds(),
        "version": settings.VERSION,
    }


@router.get("/readiness", status_code=status.HTTP_200_OK)
async def readiness_check(request: Request) -> JSONResponse:
    """
    Проверка готовности сервиса (Kubernetes readiness probe).

    Проверяет все зависимости:
    - PostgreSQL (БД)
    - Redis (кэш/сессии)
    - Kafka (брокер сообщений)
    - Vault (секреты)

    Returns:
        - 200 OK: Все зависимости здоровы
        - 503 Service Unavailable: Есть проблемы
    """
    try:
        # Проверяем все зависимости с таймаутом
        result = await HealthService.check_all_with_timeout(
            timeout_seconds=settings.HEALTH_CHECK_TIMEOUT
        )

        if result["status"] == "ready":
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "status": "ready",
                    "service": "auth-service",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "checks": result.get("checks", {}),
                }
            )
        else:
            # Возвращаем 503 с деталями проблем
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "status": "not_ready",
                    "service": "auth-service",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "checks": result.get("checks", {}),
                    "error": result.get("error", "Dependencies are not ready"),
                }
            )

    except asyncio.TimeoutError:
        logger.error("Readiness check timed out")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not_ready",
                "service": "auth-service",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "error": "Health check timed out",
            }
        )

    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not_ready",
                "service": "auth-service",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "error": str(e),
            }
        )


@router.get("/ready", status_code=status.HTTP_200_OK)
async def ready_alias(request: Request) -> JSONResponse:
    """
    Алиас для /readiness.

    Сохраняет обратную совместимость с предыдущими версиями.
    """
    return await readiness_check(request)


@router.get("/detailed", status_code=status.HTTP_200_OK)
async def detailed_health_check() -> JSONResponse:
    """
    Детальная проверка здоровья с расширенной информацией.

    Включает:
    - Состояние всех зависимостей
    - Метрики производительности
    - Информацию о пулах соединений
    - Статистику запросов
    - Состояние Circuit Breaker'ов

    Используется для глубокого мониторинга и отладки.
    """
    try:
        # Проверяем зависимости
        readiness_result = await HealthService.check_all_with_timeout(
            timeout_seconds=settings.HEALTH_CHECK_TIMEOUT
        )

        # Получаем метрики производительности
        performance_metrics = await HealthService.get_performance_metrics()

        # Получаем состояние Circuit Breaker'ов
        from app.core.circuit_breaker import circuit_breaker_registry
        circuit_breakers = circuit_breaker_registry.get_all_states()

        # Формируем детальный ответ
        response_data = {
            "status": readiness_result["status"],
            "service": "auth-service",
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "uptime_seconds": get_uptime_seconds(),
            "checks": readiness_result.get("checks", {}),
            "performance": performance_metrics,
            "circuit_breakers": circuit_breakers,
        }

        # Если есть ошибки, добавляем их
        if "error" in readiness_result:
            response_data["error"] = readiness_result["error"]

        status_code = (
            status.HTTP_200_OK
            if readiness_result["status"] == "ready"
            else status.HTTP_503_SERVICE_UNAVAILABLE
        )

        return JSONResponse(
            status_code=status_code,
            content=response_data,
        )

    except Exception as e:
        logger.error(f"Detailed health check failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "service": "auth-service",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "error": str(e),
            }
        )


@router.get("/metrics", status_code=status.HTTP_200_OK)
async def prometheus_metrics() -> PlainTextResponse:
    """
    Метрики в формате Prometheus.

    Возвращает метрики для сбора Prometheus:
    - auth_service_uptime_seconds - время работы
    - auth_service_info - информация о сервисе
    - auth_service_postgresql_healthy - статус БД (0/1)
    - auth_service_redis_healthy - статус Redis (0/1)
    - auth_service_kafka_healthy - статус Kafka (0/1)
    - auth_service_vault_healthy - статус Vault (0/1)
    - auth_service_readiness_ready - статус готовности (0/1)
    - circuit_breaker_state - состояние защитных цепей
    - circuit_breaker_failures - количество отказов цепей
    - db_pool_size - размер пула соединений
    - redis_connections - количество подключений к Redis
    - kafka_brokers - количество брокеров Kafka
    """
    try:
        # Получаем статус зависимостей
        readiness = await HealthService.get_readiness()
        performance = await HealthService.get_performance_metrics()

        # Получаем состояние Circuit Breaker'ов
        from app.core.circuit_breaker import circuit_breaker_registry
        breakers_info = circuit_breaker_registry.get_all_info()

        # Строим метрики в формате Prometheus
        metrics_lines = [
            "# HELP auth_service_uptime_seconds Uptime of the auth service in seconds",
            "# TYPE auth_service_uptime_seconds gauge",
            f"auth_service_uptime_seconds {get_uptime_seconds():.2f}",
            "",
            "# HELP auth_service_info Service information",
            "# TYPE auth_service_info gauge",
            f'auth_service_info{{version="{settings.VERSION}",environment="{settings.ENVIRONMENT}"}} 1',
            "",
            "# HELP auth_service_postgresql_healthy PostgreSQL health status (1=healthy, 0=unhealthy)",
            "# TYPE auth_service_postgresql_healthy gauge",
            f"auth_service_postgresql_healthy {1 if readiness.get('postgresql', {}).get('healthy', False) else 0}",
            "",
            "# HELP auth_service_redis_healthy Redis health status (1=healthy, 0=unhealthy)",
            "# TYPE auth_service_redis_healthy gauge",
            f"auth_service_redis_healthy {1 if readiness.get('redis', {}).get('healthy', False) else 0}",
            "",
            "# HELP auth_service_kafka_healthy Kafka health status (1=healthy, 0=unhealthy)",
            "# TYPE auth_service_kafka_healthy gauge",
            f"auth_service_kafka_healthy {1 if readiness.get('kafka', {}).get('healthy', False) else 0}",
            "",
            "# HELP auth_service_vault_healthy Vault health status (1=healthy, 0=unhealthy)",
            "# TYPE auth_service_vault_healthy gauge",
            f"auth_service_vault_healthy {1 if readiness.get('vault', {}).get('healthy', False) else 0}",
            "",
            "# HELP auth_service_readiness_ready Service readiness status (1=ready, 0=not_ready)",
            "# TYPE auth_service_readiness_ready gauge",
            f"auth_service_readiness_ready {1 if readiness.get('_ready', False) else 0}",
            "",
        ]

        # Метрики Circuit Breaker
        if breakers_info:
            metrics_lines.extend([
                "# HELP circuit_breaker_state Circuit breaker state (0=closed, 1=open, 2=half_open)",
                "# TYPE circuit_breaker_state gauge",
            ])
            for breaker in breakers_info:
                state_map = {"closed": 0, "open": 1, "half_open": 2}
                state_value = state_map.get(breaker["state"], 0)
                metrics_lines.append(
                    f'circuit_breaker_state{{service="{breaker["name"]}"}} {state_value}'
                )
            metrics_lines.append("")

            metrics_lines.extend([
                "# HELP circuit_breaker_failures Circuit breaker failure count",
                "# TYPE circuit_breaker_failures gauge",
            ])
            for breaker in breakers_info:
                metrics_lines.append(
                    f'circuit_breaker_failures{{service="{breaker["name"]}"}} {breaker["failure_count"]}'
                )
            metrics_lines.append("")

        # Добавляем метрики производительности
        db_pool = performance.get("db_pool_status", {})
        if db_pool:
            metrics_lines.extend([
                "# HELP db_pool_size Database connection pool size",
                "# TYPE db_pool_size gauge",
                f"db_pool_size {db_pool.get('size', 0)}",
                "",
                "# HELP db_pool_used Database connections currently in use",
                "# TYPE db_pool_used gauge",
                f"db_pool_used {db_pool.get('used', 0)}",
                "",
            ])

        redis_info = performance.get("redis_info", {})
        if redis_info:
            metrics_lines.extend([
                "# HELP redis_connections Redis active connections",
                "# TYPE redis_connections gauge",
                f"redis_connections {redis_info.get('connected_clients', 0)}",
                "",
                "# HELP redis_commands_processed Redis total commands processed",
                "# TYPE redis_commands_processed counter",
                f"redis_commands_processed {redis_info.get('total_commands_processed', 0)}",
                "",
            ])

        kafka_info = performance.get("kafka_info", {})
        if kafka_info:
            brokers = kafka_info.get("brokers", [])
            metrics_lines.extend([
                "# HELP kafka_brokers Number of Kafka brokers",
                "# TYPE kafka_brokers gauge",
                f"kafka_brokers {len(brokers)}",
                "",
                "# HELP kafka_topics Number of Kafka topics",
                "# TYPE kafka_topics gauge",
                f"kafka_topics {len(kafka_info.get('topics', []))}",
                "",
            ])

        return PlainTextResponse(
            content="\n".join(metrics_lines),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    except Exception as e:
        logger.error(f"Failed to generate Prometheus metrics: {e}")
        return PlainTextResponse(
            content=f"# ERROR: {str(e)}\n",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )


@router.get("/live", status_code=status.HTTP_200_OK)
async def liveness_alias() -> Dict[str, Any]:
    """
    Алиас для /liveness.

    Сохраняет обратную совместимость с предыдущими версиями.
    """
    return await liveness_check()