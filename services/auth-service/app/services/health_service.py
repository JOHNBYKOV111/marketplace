"""
Health check service.

Обеспечивает:
- Проверку всех зависимостей (БД, Redis, Kafka, Vault)
- Сбор метрик производительности
- Graceful shutdown проверки
- Timeout защиту
- Статусы готовности (ready, not_ready, degraded, unhealthy)
- Асинхронные проверки с параллельным выполнением
"""

import asyncio
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from app.core.config import settings
from app.core.database import db_manager
from app.core.redis_client import redis_client
from app.core.kafka_client import kafka_producer
from app.core.vault_client import vault_client
from app.core.logging import get_logger


logger = get_logger(__name__)

# Время старта сервиса
_startup_time = time.time()


class HealthService:
    """
    Сервис для проверки здоровья и готовности приложения.
    
    Предоставляет методы для проверки всех зависимостей,
    сбора метрик и определения статуса сервиса.
    """
    
    @staticmethod
    async def check_database() -> Dict[str, Any]:
        """
        Проверка подключения к PostgreSQL.
        
        Returns:
            Dict: Статус проверки с полями:
                - healthy: bool
                - message: str
                - latency_ms: float (опционально)
                - error: str (опционально)
        """
        start_time = time.time()
        try:
            is_healthy = await db_manager.ping()
            latency_ms = (time.time() - start_time) * 1000
            
            if is_healthy:
                return {
                    "healthy": True,
                    "message": "Connected to PostgreSQL",
                    "latency_ms": round(latency_ms, 2),
                }
            else:
                return {
                    "healthy": False,
                    "message": "PostgreSQL is not responding",
                    "latency_ms": round(latency_ms, 2),
                }
                
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            logger.error(f"Database health check failed: {e}")
            return {
                "healthy": False,
                "message": f"Database connection failed: {str(e)}",
                "latency_ms": round(latency_ms, 2),
                "error": str(e),
            }
    
    @staticmethod
    async def check_redis() -> Dict[str, Any]:
        """
        Проверка подключения к Redis.
        
        Returns:
            Dict: Статус проверки
        """
        start_time = time.time()
        try:
            is_healthy = await redis_client.ping()
            latency_ms = (time.time() - start_time) * 1000
            
            if is_healthy:
                return {
                    "healthy": True,
                    "message": "Connected to Redis",
                    "latency_ms": round(latency_ms, 2),
                }
            else:
                return {
                    "healthy": False,
                    "message": "Redis is not responding",
                    "latency_ms": round(latency_ms, 2),
                }
                
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            logger.error(f"Redis health check failed: {e}")
            return {
                "healthy": False,
                "message": f"Redis connection failed: {str(e)}",
                "latency_ms": round(latency_ms, 2),
                "error": str(e),
            }
    
    @staticmethod
    async def check_kafka() -> Dict[str, Any]:
        """
        Проверка подключения к Kafka.
        
        Returns:
            Dict: Статус проверки
        """
        start_time = time.time()
        try:
            metadata = await kafka_producer.get_metadata()
            latency_ms = (time.time() - start_time) * 1000
            
            if metadata:
                return {
                    "healthy": True,
                    "message": "Connected to Kafka",
                    "latency_ms": round(latency_ms, 2),
                    "brokers": metadata.get("brokers", []),
                    "topics": metadata.get("topics", []),
                }
            else:
                return {
                    "healthy": False,
                    "message": "Kafka is not responding",
                    "latency_ms": round(latency_ms, 2),
                }
                
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            logger.error(f"Kafka health check failed: {e}")
            return {
                "healthy": False,
                "message": f"Kafka connection failed: {str(e)}",
                "latency_ms": round(latency_ms, 2),
                "error": str(e),
            }
    
    @staticmethod
    async def check_vault() -> Dict[str, Any]:
        """
        Проверка подключения к Vault.
        
        Returns:
            Dict: Статус проверки
        """
        start_time = time.time()
        try:
            is_healthy = await vault_client.health_check()
            latency_ms = (time.time() - start_time) * 1000
            
            if is_healthy:
                return {
                    "healthy": True,
                    "message": "Connected to Vault",
                    "latency_ms": round(latency_ms, 2),
                }
            else:
                return {
                    "healthy": False,
                    "message": "Vault is not healthy",
                    "latency_ms": round(latency_ms, 2),
                }
                
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            logger.error(f"Vault health check failed: {e}")
            return {
                "healthy": False,
                "message": f"Vault connection failed: {str(e)}",
                "latency_ms": round(latency_ms, 2),
                "error": str(e),
            }
    
    @staticmethod
    async def check_all_with_timeout(
        timeout_seconds: float = 5.0
    ) -> Dict[str, Any]:
        """
        Проверка всех зависимостей с таймаутом.
        
        Выполняет все проверки параллельно с общим таймаутом.
        
        Args:
            timeout_seconds: Максимальное время выполнения в секундах
        
        Returns:
            Dict: Результат проверки со статусом и деталями
        """
        checks = {}
        all_healthy = True
        errors = []
        
        try:
            # Запускаем все проверки параллельно с таймаутом
            results = await asyncio.wait_for(
                asyncio.gather(
                    HealthService.check_database(),
                    HealthService.check_redis(),
                    HealthService.check_kafka(),
                    HealthService.check_vault(),
                    return_exceptions=True,
                ),
                timeout=timeout_seconds,
            )
            
            # Обрабатываем результаты
            check_names = ["postgresql", "redis", "kafka", "vault"]
            
            for name, result in zip(check_names, results):
                if isinstance(result, Exception):
                    checks[name] = {
                        "healthy": False,
                        "message": f"Check failed: {str(result)}",
                        "error": str(result),
                    }
                    all_healthy = False
                    errors.append(f"{name}: {str(result)}")
                else:
                    checks[name] = result
                    if not result.get("healthy", False):
                        all_healthy = False
                        errors.append(f"{name}: {result.get('message', 'Unhealthy')}")
            
            # Определяем общий статус
            if all_healthy:
                status = "ready"
                message = "All dependencies are healthy"
            else:
                status = "not_ready"
                message = "Some dependencies are unhealthy"
            
            return {
                "status": status,
                "message": message,
                "checks": checks,
                "error": "; ".join(errors) if errors else None,
            }
            
        except asyncio.TimeoutError:
            logger.error(f"Health check timed out after {timeout_seconds}s")
            return {
                "status": "not_ready",
                "message": f"Health check timed out after {timeout_seconds}s",
                "checks": checks or {},
                "error": "Timeout",
            }
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "status": "unhealthy",
                "message": f"Health check failed: {str(e)}",
                "checks": checks or {},
                "error": str(e),
            }
    
    @staticmethod
    async def get_readiness() -> Dict[str, Any]:
        """
        Получение статуса готовности сервиса.
        
        Returns:
            Dict: Статус готовности
        """
        result = await HealthService.check_all_with_timeout(
            timeout_seconds=settings.HEALTH_CHECK_TIMEOUT
        )
        
        # Добавляем общий флаг готовности
        result["_ready"] = result.get("status") == "ready"
        result["timestamp"] = datetime.utcnow().isoformat() + "Z"
        result["service"] = "auth-service"
        
        return result
    
    @staticmethod
    async def get_detailed_health() -> Dict[str, Any]:
        """
        Получение детальной информации о здоровье сервиса.
        
        Returns:
            Dict: Детальный статус
        """
        # Получаем статус готовности
        readiness = await HealthService.get_readiness()
        
        # Получаем метрики производительности
        performance = await HealthService.get_performance_metrics()
        
        return {
            "status": readiness.get("status", "unknown"),
            "service": "auth-service",
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "checks": readiness.get("checks", {}),
            "performance": performance,
            "error": readiness.get("error"),
        }
    
    @staticmethod
    async def get_performance_metrics() -> Dict[str, Any]:
        """
        Сбор метрик производительности.
        
        Returns:
            Dict: Метрики производительности
        """
        metrics = {
            "uptime_seconds": time.time() - _startup_time,
        }
        
        # Метрики БД
        try:
            db_pool_status = await db_manager.get_pool_status()
            metrics["db_pool_status"] = db_pool_status
        except Exception as e:
            logger.warning(f"Failed to get DB pool status: {e}")
            metrics["db_pool_status"] = {"error": str(e)}
        
        # Метрики Redis
        try:
            redis_info = await redis_client.info()
            if redis_info:
                metrics["redis_info"] = {
                    "connected_clients": redis_info.get("connected_clients", 0),
                    "total_connections_received": redis_info.get("total_connections_received", 0),
                    "total_commands_processed": redis_info.get("total_commands_processed", 0),
                    "used_memory_human": redis_info.get("used_memory_human", "0"),
                    "uptime_in_seconds": redis_info.get("uptime_in_seconds", 0),
                }
        except Exception as e:
            logger.warning(f"Failed to get Redis info: {e}")
            metrics["redis_info"] = {"error": str(e)}
        
        # Метрики Kafka
        try:
            metadata = await kafka_producer.get_metadata()
            if metadata:
                metrics["kafka_info"] = {
                    "brokers": metadata.get("brokers", []),
                    "topics": metadata.get("topics", []),
                }
        except Exception as e:
            logger.warning(f"Failed to get Kafka metadata: {e}")
            metrics["kafka_info"] = {"error": str(e)}
        
        return metrics
    
    @staticmethod
    async def get_service_uptime() -> float:
        """
        Получение времени работы сервиса в секундах.
        
        Returns:
            float: Время работы в секундах
        """
        return time.time() - _startup_time


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

async def wait_for_dependencies(
    timeout_seconds: float = 30.0,
    check_interval: float = 1.0,
) -> bool:
    """
    Ожидание готовности всех зависимостей.
    
    Args:
        timeout_seconds: Максимальное время ожидания
        check_interval: Интервал между проверками
    
    Returns:
        bool: True если все зависимости готовы, иначе False
    """
    start_time = time.time()
    last_error = None
    
    while time.time() - start_time < timeout_seconds:
        try:
            result = await HealthService.check_all_with_timeout(
                timeout_seconds=min(5.0, timeout_seconds - (time.time() - start_time))
            )
            
            if result.get("status") == "ready":
                logger.info("All dependencies are ready")
                return True
            
            # Логируем прогресс
            unhealthy = [
                f"{name}: {check.get('message', 'Unknown')}"
                for name, check in result.get("checks", {}).items()
                if not check.get("healthy", False)
            ]
            
            if unhealthy:
                logger.debug(f"Waiting for dependencies: {', '.join(unhealthy)}")
            
        except Exception as e:
            last_error = str(e)
            logger.debug(f"Dependency check failed: {e}")
        
        await asyncio.sleep(check_interval)
    
    logger.error(f"Dependencies not ready after {timeout_seconds}s: {last_error}")
    return False


async def wait_for_database(
    timeout_seconds: float = 30.0,
    check_interval: float = 0.5,
) -> bool:
    """
    Ожидание готовности базы данных.
    
    Args:
        timeout_seconds: Максимальное время ожидания
        check_interval: Интервал между проверками
    
    Returns:
        bool: True если БД готова, иначе False
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout_seconds:
        try:
            result = await HealthService.check_database()
            if result.get("healthy", False):
                logger.info("Database is ready")
                return True
        except Exception as e:
            logger.debug(f"Database not ready: {e}")
        
        await asyncio.sleep(check_interval)
    
    logger.error(f"Database not ready after {timeout_seconds}s")
    return False


async def wait_for_redis(
    timeout_seconds: float = 10.0,
    check_interval: float = 0.5,
) -> bool:
    """
    Ожидание готовности Redis.
    
    Args:
        timeout_seconds: Максимальное время ожидания
        check_interval: Интервал между проверками
    
    Returns:
        bool: True если Redis готов, иначе False
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout_seconds:
        try:
            result = await HealthService.check_redis()
            if result.get("healthy", False):
                logger.info("Redis is ready")
                return True
        except Exception as e:
            logger.debug(f"Redis not ready: {e}")
        
        await asyncio.sleep(check_interval)
    
    logger.error(f"Redis not ready after {timeout_seconds}s")
    return False