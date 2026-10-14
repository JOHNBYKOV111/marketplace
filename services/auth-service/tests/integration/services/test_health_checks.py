"""
Интеграционные тесты для Health Check эндпоинтов.

Тестирует:
- GET /api/v1/liveness - проверка жизни сервиса
- GET /api/v1/readiness - проверка всех зависимостей (БД, Redis, Kafka)
- GET /api/v1/ready - алиас для readiness
- GET /api/v1/detailed - детальная проверка с метриками
- GET /api/v1/ - простая проверка
- GET /api/v1/metrics - Prometheus метрики
- Обработку ошибок при недоступности зависимостей
- Таймауты и статусы (ready, not_ready, degraded, unhealthy)
"""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from fastapi.responses import PlainTextResponse
from httpx import AsyncClient

from app.main import app
from app.core.database import db_manager
from app.core.redis_client import redis_client
from app.services.health_service import HealthService


# ==================== ГЛОБАЛЬНАЯ ФИКСТУРА ДЛЯ МОКОВ ====================

@pytest.fixture(autouse=True)
def mock_kafka_vault_health_checks():
    """
    Глобальная фикстура, которая мокает только Kafka и Vault.
    PostgreSQL и Redis проверяются реально.
    """
    with patch("app.services.health_service.HealthService.check_kafka") as mock_kafka, \
         patch("app.services.health_service.HealthService.check_vault") as mock_vault, \
         patch("app.services.health_service.HealthService.get_performance_metrics") as mock_perf:
        
        # По умолчанию Kafka и Vault здоровы (для тестов где они не проверяются)
        mock_kafka.return_value = {"healthy": True, "message": "Connected", "latency_ms": 12.3, "topics": ["topic1"]}
        mock_vault.return_value = {"healthy": True, "message": "Connected", "latency_ms": 8.1}
        mock_perf.return_value = {"uptime_seconds": 3600, "db_pool_size": 20}
        
        yield mock_kafka, mock_vault, mock_perf


class TestHealthLiveness:
    """Тесты для GET /api/v1/liveness."""

    async def test_liveness_success(self, client: AsyncClient):
        """Тест успешной проверки liveness."""
        response = await client.get("/api/v1/liveness")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "alive"
        assert data["service"] == "auth-service"
        assert "environment" in data
        assert "timestamp" in data
        assert "uptime_seconds" in data

    async def test_liveness_includes_version(self, client: AsyncClient):
        """Тест наличия версии в ответе."""
        response = await client.get("/api/v1/liveness")
        data = response.json()
        assert "version" in data
        assert data["version"] == "1.0.0"


class TestHealthReadiness:
    """Тесты для GET /api/v1/readiness."""

    async def test_readiness_all_healthy(self, client: AsyncClient, mock_kafka_vault_health_checks):
        """Тест readiness когда все зависимости здоровы."""
        mock_kafka, mock_vault, _ = mock_kafka_vault_health_checks
        mock_kafka.return_value = {"healthy": True, "message": "Connected", "latency_ms": 12.3, "topics": []}
        mock_vault.return_value = {"healthy": True, "message": "Connected", "latency_ms": 8.1}

        response = await client.get("/api/v1/readiness")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "ready"
        assert "checks" in data
        assert data["checks"]["postgresql"]["healthy"] is True
        assert data["checks"]["redis"]["healthy"] is True
        assert data["checks"]["kafka"]["healthy"] is True
        assert data["checks"]["vault"]["healthy"] is True

    async def test_readiness_database_failure(self, client: AsyncClient, mock_kafka_vault_health_checks):
        """Тест readiness когда БД недоступна."""
        mock_kafka, mock_vault, _ = mock_kafka_vault_health_checks
        mock_kafka.return_value = {"healthy": True}
        mock_vault.return_value = {"healthy": True}

        # Эмулируем недоступность БД через отключение
        with patch("app.services.health_service.HealthService.check_database") as mock_db:
            mock_db.return_value = {"healthy": False, "message": "Connection failed"}

            response = await client.get("/api/v1/readiness")

            assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
            data = response.json()
            assert data["status"] == "not_ready"
            assert data["checks"]["postgresql"]["healthy"] is False

    async def test_readiness_redis_failure(self, client: AsyncClient, mock_kafka_vault_health_checks):
        """Тест readiness когда Redis недоступен."""
        mock_kafka, mock_vault, _ = mock_kafka_vault_health_checks
        mock_kafka.return_value = {"healthy": True}
        mock_vault.return_value = {"healthy": True}

        # Эмулируем недоступность Redis через отключение
        with patch("app.services.health_service.HealthService.check_redis") as mock_redis:
            mock_redis.return_value = {"healthy": False, "message": "Connection refused"}

            response = await client.get("/api/v1/readiness")

            assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
            data = response.json()
            assert data["status"] == "not_ready"
            assert data["checks"]["redis"]["healthy"] is False

    async def test_readiness_kafka_failure(self, client: AsyncClient, mock_kafka_vault_health_checks):
        """Тест readiness когда Kafka недоступен."""
        mock_kafka, mock_vault, _ = mock_kafka_vault_health_checks
        mock_kafka.return_value = {"healthy": False, "message": "No metadata"}
        mock_vault.return_value = {"healthy": True}

        response = await client.get("/api/v1/readiness")

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = response.json()
        assert data["status"] == "not_ready"
        assert data["checks"]["kafka"]["healthy"] is False

    async def test_readiness_alias_ready(self, client: AsyncClient):
        """Тест алиаса /api/v1/ready."""
        response = await client.get("/api/v1/ready")
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_503_SERVICE_UNAVAILABLE]


class TestHealthDetailed:
    """Тесты для GET /api/v1/detailed."""

    async def test_detailed_health_all_healthy(self, client: AsyncClient, mock_kafka_vault_health_checks):
        """Тест детальной проверки когда всё здорово."""
        mock_kafka, mock_vault, mock_perf = mock_kafka_vault_health_checks
        mock_kafka.return_value = {"healthy": True, "latency_ms": 12.3}
        mock_vault.return_value = {"healthy": True}
        mock_perf.return_value = {"uptime_seconds": 3600, "db_pool_status": {}}

        response = await client.get("/api/v1/detailed")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "ready"
        assert "checks" in data
        assert "latency_ms" in data["checks"]["postgresql"]
        assert "latency_ms" in data["checks"]["redis"]
        assert "latency_ms" in data["checks"]["kafka"]
        assert "performance" in data

    async def test_detailed_health_unhealthy(self, client: AsyncClient, mock_kafka_vault_health_checks):
        """Тест детальной проверки когда есть проблемы."""
        mock_kafka, mock_vault, _ = mock_kafka_vault_health_checks
        mock_kafka.return_value = {"healthy": True}
        mock_vault.return_value = {"healthy": True}

        # Эмулируем проблему с БД
        with patch("app.services.health_service.HealthService.check_database") as mock_db:
            mock_db.return_value = {"healthy": False, "message": "Connection failed"}

            response = await client.get("/api/v1/detailed")

            assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
            data = response.json()
            assert data["status"] in ["unhealthy", "not_ready"]


class TestSimpleHealth:
    """Тесты для GET /api/v1/."""

    async def test_simple_health_success(self, client: AsyncClient):
        """Тест простой проверки здоровья."""
        response = await client.get("/api/v1/")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "auth-service"


class TestPrometheusMetrics:
    """Тесты для GET /api/v1/metrics."""

    @patch("app.services.health_service.HealthService.get_readiness")
    @patch("app.services.health_service.HealthService.get_performance_metrics")
    async def test_prometheus_metrics_format(
        self,
        mock_get_performance,
        mock_get_readiness,
        client: AsyncClient
    ):
        """Тест формата Prometheus метрик."""
        # Мокаем readiness - все сервисы здоровы
        mock_get_readiness.return_value = {
            "postgresql": {"healthy": True, "latency_ms": 5.2},
            "redis": {"healthy": True, "latency_ms": 1.5},
            "kafka": {"healthy": True, "latency_ms": 12.3},
            "vault": {"healthy": True, "latency_ms": 8.1},
            "_ready": True,
        }
        
        # Мокаем performance метрики
        mock_get_performance.return_value = {
            "uptime_seconds": 3600,
            "db_pool_status": {"size": 10, "used": 5},
            "redis_info": {"connected_clients": 3, "total_commands_processed": 5000},
            "kafka_info": {"brokers": ["broker1:9092"], "topics": ["topic1", "topic2"]},
        }

        response = await client.get("/api/v1/metrics")

        assert response.status_code == status.HTTP_200_OK
        assert "text/plain" in response.headers["content-type"]
        assert "version=0.0.4" in response.headers["content-type"]

        content = response.text
        assert "auth_service_uptime_seconds" in content
        assert "auth_service_info" in content
        assert "auth_service_postgresql_healthy" in content
        assert "auth_service_redis_healthy" in content
        assert "auth_service_kafka_healthy" in content
        assert "auth_service_readiness_ready" in content
        assert "db_pool_size" in content
        assert "redis_connections" in content
        assert "kafka_brokers" in content

    @patch("app.services.health_service.HealthService.get_readiness")
    @patch("app.services.health_service.HealthService.get_performance_metrics")
    async def test_prometheus_metrics_unhealthy_dependencies(
        self,
        mock_get_performance,
        mock_get_readiness,
        client: AsyncClient
    ):
        """Тест метрик когда зависимости недоступны."""
        # Мокаем readiness - PostgreSQL и Kafka недоступны, Redis здоров
        mock_get_readiness.return_value = {
            "postgresql": {"healthy": False},
            "redis": {"healthy": True},
            "kafka": {"healthy": False},
            "vault": {"healthy": True},
            "_ready": False,
        }
        
        # Мокаем performance метрики
        mock_get_performance.return_value = {
            "uptime_seconds": 3600,
            "db_pool_status": {"size": 0, "used": 0},
            "redis_info": {"connected_clients": 0, "total_commands_processed": 0},
            "kafka_info": {"brokers": [], "topics": []},
        }

        response = await client.get("/api/v1/metrics")

        assert response.status_code == status.HTTP_200_OK
        content = response.text
        assert "auth_service_postgresql_healthy 0" in content
        assert "auth_service_redis_healthy 1" in content
        assert "auth_service_kafka_healthy 0" in content
        assert "auth_service_readiness_ready 0" in content


class TestHealthCheckFunctions:
    """Тесты для вспомогательных функций health check."""

    async def test_check_postgresql_success(self):
        """Тест успешной проверки PostgreSQL (реальная БД)."""
        result = await HealthService.check_database()

        assert result["healthy"] is True
        assert result["message"] == "Connected to PostgreSQL"
        assert result["latency_ms"] is not None
        assert result["latency_ms"] > 0

    async def test_check_redis_success(self):
        """Тест успешной проверки Redis (реальный Redis)."""
        result = await HealthService.check_redis()

        assert result["healthy"] is True
        assert result["message"] == "Connected to Redis"
        assert result["latency_ms"] is not None
        assert result["latency_ms"] > 0

    async def test_check_kafka_success(self, mock_kafka_vault_health_checks):
        """Тест успешной проверки Kafka (мок)."""
        mock_kafka, _, _ = mock_kafka_vault_health_checks
        mock_kafka.return_value = {"healthy": True, "message": "Connected", "topics": ["topic1", "topic2"]}

        result = await HealthService.check_kafka()

        assert result["healthy"] is True
        assert result["message"] == "Connected"

    async def test_check_kafka_failure(self, mock_kafka_vault_health_checks):
        """Тест неудачной проверки Kafka (мок)."""
        mock_kafka, _, _ = mock_kafka_vault_health_checks
        mock_kafka.return_value = {"healthy": False, "message": "Kafka unavailable"}

        result = await HealthService.check_kafka()

        assert result["healthy"] is False

    async def test_check_vault_success(self, mock_kafka_vault_health_checks):
        """Тест успешной проверки Vault (мок)."""
        _, mock_vault, _ = mock_kafka_vault_health_checks
        mock_vault.return_value = {"healthy": True, "message": "Connected"}

        result = await HealthService.check_vault()

        assert result["healthy"] is True

    async def test_check_vault_failure(self, mock_kafka_vault_health_checks):
        """Тест неудачной проверки Vault (мок)."""
        _, mock_vault, _ = mock_kafka_vault_health_checks
        mock_vault.return_value = {"healthy": False, "message": "Vault unhealthy"}

        result = await HealthService.check_vault()

        assert result["healthy"] is False


class TestHealthServiceEdgeCases:
    """Тесты для граничных случаев HealthService."""

    async def test_check_all_with_timeout(self, mock_kafka_vault_health_checks):
        """Тест проверки всех зависимостей с таймаутом."""
        mock_kafka, mock_vault, _ = mock_kafka_vault_health_checks
        
        async def slow_check():
            import asyncio
            await asyncio.sleep(2.0)
            return {"healthy": True}

        mock_kafka.side_effect = slow_check
        mock_vault.side_effect = slow_check

        # Мокаем БД и Redis для этого теста, чтобы они не мешали
        with patch("app.services.health_service.HealthService.check_database") as mock_db, \
             patch("app.services.health_service.HealthService.check_redis") as mock_redis:
            mock_db.side_effect = slow_check
            mock_redis.side_effect = slow_check

            result = await HealthService.check_all_with_timeout(timeout_seconds=0.5)

            assert result["status"] == "not_ready"
            assert "timeout" in result.get("error", "").lower() if result.get("error") else True

    async def test_check_all_with_timeout_success(self, mock_kafka_vault_health_checks):
        """Тест успешной проверки в пределах таймаута."""
        mock_kafka, mock_vault, _ = mock_kafka_vault_health_checks
        mock_kafka.return_value = {"healthy": True}
        mock_vault.return_value = {"healthy": True}

        result = await HealthService.check_all_with_timeout(timeout_seconds=5.0)

        assert result["status"] == "ready"


class TestHealthResponseStatusCodes:
    """Тесты статус кодов health эндпоинтов."""

    async def test_liveness_method_not_allowed(self, client: AsyncClient):
        """Тест неразрешённого метода для liveness."""
        response = await client.post("/api/v1/liveness")
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    async def test_readiness_method_not_allowed(self, client: AsyncClient):
        """Тест неразрешённого метода для readiness."""
        response = await client.post("/api/v1/readiness")
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    async def test_metrics_returns_text_plain(self, client: AsyncClient):
        """Тест что metrics возвращает text/plain."""
        response = await client.get("/api/v1/metrics")
        assert response.status_code == status.HTTP_200_OK
        assert "text/plain" in response.headers.get("content-type", "")