"""
Unit tests for HealthService.

Tests cover:
- check_database (success, failure, latency)
- check_redis (success, failure, latency)
- check_kafka (success, failure, latency, metadata)
- check_vault (success, failure)
- check_all_with_timeout (all healthy, partial failure, timeout)
- get_readiness (ready, not_ready)
- get_detailed_health (includes performance metrics)
- get_performance_metrics (uptime, db pool, redis info, kafka info)
- get_service_uptime
- wait_for_dependencies (success, timeout)
- wait_for_database (success, timeout)
- wait_for_redis (success, timeout)
- Edge cases and error handling
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.health_service import (
    HealthService,
    wait_for_dependencies,
    wait_for_database,
    wait_for_redis,
)


class TestCheckDatabase:
    """Tests for check_database method."""

    @patch("app.services.health_service.db_manager")
    async def test_check_database_success(self, mock_db):
        """Test successful database connection."""
        mock_db.ping = AsyncMock(return_value=True)

        result = await HealthService.check_database()

        assert result["healthy"] is True
        assert "Connected to PostgreSQL" in result["message"]
        assert result["latency_ms"] is not None
        mock_db.ping.assert_called_once()

    @patch("app.services.health_service.db_manager")
    async def test_check_database_not_responding(self, mock_db):
        """Test database not responding."""
        mock_db.ping = AsyncMock(return_value=False)

        result = await HealthService.check_database()

        assert result["healthy"] is False
        assert "not responding" in result["message"]
        assert result["latency_ms"] is not None

    @patch("app.services.health_service.db_manager")
    async def test_check_database_exception(self, mock_db):
        """Test database raises exception."""
        mock_db.ping = AsyncMock(side_effect=Exception("Connection refused"))

        result = await HealthService.check_database()

        assert result["healthy"] is False
        assert "Connection refused" in result["message"]
        assert "error" in result


class TestCheckRedis:
    """Tests for check_redis method."""

    @patch("app.services.health_service.redis_client")
    async def test_check_redis_success(self, mock_redis):
        """Test successful Redis connection."""
        mock_redis.ping = AsyncMock(return_value=True)

        result = await HealthService.check_redis()

        assert result["healthy"] is True
        assert "Connected to Redis" in result["message"]
        assert result["latency_ms"] is not None
        mock_redis.ping.assert_called_once()

    @patch("app.services.health_service.redis_client")
    async def test_check_redis_not_responding(self, mock_redis):
        """Test Redis not responding."""
        mock_redis.ping = AsyncMock(return_value=False)

        result = await HealthService.check_redis()

        assert result["healthy"] is False
        assert "not responding" in result["message"]

    @patch("app.services.health_service.redis_client")
    async def test_check_redis_exception(self, mock_redis):
        """Test Redis raises exception."""
        mock_redis.ping = AsyncMock(side_effect=Exception("Connection refused"))

        result = await HealthService.check_redis()

        assert result["healthy"] is False
        assert "Connection refused" in result["message"]
        assert "error" in result


class TestCheckKafka:
    """Tests for check_kafka method."""

    @patch("app.services.health_service.kafka_producer")
    async def test_check_kafka_success(self, mock_kafka):
        """Test successful Kafka connection with metadata."""
        mock_metadata = {
            "brokers": ["broker1:9092", "broker2:9092"],
            "topics": ["topic1", "topic2", "topic3"],
        }
        mock_kafka.get_metadata = AsyncMock(return_value=mock_metadata)

        result = await HealthService.check_kafka()

        assert result["healthy"] is True
        assert "Connected to Kafka" in result["message"]
        assert result["latency_ms"] is not None
        assert result["brokers"] == mock_metadata["brokers"]
        assert result["topics"] == mock_metadata["topics"]

    @patch("app.services.health_service.kafka_producer")
    async def test_check_kafka_no_metadata(self, mock_kafka):
        """Test Kafka returns no metadata."""
        mock_kafka.get_metadata = AsyncMock(return_value=None)

        result = await HealthService.check_kafka()

        assert result["healthy"] is False
        assert "not responding" in result["message"]

    @patch("app.services.health_service.kafka_producer")
    async def test_check_kafka_exception(self, mock_kafka):
        """Test Kafka raises exception."""
        mock_kafka.get_metadata = AsyncMock(side_effect=Exception("Broker not available"))

        result = await HealthService.check_kafka()

        assert result["healthy"] is False
        assert "Broker not available" in result["message"]
        assert "error" in result


class TestCheckVault:
    """Tests for check_vault method."""

    @patch("app.services.health_service.vault_client")
    async def test_check_vault_success(self, mock_vault):
        """Test successful Vault connection."""
        mock_vault.health_check = AsyncMock(return_value=True)

        result = await HealthService.check_vault()

        assert result["healthy"] is True
        assert "Connected to Vault" in result["message"]
        assert result["latency_ms"] is not None

    @patch("app.services.health_service.vault_client")
    async def test_check_vault_not_healthy(self, mock_vault):
        """Test Vault not healthy."""
        mock_vault.health_check = AsyncMock(return_value=False)

        result = await HealthService.check_vault()

        assert result["healthy"] is False
        assert "not healthy" in result["message"]

    @patch("app.services.health_service.vault_client")
    async def test_check_vault_exception(self, mock_vault):
        """Test Vault raises exception."""
        mock_vault.health_check = AsyncMock(side_effect=Exception("Sealed"))

        result = await HealthService.check_vault()

        assert result["healthy"] is False
        assert "Sealed" in result["message"]
        assert "error" in result


class TestCheckAllWithTimeout:
    """Tests for check_all_with_timeout method."""

    @patch.object(HealthService, "check_database")
    @patch.object(HealthService, "check_redis")
    @patch.object(HealthService, "check_kafka")
    @patch.object(HealthService, "check_vault")
    async def test_all_healthy(self, mock_vault, mock_kafka, mock_redis, mock_db):
        """Test all checks healthy."""
        mock_db.return_value = {"healthy": True, "message": "ok"}
        mock_redis.return_value = {"healthy": True, "message": "ok"}
        mock_kafka.return_value = {"healthy": True, "message": "ok"}
        mock_vault.return_value = {"healthy": True, "message": "ok"}

        result = await HealthService.check_all_with_timeout(timeout_seconds=5.0)

        assert result["status"] == "ready"
        assert result["checks"]["postgresql"]["healthy"] is True
        assert result["checks"]["redis"]["healthy"] is True
        assert result["checks"]["kafka"]["healthy"] is True
        assert result["checks"]["vault"]["healthy"] is True
        assert result["error"] is None

    @patch.object(HealthService, "check_database")
    @patch.object(HealthService, "check_redis")
    @patch.object(HealthService, "check_kafka")
    @patch.object(HealthService, "check_vault")
    async def test_partial_failure(self, mock_vault, mock_kafka, mock_redis, mock_db):
        """Test some checks fail."""
        mock_db.return_value = {"healthy": False, "message": "DB down"}
        mock_redis.return_value = {"healthy": True, "message": "ok"}
        mock_kafka.return_value = {"healthy": True, "message": "ok"}
        mock_vault.return_value = {"healthy": True, "message": "ok"}

        result = await HealthService.check_all_with_timeout(timeout_seconds=5.0)

        assert result["status"] == "not_ready"
        assert result["checks"]["postgresql"]["healthy"] is False
        assert result["error"] is not None

    @patch.object(HealthService, "check_database")
    @patch.object(HealthService, "check_redis")
    @patch.object(HealthService, "check_kafka")
    @patch.object(HealthService, "check_vault")
    async def test_check_exception(self, mock_vault, mock_kafka, mock_redis, mock_db):
        """Test check raises exception."""
        mock_db.side_effect = Exception("Boom")
        mock_redis.return_value = {"healthy": True, "message": "ok"}
        mock_kafka.return_value = {"healthy": True, "message": "ok"}
        mock_vault.return_value = {"healthy": True, "message": "ok"}

        result = await HealthService.check_all_with_timeout(timeout_seconds=5.0)

        assert result["status"] == "not_ready"
        assert result["checks"]["postgresql"]["healthy"] is False

    @patch.object(HealthService, "check_database")
    @patch.object(HealthService, "check_redis")
    @patch.object(HealthService, "check_kafka")
    @patch.object(HealthService, "check_vault")
    async def test_timeout(self, mock_vault, mock_kafka, mock_redis, mock_db):
        """Test timeout handling."""
        async def slow_check():
            await asyncio.sleep(10)
            return {"healthy": True}

        mock_db.side_effect = slow_check
        mock_redis.side_effect = slow_check
        mock_kafka.side_effect = slow_check
        mock_vault.side_effect = slow_check

        result = await HealthService.check_all_with_timeout(timeout_seconds=0.01)

        assert result["status"] == "not_ready"
        assert "timed out" in result["message"].lower()
        assert result["error"] == "Timeout"


class TestGetReadiness:
    """Tests for get_readiness method."""

    @patch.object(HealthService, "check_all_with_timeout")
    async def test_ready(self, mock_check_all):
        """Test readiness when all dependencies ready."""
        mock_check_all.return_value = {"status": "ready", "checks": {}}

        result = await HealthService.get_readiness()

        assert result["_ready"] is True
        assert result["status"] == "ready"
        assert "timestamp" in result
        assert result["service"] == "auth-service"

    @patch.object(HealthService, "check_all_with_timeout")
    async def test_not_ready(self, mock_check_all):
        """Test readiness when not ready."""
        mock_check_all.return_value = {"status": "not_ready", "checks": {}}

        result = await HealthService.get_readiness()

        assert result["_ready"] is False
        assert result["status"] == "not_ready"


class TestGetDetailedHealth:
    """Tests for get_detailed_health method."""

    @patch.object(HealthService, "get_readiness")
    @patch.object(HealthService, "get_performance_metrics")
    async def test_detailed_health(self, mock_perf, mock_readiness):
        """Test detailed health includes all sections."""
        mock_readiness.return_value = {
            "status": "ready",
            "checks": {"postgresql": {"healthy": True}},
            "error": None,
        }
        mock_perf.return_value = {"uptime_seconds": 3600}

        result = await HealthService.get_detailed_health()

        assert result["status"] == "ready"
        assert result["service"] == "auth-service"
        assert "version" in result
        assert "environment" in result
        assert "checks" in result
        assert "performance" in result
        assert result["performance"]["uptime_seconds"] == 3600


class TestGetPerformanceMetrics:
    """Tests for get_performance_metrics method."""

    @patch("app.services.health_service.db_manager")
    @patch("app.services.health_service.redis_client")
    @patch("app.services.health_service.kafka_producer")
    async def test_performance_metrics_success(self, mock_kafka, mock_redis, mock_db):
        """Test successful metrics collection."""
        mock_db.get_pool_status = AsyncMock(return_value={"size": 10, "used": 5})
        mock_redis.info = AsyncMock(return_value={
            "connected_clients": 3,
            "total_connections_received": 1000,
            "total_commands_processed": 5000,
            "used_memory_human": "10M",
            "uptime_in_seconds": 86400,
        })
        mock_kafka.get_metadata = AsyncMock(return_value={
            "brokers": ["b1:9092", "b2:9092"],
            "topics": ["t1", "t2"],
        })

        result = await HealthService.get_performance_metrics()

        assert "uptime_seconds" in result
        assert result["db_pool_status"] == {"size": 10, "used": 5}
        assert result["redis_info"]["connected_clients"] == 3
        assert result["kafka_info"]["brokers"] == ["b1:9092", "b2:9092"]

    @patch("app.services.health_service.db_manager")
    async def test_performance_metrics_db_error(self, mock_db):
        """Test metrics when DB fails."""
        mock_db.get_pool_status = AsyncMock(side_effect=Exception("DB error"))

        with patch("app.services.health_service.redis_client") as mock_redis, \
             patch("app.services.health_service.kafka_producer") as mock_kafka:
            mock_redis.info = AsyncMock(return_value={})
            mock_kafka.get_metadata = AsyncMock(return_value=None)

            result = await HealthService.get_performance_metrics()

        assert "error" in result["db_pool_status"]

    @patch("app.services.health_service.redis_client")
    async def test_performance_metrics_redis_error(self, mock_redis):
        """Test metrics when Redis fails."""
        mock_redis.info = AsyncMock(side_effect=Exception("Redis error"))

        with patch("app.services.health_service.db_manager") as mock_db, \
             patch("app.services.health_service.kafka_producer") as mock_kafka:
            mock_db.get_pool_status = AsyncMock(return_value={})
            mock_kafka.get_metadata = AsyncMock(return_value=None)

            result = await HealthService.get_performance_metrics()

        assert "error" in result["redis_info"]


class TestGetServiceUptime:
    """Tests for get_service_uptime method."""

    async def test_get_service_uptime(self):
        """Test service uptime returns positive value."""
        uptime = await HealthService.get_service_uptime()
        assert uptime > 0
        assert isinstance(uptime, float)


class TestWaitForDependencies:
    """Tests for wait_for_dependencies function."""

    @patch.object(HealthService, "check_all_with_timeout")
    async def test_wait_success_immediately(self, mock_check):
        """Test wait succeeds on first check."""
        mock_check.return_value = {"status": "ready"}

        with patch("asyncio.sleep", AsyncMock()) as mock_sleep:
            result = await wait_for_dependencies(timeout_seconds=5.0, check_interval=0.1)

        assert result is True
        mock_sleep.assert_not_called()

    @patch.object(HealthService, "check_all_with_timeout")
    async def test_wait_success_after_retries(self, mock_check):
        """Test wait succeeds after several retries."""
        mock_check.side_effect = [
            {"status": "not_ready", "checks": {}},
            {"status": "not_ready", "checks": {}},
            {"status": "ready", "checks": {}},
        ]

        with patch("asyncio.sleep", AsyncMock()) as mock_sleep:
            result = await wait_for_dependencies(timeout_seconds=5.0, check_interval=0.1)

        assert result is True
        assert mock_sleep.call_count == 2

    @patch.object(HealthService, "check_all_with_timeout")
    async def test_wait_timeout(self, mock_check):
        """Test wait times out."""
        mock_check.return_value = {"status": "not_ready", "checks": {}}

        with patch("asyncio.sleep", AsyncMock()):
            result = await wait_for_dependencies(timeout_seconds=0.1, check_interval=0.1)

        assert result is False

    @patch.object(HealthService, "check_all_with_timeout")
    async def test_wait_check_exception(self, mock_check):
        """Test wait handles check exceptions gracefully."""
        mock_check.side_effect = [
            Exception("Boom"),
            {"status": "ready", "checks": {}},
        ]

        with patch("asyncio.sleep", AsyncMock()) as mock_sleep:
            result = await wait_for_dependencies(timeout_seconds=5.0, check_interval=0.1)

        assert result is True
        assert mock_sleep.call_count == 1


class TestWaitForDatabase:
    """Tests for wait_for_database function."""

    @patch.object(HealthService, "check_database")
    async def test_wait_database_success(self, mock_check):
        """Test wait for database succeeds."""
        mock_check.return_value = {"healthy": True}

        with patch("asyncio.sleep", AsyncMock()):
            result = await wait_for_database(timeout_seconds=5.0)

        assert result is True

    @patch.object(HealthService, "check_database")
    async def test_wait_database_timeout(self, mock_check):
        """Test wait for database times out."""
        mock_check.return_value = {"healthy": False}

        with patch("asyncio.sleep", AsyncMock()):
            result = await wait_for_database(timeout_seconds=0.1, check_interval=0.1)

        assert result is False


class TestWaitForRedis:
    """Tests for wait_for_redis function."""

    @patch.object(HealthService, "check_redis")
    async def test_wait_redis_success(self, mock_check):
        """Test wait for Redis succeeds."""
        mock_check.return_value = {"healthy": True}

        with patch("asyncio.sleep", AsyncMock()):
            result = await wait_for_redis(timeout_seconds=5.0)

        assert result is True

    @patch.object(HealthService, "check_redis")
    async def test_wait_redis_timeout(self, mock_check):
        """Test wait for Redis times out."""
        mock_check.return_value = {"healthy": False}

        with patch("asyncio.sleep", AsyncMock()):
            result = await wait_for_redis(timeout_seconds=0.1, check_interval=0.1)

        assert result is False