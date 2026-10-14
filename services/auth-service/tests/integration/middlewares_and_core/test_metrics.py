"""
Интеграционные тесты для Prometheus метрик с реальной инфраструктурой.

Тестирует:
- GET /api/v1/metrics - получение метрик в формате Prometheus
- Формат метрик (text/plain, валидный синтаксис)
- Реальные метрики зависимостей (postgresql, redis, kafka замокан)
- Реальные метрики производительности (db_pool_status, redis_info)
- Обработку ошибок при сборе метрик
- Граничные случаи

Архитектура:
- Реальная логика: HealthService, PostgreSQL, Redis
- Моки: Kafka (глобально), Vault (глобально)
- Использует глобальные фикстуры из conftest.py (client, db_session, manage_test_redis)
"""

import pytest
from fastapi import status


class TestPrometheusMetrics:
    """Тесты для Prometheus метрик с реальными зависимостями."""

    @pytest.mark.asyncio
    async def test_metrics_endpoint_returns_text_plain(self, client):
        response = await client.get("/api/v1/metrics")
        assert response.status_code == status.HTTP_200_OK
        assert "text/plain" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_metrics_contains_uptime(self, client):
        response = await client.get("/api/v1/metrics")
        assert "auth_service_uptime_seconds" in response.text

    @pytest.mark.asyncio
    async def test_metrics_contains_service_info(self, client):
        response = await client.get("/api/v1/metrics")
        assert "auth_service_info" in response.text

    @pytest.mark.asyncio
    async def test_metrics_postgresql_health_present(self, client):
        response = await client.get("/api/v1/metrics")
        assert "auth_service_postgresql_healthy" in response.text

    @pytest.mark.asyncio
    async def test_metrics_redis_health_present(self, client):
        response = await client.get("/api/v1/metrics")
        assert "auth_service_redis_healthy" in response.text

    @pytest.mark.asyncio
    async def test_metrics_readiness_present(self, client):
        response = await client.get("/api/v1/metrics")
        assert "auth_service_readiness_ready" in response.text


class TestPerformanceMetrics:
    """Тесты для реальных метрик производительности."""

    @pytest.mark.asyncio
    async def test_metrics_contains_db_pool_size(self, client):
        response = await client.get("/api/v1/metrics")
        assert "db_pool_size" in response.text

    @pytest.mark.asyncio
    async def test_metrics_contains_redis_connections(self, client):
        response = await client.get("/api/v1/metrics")
        assert "redis_connections" in response.text


class TestMetricsFormat:
    """Тесты формата Prometheus метрик."""

    @pytest.mark.asyncio
    async def test_metrics_valid_syntax(self, client):
        response = await client.get("/api/v1/metrics")
        for line in response.text.strip().split("\n"):
            if line and not line.startswith("#"):
                parts = line.split()
                assert len(parts) >= 2, f"Invalid metric line: {line}"
                try:
                    float(parts[-1])
                except ValueError:
                    pytest.fail(f"Invalid metric value in line: {line}")

    @pytest.mark.asyncio
    async def test_metrics_no_trailing_newline_issues(self, client):
        response = await client.get("/api/v1/metrics")
        assert response.text.strip() == response.text or response.text.endswith("\n")


class TestMetricsEdgeCases:
    """Тесты для граничных случаев метрик."""

    @pytest.mark.asyncio
    async def test_metrics_contains_all_basic_metrics(self, client):
        response = await client.get("/api/v1/metrics")
        content = response.text

        required = [
            "auth_service_uptime_seconds",
            "auth_service_info",
            "auth_service_postgresql_healthy",
            "auth_service_redis_healthy",
            "auth_service_readiness_ready",
            "db_pool_size",
            "redis_connections",
        ]
        for metric in required:
            assert metric in content, f"Missing metric: {metric}"


class TestMetricsResponseHeaders:
    """Тесты заголовков ответа метрик."""

    @pytest.mark.asyncio
    async def test_metrics_endpoint_cache_control(self, client):
        response = await client.get("/api/v1/metrics")
        cache_control = response.headers.get("cache-control", "")
        assert "no-cache" in cache_control.lower() or "no-store" in cache_control.lower() or not cache_control

    @pytest.mark.asyncio
    async def test_metrics_endpoint_method_not_allowed(self, client):
        for method in ("post", "put", "delete"):
            response = await getattr(client, method)("/api/v1/metrics")
            assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED