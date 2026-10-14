"""
Локальный конфиг для тестов внешних сервисов и интеграций.

Содержит фикстуры для:
- gRPC клиентов и моков
- Health check зависимостей (Kafka, Vault - моки, PostgreSQL и Redis - реальные)
- Внешних сервисов (Kafka, Redis, Vault)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

import app.services.health_service


# ==================== ФИКСТУРЫ ДЛЯ МОКОВ ВНЕШНИХ СЕРВИСОВ ====================

@pytest.fixture(autouse=True)
def mock_vault():
    """
    Lead-решение: изолируем тесты сервисов от Волта,
    не импортируя сам модуль vault_client, которого нет в системе.
    """
    mock = AsyncMock()
    mock.health_check = AsyncMock(return_value=True)
    mock.is_healthy = AsyncMock(return_value=True)
    mock.read_secret = AsyncMock(return_value={"data": {"value": "test_secret"}})
    mock.write_secret = AsyncMock(return_value={"data": {"created": True}})
    mock.delete_secret = AsyncMock(return_value=True)
    mock.close = AsyncMock(return_value=True)

    # Мокаем Волт строго там, где его дергает логика приложения (в хелс-сервисе)
    with patch("app.services.health_service.vault_client", mock):
        yield mock


# ==================== ФИКСТУРЫ ДЛЯ GRPC ТЕСТОВ ====================

@pytest.fixture(autouse=True)
def mock_grpc_channel(monkeypatch):
    """
    Глобальная фикстура, которая мокает grpc.aio.insecure_channel
    для предотвращения реальных gRPC соединений.
    """
    import grpc
    import app.services.grpc_client

    mock_channel = MagicMock()
    mock_channel.return_value = AsyncMock()

    monkeypatch.setattr(grpc.aio, "insecure_channel", mock_channel)
    if hasattr(app.services.grpc_client, "insecure_channel"):
        monkeypatch.setattr(app.services.grpc_client, "insecure_channel", mock_channel)
    monkeypatch.setattr(app.services.grpc_client.grpc.aio, "insecure_channel", mock_channel)

    # Сохраняем ссылку на мок в pytest для использования в тестах
    pytest.global_mock_channel = mock_channel

    return mock_channel


# ==================== ФИКСТУРЫ ДЛЯ HEALTH CHECKS ====================

@pytest.fixture(autouse=True)
def mock_kafka_vault_health_checks():
    """
    Глобальная фикстура, которая мокает только Kafka и Vault.
    PostgreSQL и Redis проверяются реально (без моков).
    
    Используется для изоляции тестов от недоступных сервисов,
    но при этом проверяет реальное состояние БД и Redis.
    """
    with patch("app.services.health_service.HealthService.check_kafka") as mock_kafka, \
         patch("app.services.health_service.HealthService.check_vault") as mock_vault, \
         patch("app.services.health_service.HealthService.get_performance_metrics") as mock_perf:
        
        # По умолчанию Kafka и Vault здоровы (для тестов где они не проверяются)
        mock_kafka.return_value = {"healthy": True, "message": "Connected", "latency_ms": 12.3, "topics": ["topic1"]}
        mock_vault.return_value = {"healthy": True, "message": "Connected", "latency_ms": 8.1}
        
        # Метрики производительности (мок)
        mock_perf.return_value = {
            "uptime_seconds": 3600,
            "db_pool_status": {"size": 20, "used": 5},
            "redis_info": {"connected_clients": 3, "total_commands_processed": 5000},
            "kafka_info": {"brokers": ["broker1:9092"], "topics": ["topic1", "topic2"]},
        }
        
        yield mock_kafka, mock_vault, mock_perf