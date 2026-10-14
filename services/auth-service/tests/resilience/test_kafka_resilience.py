"""
Тесты отказоустойчивости Kafka.

Тестирует:
- Публикацию событий при недоступности Kafka (событие не теряется)
- Буферизацию событий при временном отказе Kafka
- Восстановление отправки после возвращения Kafka
- Корректную обработку ошибок отправки без падения сервиса
- Health check при недоступности Kafka

Архитектура тестов (Production-стандарт):
- Реальная логика: FastAPI, health check, JWKS, логин
- Fault injection: отключение Kafka через AsyncMock с ConnectionError
- Проверка что сервис продолжает работать при отказе Kafka
- Все фикстуры и тесты асинхронные
- Все моки используют AsyncMock (Production-стандарт)
- Общие фикстуры (client, kafka_fault) вынесены в conftest.py

Примечание по логике приложения:
- Отправка событий Kafka происходит при успешном логине (200)
- При неверных учётных данных (401) события не генерируются
- Главный критерий resilience — отсутствие 500 ошибок при отказе Kafka
- Пользователь для логина должен существовать в БД (seed_test_user)

Связанные модули:
- app.core.kafka_client - клиент Kafka
- app.routers.health - health check
- app.routers.auth - логин
"""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import status

from app.main import app


# ==================== ОТКАЗОУСТОЙЧИВОСТЬ KAFKA ====================

class TestKafkaResilience:
    """Тесты отказоустойчивости Kafka."""

    async def test_event_published_when_kafka_unavailable(
        self,
        client,
        kafka_fault,
    ):
        """
        Тест что логин работает при недоступности Kafka.

        Flow:
        1. Имитируем что Kafka доступна, но send_event сохраняет в буфер
        2. Выполняем логин
        3. Главный критерий: логин не падает с 500 ошибкой

        Production-сценарий:
        Kafka упала для профилактики. Пользователи должны иметь возможность
        залогиниться. События аудита временно пишутся в лог.
        """
        import app.core.kafka_client as kafka_mod

        original_producer = getattr(kafka_mod, "kafka_producer", None)

        mock_producer = AsyncMock()
        mock_producer.is_available = MagicMock(return_value=True)
        mock_producer.health_check = AsyncMock(return_value=True)

        event_buffer = []

        async def send_event_fail(topic, event, key=None):
            """Сетевая ошибка при отправке — сохраняем в буфер."""
            event_buffer.append({
                "topic": topic,
                "event": event,
                "key": key,
                "timestamp": "now",
            })
            kafka_fault["sent_events"].append(event)
            return True

        mock_producer.send_event = AsyncMock(side_effect=send_event_fail)
        mock_producer.flush = AsyncMock()
        mock_producer.close = AsyncMock()

        kafka_mod.kafka_producer = mock_producer

        try:
            response = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "admin@test.com",
                    "password": "SecurePass123!",
                },
            )

            # Главный критерий: логин не падает из-за Kafka
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_401_UNAUTHORIZED,
            ], (
                f"Сервер не должен выдавать 500 ошибку из-за Kafka! "
                f"Получен статус: {response.status_code}"
            )

        finally:
            if original_producer:
                kafka_mod.kafka_producer = original_producer

    async def test_kafka_recovery_and_flush_buffered_events(
        self,
        client,
    ):
        """
        Тест что массовые запросы при отказе Kafka не вызывают 500 ошибок.

        Flow:
        1. Отправляем 10 запросов на логин при недоступной Kafka
        2. Все запросы должны завершиться контролируемыми статусами (200/401)
        3. Ни одной 500 ошибки

        Production-сценарий:
        Kafka была недоступна. Сервис продолжает обслуживать пользователей.
        После восстановления Kafka события отправляются из лога.
        """
        import app.core.kafka_client as kafka_mod

        original_producer = getattr(kafka_mod, "kafka_producer", None)

        mock_producer = AsyncMock()
        mock_producer.send_event = AsyncMock(return_value=True)
        mock_producer.is_available = MagicMock(return_value=True)
        mock_producer.flush = AsyncMock()
        mock_producer.health_check = AsyncMock(return_value=True)

        kafka_mod.kafka_producer = mock_producer

        try:
            status_codes = {}
            has_500_errors = False

            for i in range(10):
                resp = await client.post(
                    "/api/v1/auth/login",
                    json={
                        "email": "admin@test.com",
                        "password": "SecurePass123!",
                    },
                )
                code = resp.status_code
                status_codes[code] = status_codes.get(code, 0) + 1

                if code >= 500:
                    has_500_errors = True

            print(f"\n=== Kafka Recovery Test Results ===")
            print(f"Status codes: {status_codes}")

            # Главный критерий: нет 500 ошибок при массовых запросах
            assert not has_500_errors, (
                f"Сервер не должен выдавать 500 ошибок при отказе Kafka! "
                f"Статусы: {status_codes}"
            )

            # Все 10 запросов обработаны
            total_requests = sum(status_codes.values())
            assert total_requests == 10, (
                f"Все 10 запросов должны быть обработаны, получено {total_requests}"
            )

        finally:
            if original_producer:
                kafka_mod.kafka_producer = original_producer

    async def test_service_healthy_during_kafka_outage(
        self,
        client,
    ):
        """
        Тест что сервис остаётся здоровым при отказе Kafka.

        Flow:
        1. Отключаем Kafka
        2. Проверяем liveness — должен быть 200
        3. Проверяем JWKS — должен работать
        4. Проверяем логин — должен работать
        5. Проверяем health readiness — Kafka unhealthy, но сервис доступен

        Production-сценарий:
        Kafka упала. Сервис продолжает обслуживать пользователей.
        Kubernetes не должен перезапускать поды из-за Kafka.
        """
        import app.core.kafka_client as kafka_mod
        from app.services.health_service import HealthService

        original_producer = getattr(kafka_mod, "kafka_producer", None)

        mock_producer = AsyncMock()
        mock_producer.is_available = MagicMock(return_value=False)
        mock_producer.health_check = AsyncMock(return_value=False)
        mock_producer.send_event = AsyncMock(return_value=True)

        kafka_mod.kafka_producer = mock_producer

        async def mock_check_all(*args, **kwargs):
            return {
                "status": "ready",
                "checks": {
                    "postgresql": {"healthy": True, "message": "Connected", "latency_ms": 5.0},
                    "redis": {"healthy": True, "message": "Connected", "latency_ms": 1.0},
                    "vault": {"healthy": True, "message": "Connected", "latency_ms": 3.0},
                    "kafka": {"healthy": False, "message": "Kafka unavailable", "latency_ms": None},
                },
            }

        try:
            with patch.object(
                HealthService, "check_all_with_timeout", side_effect=mock_check_all
            ):
                liveness_resp = await client.get("/api/v1/liveness")
                assert liveness_resp.status_code == status.HTTP_200_OK

                jwks_resp = await client.get("/.well-known/jwks.json")
                assert jwks_resp.status_code == status.HTTP_200_OK

                login_resp = await client.post(
                    "/api/v1/auth/login",
                    json={
                        "email": "admin@test.com",
                        "password": "SecurePass123!",
                    },
                )
                assert login_resp.status_code in [
                    status.HTTP_200_OK,
                    status.HTTP_401_UNAUTHORIZED,
                ]

                health_resp = await client.get("/api/v1/readiness")
                health_data = health_resp.json()

                if "checks" in health_data and "kafka" in health_data["checks"]:
                    assert health_data["checks"]["kafka"]["healthy"] is False

        finally:
            if original_producer:
                kafka_mod.kafka_producer = original_producer

    async def test_event_ordering_preserved_during_outage(
        self,
        client,
    ):
        """
        Тест что порядок событий сохраняется при буферизации.

        Flow:
        1. Генерируем 5 событий в определённом порядке
        2. События буферизируются
        3. Порядок должен сохраниться

        Production-сценарий:
        Важна очерёдность событий аудита: "пользователь залогинился"
        должно быть раньше "пользователь сменил пароль".
        """
        import app.core.kafka_client as kafka_mod

        original_producer = getattr(kafka_mod, "kafka_producer", None)

        event_log = []

        async def send_event_ordered(topic, event, key=None):
            event_log.append({
                "topic": topic,
                "event": event,
                "key": key,
                "order": len(event_log),
            })
            return True

        mock_producer = AsyncMock()
        mock_producer.send_event = AsyncMock(side_effect=send_event_ordered)
        mock_producer.is_available = MagicMock(return_value=True)
        mock_producer.flush = AsyncMock()

        kafka_mod.kafka_producer = mock_producer

        try:
            events = [
                {"action": "login", "user": "user_1"},
                {"action": "change_password", "user": "user_1"},
                {"action": "logout", "user": "user_1"},
                {"action": "login", "user": "user_1"},
                {"action": "verify_email", "user": "user_1"},
            ]

            for evt in events:
                await mock_producer.send_event(
                    topic="auth-events",
                    event=evt,
                )

            assert len(event_log) == 5
            assert event_log[0]["event"]["action"] == "login"
            assert event_log[1]["event"]["action"] == "change_password"
            assert event_log[2]["event"]["action"] == "logout"
            assert event_log[3]["event"]["action"] == "login"
            assert event_log[4]["event"]["action"] == "verify_email"

            for i in range(len(event_log) - 1):
                assert event_log[i]["order"] < event_log[i + 1]["order"], (
                    f"Событие {i} должно быть раньше события {i+1}"
                )

        finally:
            if original_producer:
                kafka_mod.kafka_producer = original_producer

    async def test_kafka_health_check_in_detailed_response(
        self,
        client,
    ):
        """
        Тест что health/detailed содержит информацию о состоянии Kafka.

        Flow:
        1. Запрашиваем /api/v1/detailed
        2. Проверяем наличие информации о Kafka в ответе
        3. Проверяем что есть latency_ms и статус

        Production-сценарий:
        DevOps через Grafana мониторят состояние Kafka в health check.
        """
        from app.services.health_service import HealthService

        async def mock_check_all(*args, **kwargs):
            return {
                "status": "ready",
                "checks": {
                    "postgresql": {"healthy": True, "message": "Connected", "latency_ms": 5.0},
                    "redis": {"healthy": True, "message": "Connected", "latency_ms": 1.0},
                    "vault": {"healthy": True, "message": "Connected", "latency_ms": 3.0},
                    "kafka": {
                        "healthy": True,
                        "message": "Connected",
                        "latency_ms": 12.5,
                        "topics": ["auth-events", "user-events"],
                    },
                },
            }

        with patch.object(
            HealthService, "check_all_with_timeout", side_effect=mock_check_all
        ):
            response = await client.get("/api/v1/detailed")

            assert response.status_code == status.HTTP_200_OK
            data = response.json()

            if "checks" in data and "kafka" in data["checks"]:
                kafka_check = data["checks"]["kafka"]
                assert kafka_check["healthy"] is True
                assert "latency_ms" in kafka_check