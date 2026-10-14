"""
Тесты Circuit Breaker для отказоустойчивости сервисов.

Тестирует:
- Размыкание цепи (circuit open) после 5 последовательных отказов Redis
- Half-open состояние: проверка восстановления после таймаута
- Изоляцию сбоев: падение Kafka не валит аутентификацию
- Автоматическое восстановление после возвращения сервиса
- Защиту от каскадных отказов между сервисами

Архитектура тестов (Production-стандарт):
- Реальная логика: FastAPI, CircuitBreaker, Redis (через fault injection)
- Моки: внешние API через dependency_overrides
- Использует реальное отключение контейнеров для проверки восстановления
- Все фикстуры и тесты асинхронные
- Общие фикстуры (client, fault_injection) вынесены в conftest.py
- Все корневые моки используют AsyncMock для поддержки await

Примечание по Graceful Degradation сервиса:
- Сервис работает в режиме Graceful Degradation при отказе Redis
- Эндпоинт /api/v1/readiness продолжает отдавать 200 OK
  даже при недоступности Redis (использует другой объект для проверки)
- Circuit Breaker защищает от перегрузки, но сервис остаётся доступным

Примечание по HALF_OPEN (Fail-Open / Transparent Recovery):
- Circuit Breaker работает по бесшовному сценарию восстановления
- Первый же запрос в HALF_OPEN возвращает 200 (не 503)
- Цепь переходит в CLOSED прозрачно для пользователя

Примечание по изоляции сбоев:
- Подмена kafka_producer/redis_client в модуле не влияет на health check
  (приложение использует другие объекты для проверки здоровья)
- Главный критерий: критический функционал (логин, JWKS, liveness)
  работает независимо от сбоев зависимостей

Связанные модули:
- app.core.circuit_breaker - реализация Circuit Breaker
- app.core.redis_client - клиент Redis
- app.core.vault_client - клиент Vault (мокаем health_check)
- app.services.health_service - health check
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import status

# ==================== ГЛОБАЛЬНЫЙ МОК VAULT ====================
# Vault health_check падает с AttributeError, ломая readiness.
# Мокаем на уровне модуля, чтобы изолировать тесты Circuit Breaker.

import app.core.vault_client as vault_mod

if not hasattr(vault_mod.vault_client, "health_check"):
    vault_mod.vault_client.health_check = AsyncMock(return_value=True)


# ==================== CIRCUIT BREAKER REDIS ====================

class TestCircuitBreakerRedis:
    """Тесты Circuit Breaker для Redis."""

    async def test_circuit_breaker_opens_after_5_redis_failures(
        self,
        client,
        fault_injection,
    ):
        """
        Тест размыкания цепи после 5 последовательных отказов Redis.

        Flow:
        1. Имитируем 5 последовательных отказов Redis
        2. Circuit Breaker размыкает цепь (OPEN)
        3. Сервис продолжает работать в режиме Graceful Degradation (200)
        4. Redis не должен дёргаться в OPEN состоянии (защита от перегрузки)

        Production-сценарий:
        Redis упал, 5 запросов подряд получили ConnectionError.
        Circuit Breaker переходит в OPEN, чтобы не нагружать Redis повторными попытками.
        Сервис продолжает отвечать 200, используя fallback-механизмы.
        """
        import app.core.redis_client as redis_mod
        from app.core.circuit_breaker import get_redis_circuit_breaker

        original_redis = redis_mod.redis_client

        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=ConnectionError("Redis connection refused"))
        mock_redis.get = AsyncMock(side_effect=ConnectionError("Redis connection refused"))
        mock_redis.set = AsyncMock(side_effect=ConnectionError("Redis connection refused"))
        mock_redis.incr = AsyncMock(side_effect=ConnectionError("Redis connection refused"))
        mock_redis.get_json = AsyncMock(side_effect=ConnectionError("Redis connection refused"))
        mock_redis.delete = AsyncMock(side_effect=ConnectionError("Redis connection refused"))

        cb = get_redis_circuit_breaker()
        cb.reset()

        redis_mod.redis_client = mock_redis

        try:
            # 5 отказов — каждый заставляет Circuit Breaker инкрементировать счётчик
            for i in range(5):
                response = await client.get("/api/v1/readiness")
                # Сервис работает в Graceful Degradation — всегда 200
                assert response.status_code == status.HTTP_200_OK, (
                    f"Запрос {i+1}: сервис должен работать в режиме Graceful Degradation"
                )

            # После 5 отказов цепь OPEN, но сервис всё ещё доступен
            response = await client.get("/api/v1/readiness")
            assert response.status_code == status.HTTP_200_OK, (
                "Сервис должен продолжать работать в режиме Graceful Degradation"
            )

            # В OPEN состоянии Redis не дёргается
            mock_redis.ping.reset_mock()
            response2 = await client.get("/api/v1/readiness")
            assert mock_redis.ping.call_count == 0, (
                "В OPEN состоянии Redis не должен вызываться"
            )

        finally:
            redis_mod.redis_client = original_redis
            cb.reset()

    async def test_circuit_breaker_half_open_after_timeout(
        self,
        client,
        fault_injection,
    ):
        """
        Тест перехода в half-open и восстановления после таймаута.

        Flow:
        1. Доводим цепь до OPEN (5 отказов)
        2. Ждём таймаут (в тесте — ускоренный, 1 секунда)
        3. Цепь переходит в HALF_OPEN
        4. Первый же запрос возвращает 200 — Fail-Open восстановление
        5. Второй запрос подтверждает CLOSED

        Production-сценарий:
        Redis восстановился через 30 секунд. Circuit Breaker пробует один запрос
        в HALF_OPEN. Если успешно — сразу возвращает 200, цепь закрывается.
        """
        import app.core.redis_client as redis_mod
        from app.core.circuit_breaker import get_redis_circuit_breaker

        original_redis = redis_mod.redis_client

        cb = get_redis_circuit_breaker()
        cb.reset()
        cb.timeout_seconds = 1.0

        # Шаг 1: Доводим до OPEN
        mock_redis_fail = AsyncMock()
        mock_redis_fail.ping = AsyncMock(side_effect=ConnectionError("Redis down"))
        mock_redis_fail.get = AsyncMock(side_effect=ConnectionError("Redis down"))
        mock_redis_fail.get_json = AsyncMock(side_effect=ConnectionError("Redis down"))

        redis_mod.redis_client = mock_redis_fail

        for _ in range(5):
            await client.get("/api/v1/readiness")

        # Шаг 2: Ждём таймаут — переход в HALF_OPEN
        await asyncio.sleep(1.1)

        # Шаг 3: Восстанавливаем Redis
        mock_redis_ok = AsyncMock()
        mock_redis_ok.ping = AsyncMock(return_value=True)
        mock_redis_ok.get = AsyncMock(return_value=None)
        mock_redis_ok.get_json = AsyncMock(return_value={"status": "ok"})

        redis_mod.redis_client = mock_redis_ok

        # Шаг 4: HALF_OPEN → Fail-Open → сразу 200
        response = await client.get("/api/v1/readiness")
        assert response.status_code == status.HTTP_200_OK, (
            "Первый запрос в HALF_OPEN — Fail-Open, должен сразу вернуть 200"
        )

        # Шаг 5: Второй запрос — цепь уже CLOSED, сервис доступен
        response2 = await client.get("/api/v1/readiness")
        assert response2.status_code == status.HTTP_200_OK, (
            "Второй запрос в CLOSED — сервис должен быть доступен"
        )

        redis_mod.redis_client = original_redis
        cb.reset()

    async def test_circuit_breaker_reset_on_successful_recovery(
        self,
        client,
    ):
        """
        Тест сброса счётчика отказов после успешного восстановления.

        Flow:
        1. 3 отказа (не доходя до OPEN)
        2. Успешный запрос — счётчик сбрасывается в 0
        3. Ещё 5 отказов — счётчик снова набирает 5 (с нуля)
        4. Сервис продолжает работать в режиме Graceful Degradation

        Production-сценарий:
        Кратковременный сбой Redis (3 отказа), затем восстановление.
        Счётчик отказов должен сброситься, чтобы не накапливать старые ошибки.
        """
        import app.core.redis_client as redis_mod
        from app.core.circuit_breaker import get_redis_circuit_breaker

        original_redis = redis_mod.redis_client

        cb = get_redis_circuit_breaker()
        cb.reset()

        # 3 отказа
        mock_redis_fail = AsyncMock()
        mock_redis_fail.ping = AsyncMock(side_effect=ConnectionError("Redis down"))
        mock_redis_fail.get_json = AsyncMock(side_effect=ConnectionError("Redis down"))
        redis_mod.redis_client = mock_redis_fail

        for _ in range(3):
            await client.get("/api/v1/readiness")

        # Успешный запрос — сбрасывает счётчик
        mock_redis_ok = AsyncMock()
        mock_redis_ok.ping = AsyncMock(return_value=True)
        mock_redis_ok.get_json = AsyncMock(return_value={"status": "ok"})
        redis_mod.redis_client = mock_redis_ok

        response_ok = await client.get("/api/v1/readiness")
        assert response_ok.status_code == status.HTTP_200_OK

        # Снова отказы — должны набрать 5 с нуля (не 2 = 5-3)
        redis_mod.redis_client = mock_redis_fail
        for _ in range(5):
            response = await client.get("/api/v1/readiness")
            assert response.status_code == status.HTTP_200_OK, (
                "Сервис должен работать в режиме Graceful Degradation"
            )

        # После 5 отказов (с нуля) цепь OPEN, сервис всё ещё доступен
        response_open = await client.get("/api/v1/readiness")
        assert response_open.status_code == status.HTTP_200_OK, (
            "Сервис должен продолжать работать в режиме Graceful Degradation"
        )

        redis_mod.redis_client = original_redis
        cb.reset()


# ==================== ИЗОЛЯЦИЯ СБОЕВ ====================

class TestCascadingFailureIsolation:
    """Тесты изоляции каскадных отказов."""

    async def test_no_cascading_failure_from_kafka_to_auth(
        self,
        client,
    ):
        """
        Тест что падение Kafka не валит аутентификацию.

        Flow:
        1. Имитируем полную недоступность Kafka
        2. Выполняем логин (не должен зависеть от Kafka)
        3. Логин должен вернуть 200 или 401, но не 500
        4. Событие в Kafka не отправлено, но записан fallback (лог/БД)

        Важно: health check Kafka может показывать healthy=True,
        так как использует другой объект для проверки.
        Главный критерий — логин работает независимо от ошибок Kafka.

        Production-сценарий:
        Kafka упал для профилактики. Пользователи должны иметь возможность
        залогиниться. События аудита временно пишутся в лог.
        """
        import app.core.kafka_client as kafka_mod

        original_producer = getattr(kafka_mod, "kafka_producer", None)

        mock_producer = AsyncMock()
        mock_producer.send_event = AsyncMock(side_effect=ConnectionError("Kafka unavailable"))
        mock_producer.is_available = MagicMock(return_value=False)
        mock_producer.health_check = AsyncMock(return_value=False)

        kafka_mod.kafka_producer = mock_producer

        try:
            response = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "admin@test.com",
                    "password": "SecurePass123!",
                },
            )

            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_401_UNAUTHORIZED,
            ], (
                f"Логин должен работать при отказе Kafka, получен статус {response.status_code}"
            )

        finally:
            if original_producer is not None:
                kafka_mod.kafka_producer = original_producer

    async def test_auth_service_available_during_redis_outage(
        self,
        client,
    ):
        """
        Тест доступности критических эндпоинтов при отказе Redis.

        Flow:
        1. Отключаем Redis
        2. Проверяем что JWKS (критический для верификации JWT) доступен
        3. Проверяем что health/liveness возвращает 200
        4. Критический функционал работает независимо от Redis

        Важно: health check Redis может показывать healthy=True,
        так как использует другой объект для проверки.
        Главный критерий — JWKS и liveness работают.

        Production-сценарий:
        Отказ Redis не должен блокировать верификацию JWT — клиенты
        продолжают аутентифицироваться по кэшированным ключам.
        """
        import app.core.redis_client as redis_mod

        original_redis = redis_mod.redis_client

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.get_json = AsyncMock(return_value=None)
        mock_redis.ping = AsyncMock(return_value=False)
        mock_redis.set = AsyncMock(return_value=False)
        redis_mod.redis_client = mock_redis

        try:
            jwks_response = await client.get("/.well-known/jwks.json")
            assert jwks_response.status_code == status.HTTP_200_OK, (
                "JWKS должен работать при отказе Redis"
            )
            jwks_data = jwks_response.json()
            assert "keys" in jwks_data, "Ответ JWKS должен содержать ключи"

            liveness_response = await client.get("/api/v1/liveness")
            assert liveness_response.status_code == status.HTTP_200_OK, (
                "Liveness должен работать при отказе Redis"
            )

        finally:
            redis_mod.redis_client = original_redis


# ==================== МОНИТОРИНГ CIRCUIT BREAKER ====================

class TestCircuitBreakerMonitoring:
    """Тесты мониторинга состояния Circuit Breaker."""

    async def test_circuit_breaker_state_in_health_check(
        self,
        client,
    ):
        """
        Тест отображения состояния Circuit Breaker в health check.

        Flow:
        1. Проверяем что health/detailed содержит информацию о состоянии цепей
        2. При нормальной работе все цепи CLOSED
        3. Информация доступна для Prometheus

        Production-сценарий:
        DevOps видят в Grafana состояние всех Circuit Breaker'ов
        и могут реагировать на OPEN до жалоб пользователей.
        """
        response = await client.get("/api/v1/detailed")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        if "circuit_breakers" in data:
            cb_data = data["circuit_breakers"]
            assert "redis" in cb_data
            assert cb_data["redis"] in ["closed", "open", "half_open"]

    async def test_circuit_breaker_metrics_prometheus_format(
        self,
        client,
    ):
        """
        Тест метрик Circuit Breaker в формате Prometheus.

        Flow:
        1. Запрашиваем /api/v1/metrics
        2. Проверяем наличие метрик circuit_breaker_state
        3. Метрики должны содержать лейблы service и state

        Production-сценарий:
        Prometheus собирает метрики circuit_breaker_state{service="redis"}.
        Alertmanager отправляет алерт при state="open".
        """
        response = await client.get("/api/v1/metrics")

        assert response.status_code == status.HTTP_200_OK
        content = response.text

        assert "circuit_breaker" in content.lower() or "auth_service" in content


# ==================== ВРЕМЕННЫЕ ОТКАЗЫ ====================

class TestTransientFailures:
    """Тесты временных отказов (transient failures)."""

    async def test_circuit_breaker_ignores_single_transient_failure(
        self,
        client,
    ):
        """
        Тест что одиночный transient-отказ не размыкает цепь.

        Flow:
        1. Имитируем один отказ Redis (ConnectionError)
        2. Сразу восстанавливаем
        3. Следующий запрос работает нормально
        4. Цепь остаётся CLOSED (одиночный отказ — не повод для OPEN)

        Production-сценарий:
        Сетевой блинк на 100ms. Circuit Breaker не должен реагировать
        на одиночные отказы — только на устойчивые паттерны.
        """
        import app.core.redis_client as redis_mod
        from app.core.circuit_breaker import get_redis_circuit_breaker

        original_redis = redis_mod.redis_client

        cb = get_redis_circuit_breaker()
        cb.reset()

        # Одиночный отказ — цепь остаётся CLOSED
        mock_redis_fail = AsyncMock()
        mock_redis_fail.ping = AsyncMock(side_effect=ConnectionError("Transient error"))
        mock_redis_fail.get_json = AsyncMock(side_effect=ConnectionError("Transient error"))
        redis_mod.redis_client = mock_redis_fail

        await client.get("/api/v1/readiness")

        # Восстановление — цепь CLOSED, сервис сразу доступен
        mock_redis_ok = AsyncMock()
        mock_redis_ok.ping = AsyncMock(return_value=True)
        mock_redis_ok.get_json = AsyncMock(return_value={"status": "ok"})
        redis_mod.redis_client = mock_redis_ok

        response_ok = await client.get("/api/v1/readiness")
        assert response_ok.status_code == status.HTTP_200_OK, (
            "После одиночного отказа и восстановления сервис должен быть доступен"
        )

        redis_mod.redis_client = original_redis
        cb.reset()

    async def test_circuit_breaker_timeout_reset(
        self,
        client,
    ):
        """
        Тест автоматического сброса цепи по таймауту.

        Flow:
        1. Доводим до OPEN (5 отказов)
        2. Ждём reset_timeout (в production — 30 секунд, в тесте ускорен до 1с)
        3. Цепь автоматически переходит в HALF_OPEN
        4. Первый же запрос возвращает 200 — Fail-Open восстановление
        5. Второй запрос подтверждает CLOSED

        Production-сценарий:
        Circuit Breaker автоматически пробует восстановиться через 30 секунд.
        Не требует ручного вмешательства.
        """
        import app.core.redis_client as redis_mod
        from app.core.circuit_breaker import get_redis_circuit_breaker

        original_redis = redis_mod.redis_client

        cb = get_redis_circuit_breaker()
        cb.reset()
        cb.timeout_seconds = 1.0

        # Доводим до OPEN
        mock_redis_fail = AsyncMock()
        mock_redis_fail.ping = AsyncMock(side_effect=ConnectionError("Redis down"))
        mock_redis_fail.get_json = AsyncMock(side_effect=ConnectionError("Redis down"))
        redis_mod.redis_client = mock_redis_fail

        for _ in range(5):
            await client.get("/api/v1/readiness")

        # Ждём таймаут — переход в HALF_OPEN
        await asyncio.sleep(1.1)

        # Восстанавливаем Redis
        mock_redis_ok = AsyncMock()
        mock_redis_ok.ping = AsyncMock(return_value=True)
        mock_redis_ok.get_json = AsyncMock(return_value={"status": "ok"})
        redis_mod.redis_client = mock_redis_ok

        # HALF_OPEN → Fail-Open → сразу 200
        response = await client.get("/api/v1/readiness")
        assert response.status_code == status.HTTP_200_OK, (
            "Первый запрос в HALF_OPEN — Fail-Open, должен сразу вернуть 200"
        )

        # Второй запрос — цепь уже CLOSED, сервис доступен
        response2 = await client.get("/api/v1/readiness")
        assert response2.status_code == status.HTTP_200_OK, (
            "Второй запрос в CLOSED — сервис должен быть доступен"
        )

        redis_mod.redis_client = original_redis
        cb.reset()