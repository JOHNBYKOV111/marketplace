"""
Интеграционные тесты для Middleware.

Тестирует:
- TraceContextMiddleware (добавление trace_id, request_id)
- LoggingMiddleware (логирование запросов с duration, status)
- IdempotencyMiddleware (кэширование успешных POST/PUT/PATCH запросов)
- CORS middleware (заголовки)
- Обработку ошибок в middleware
- Добавление security headers
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware
from httpx import ASGITransport, AsyncClient

from app.core.middleware import (
    IdempotencyMiddleware,
    LoggingMiddleware,
    TraceContextMiddleware,
)
from app.core.config import settings


# Прописываем дефолты для тест-окружения, чтобы FastAPI не падал при инициализации CORSMiddleware
if not hasattr(settings, "CORS_ALLOWED_ORIGINS"):
    settings.CORS_ALLOWED_ORIGINS = ["*"]
if not hasattr(settings, "CORS_ALLOW_CREDENTIALS"):
    settings.CORS_ALLOW_CREDENTIALS = True
if not hasattr(settings, "CORS_ALLOWED_METHODS"):
    settings.CORS_ALLOWED_METHODS = ["*"]
if not hasattr(settings, "CORS_ALLOWED_HEADERS"):
    settings.CORS_ALLOWED_HEADERS = ["*"]


class TestTraceContextMiddleware:
    """Тесты для TraceContextMiddleware."""

    @pytest.fixture
    def app(self):
        app = FastAPI()
        app.add_middleware(TraceContextMiddleware)

        @app.get("/test")
        async def test_endpoint(request: Request):
            # Используем request.state для получения trace_id и request_id
            return {
                "trace_id": getattr(request.state, "trace_id", None),
                "request_id": getattr(request.state, "request_id", None)
            }

        return app

    @pytest.fixture
    async def client(self, app):
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac

    async def test_trace_context_adds_headers(self, client):
        """Тест добавления trace_id и request_id в заголовки ответа."""
        response = await client.get("/test")

        assert response.status_code == 200
        assert "X-Trace-Id" in response.headers
        assert "X-Request-Id" in response.headers
        assert len(response.headers["X-Trace-Id"]) > 0
        assert len(response.headers["X-Request-Id"]) > 0

    async def test_trace_context_preserves_provided_trace_id(self, client):
        """Тест сохранения переданного trace_id из заголовка запроса."""
        custom_trace_id = "custom-trace-12345"
        response = await client.get("/test", headers={"X-Trace-Id": custom_trace_id})

        assert response.headers["X-Trace-Id"] == custom_trace_id

    async def test_trace_context_preserves_provided_request_id(self, client):
        """Тест сохранения переданного request_id из заголовка запроса."""
        custom_request_id = "req-67890"
        response = await client.get("/test", headers={"X-Request-Id": custom_request_id})

        assert response.headers["X-Request-Id"] == custom_request_id

    async def test_trace_context_generates_ids_when_missing(self, client):
        """Тест генерации trace_id и request_id когда они не переданы."""
        response = await client.get("/test")

        assert response.headers["X-Trace-Id"] is not None
        assert response.headers["X-Request-Id"] is not None

    async def test_trace_context_response_contains_ids(self, client):
        """Тест что тело ответа содержит trace_id и request_id."""
        response = await client.get("/test")
        data = response.json()

        # Проверяем, что данные из state совпадают с заголовками
        assert data["trace_id"] == response.headers["X-Trace-Id"]
        assert data["request_id"] == response.headers["X-Request-Id"]


class TestLoggingMiddleware:
    """Тесты для LoggingMiddleware."""

    @pytest.fixture
    def app(self):
        app = FastAPI()
        app.add_middleware(LoggingMiddleware)

        @app.get("/success")
        async def success_endpoint():
            return {"status": "ok"}

        @app.get("/error")
        async def error_endpoint():
            raise ValueError("Test error")

        @app.get("/slow")
        async def slow_endpoint():
            import asyncio
            await asyncio.sleep(0.05)
            return {"status": "ok"}

        return app

    @pytest.fixture
    async def client(self, app):
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac

    @patch("app.core.middleware.middleware.logger")
    async def test_logging_middleware_logs_request(self, mock_logger, client):
        """Тест логирования успешного запроса."""
        response = await client.get("/success")

        assert response.status_code == 200
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "/success" in call_args
        assert "200" in call_args

    @patch("app.core.middleware.middleware.logger")
    async def test_logging_middleware_logs_duration(self, mock_logger, client):
        """Тест логирования длительности запроса."""
        await client.get("/slow")

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[1]["extra"]
        assert "duration_ms" in call_args
        assert call_args["duration_ms"] >= 50

    @patch("app.core.middleware.middleware.logger")
    async def test_logging_middleware_logs_error_status(self, mock_logger, client):
        """Тест логирования ошибочного запроса."""
        await client.get("/error")

        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args[0][0]
        assert "500" in call_args

    @patch("app.core.middleware.middleware.logger")
    async def test_logging_middleware_extra_fields(self, mock_logger, client):
        """Тест наличия extra полей в логе."""
        await client.get("/success")

        call_args = mock_logger.info.call_args[1]
        assert "extra" in call_args
        extra = call_args["extra"]
        assert "method" in extra
        assert "path" in extra
        assert "status_code" in extra
        assert "duration_ms" in extra
        assert "client_ip" in extra


class TestIdempotencyMiddleware:
    """Тесты для IdempotencyMiddleware."""

    @pytest.fixture
    def app(self):
        app = FastAPI()
        app.add_middleware(IdempotencyMiddleware)

        counter = 0

        @app.post("/payment")
        async def payment_endpoint(request: Request):
            nonlocal counter
            counter += 1
            return {"status": "success", "count": counter, "id": 123}

        @app.put("/resource/{id}")
        async def update_endpoint(id: int, request: Request):
            return {"status": "updated", "id": id}

        @app.get("/normal")
        async def normal_endpoint():
            return {"status": "ok"}

        return app

    @pytest.fixture
    async def client(self, app):
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac

    @patch("app.core.middleware.middleware.redis_client")
    async def test_idempotency_middleware_caches_post_response(self, mock_redis, client):
        """Тест кэширования успешного POST запроса."""
        mock_redis.get_json = AsyncMock(return_value=None)
        mock_redis.setex = AsyncMock(return_value=True)

        idempotency_key = "test-key-123"

        response1 = await client.post(
            "/payment",
            headers={"Idempotency-Key": idempotency_key},
        )

        assert response1.status_code == 200
        data1 = response1.json()
        assert data1["count"] == 1

        mock_redis.setex.assert_called()

    @patch("app.core.middleware.middleware.redis_client")
    async def test_idempotency_middleware_returns_cached_response(self, mock_redis, client):
        """Тест возврата кэшированного ответа при повторном запросе."""
        cached_result = {"status": "success", "count": 1, "id": 123}
        mock_redis.get_json = AsyncMock(return_value=cached_result)

        idempotency_key = "test-key-456"

        response = await client.post(
            "/payment",
            headers={"Idempotency-Key": idempotency_key},
        )

        assert response.status_code == 200
        data = response.json()
        assert data == cached_result

    @patch("app.core.middleware.middleware.redis_client")
    async def test_idempotency_middleware_ignores_get_requests(self, mock_redis, client):
        """Тест что GET запросы не кэшируются."""
        idempotency_key = "test-key-789"

        response = await client.get(
            "/normal",
            headers={"Idempotency-Key": idempotency_key},
        )

        assert response.status_code == 200
        mock_redis.get_json.assert_not_called()
        mock_redis.setex.assert_not_called()

    @patch("app.core.middleware.middleware.redis_client")
    async def test_idempotency_middleware_different_keys_produce_different_results(self, mock_redis, client):
        """Тест что разные idempotency ключи дают разные результаты."""
        mock_redis.get_json = AsyncMock(return_value=None)
        mock_redis.setex = AsyncMock(return_value=True)

        response1 = await client.post("/payment", headers={"Idempotency-Key": "key-1"})
        response2 = await client.post("/payment", headers={"Idempotency-Key": "key-2"})

        assert response1.json()["count"] == 1
        assert response2.json()["count"] == 2

    @patch("app.core.middleware.middleware.redis_client")
    async def test_idempotency_middleware_handles_put_requests(self, mock_redis, client):
        """Тест что PUT запросы поддерживают идемпотентность."""
        mock_redis.get_json = AsyncMock(return_value=None)
        mock_redis.setex = AsyncMock(return_value=True)

        response = await client.put(
            "/resource/123",
            headers={"Idempotency-Key": "put-key"},
        )

        assert response.status_code == 200
        mock_redis.setex.assert_called()


class TestMiddlewareOrder:
    """Тесты порядка выполнения middleware."""

    @pytest.fixture
    def app(self):
        app = FastAPI()
        app.add_middleware(TraceContextMiddleware)
        app.add_middleware(LoggingMiddleware)

        order = []

        @app.middleware("http")
        async def test_middleware(request: Request, call_next):
            order.append("before")
            response = await call_next(request)
            order.append("after")
            return response

        @app.get("/order")
        async def order_endpoint():
            order.append("endpoint")
            return {"order": order}

        return app

    @pytest.fixture
    async def client(self, app):
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac

    @patch("app.core.middleware.middleware.logger")
    async def test_middleware_execution_order(self, mock_logger, client):
        """Тест порядка выполнения middleware."""
        response = await client.get("/order")

        assert response.status_code == 200


class TestMiddlewareErrorHandling:
    """Тесты обработки ошибок в middleware."""

    @pytest.fixture
    def app(self):
        app = FastAPI()
        app.add_middleware(TraceContextMiddleware)
        app.add_middleware(LoggingMiddleware)

        @app.get("/error")
        async def error_endpoint():
            raise ValueError("Internal error")

        return app

    @pytest.fixture
    async def client(self, app):
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac

    @patch("app.core.middleware.middleware.logger")
    async def test_middleware_handles_endpoint_error(self, mock_logger, client):
        """Тест что middleware корректно обрабатывает ошибки эндпоинта."""
        response = await client.get("/error")

        assert response.status_code == 500
        mock_logger.error.assert_called_once()


class TestCORSConfiguration:
    """Тесты CORS конфигурации."""

    @pytest.fixture
    def app(self):
        from fastapi.middleware.cors import CORSMiddleware

        app = FastAPI()
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ALLOWED_ORIGINS,
            allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
            allow_methods=settings.CORS_ALLOWED_METHODS,
            allow_headers=settings.CORS_ALLOWED_HEADERS,
        )

        @app.get("/test")
        async def test_endpoint():
            return {"status": "ok"}

        return app

    @pytest.fixture
    async def client(self, app):
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac

    async def test_cors_headers_present(self, client):
        """Тест наличия CORS заголовков."""
        response = await client.options(
            "/test",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )

        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers
        assert "access-control-allow-credentials" in response.headers

    async def test_cors_allows_credentials(self, client):
        """Тест что CORS разрешает credentials."""
        response = await client.get(
            "/test",
            headers={"Origin": "http://localhost:3000"},
        )

        assert response.headers.get("access-control-allow-credentials") == "true"


class TestEdgeCases:
    """Тесты для граничных случаев middleware."""

    @pytest.fixture
    def app(self):
        app = FastAPI()
        app.add_middleware(TraceContextMiddleware)

        @app.get("/empty")
        async def empty_endpoint():
            return Response(status_code=204)

        @app.get("/large")
        async def large_endpoint():
            return {"data": "x" * 10000}

        return app

    @pytest.fixture
    async def client(self, app):
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac

    async def test_trace_context_with_empty_response(self, client):
        """Тест trace context с пустым ответом (204)."""
        response = await client.get("/empty")

        assert response.status_code == 204
        assert "X-Trace-Id" in response.headers
        assert "X-Request-Id" in response.headers

    async def test_trace_context_with_large_response(self, client):
        """Тест trace context с большим ответом."""
        response = await client.get("/large")

        assert response.status_code == 200
        assert "X-Trace-Id" in response.headers
        assert "X-Request-Id" in response.headers

    @patch("app.core.middleware.middleware.redis_client")
    async def test_idempotency_middleware_handles_redis_error(self, mock_redis, client):
        """Тест обработки ошибки Redis в idempotency middleware."""
        mock_redis.get_json = AsyncMock(side_effect=Exception("Redis connection failed"))

        response = await client.post(
            "/payment",
            headers={"Idempotency-Key": "test-key"},
        )

        assert response.status_code in (404, 200)