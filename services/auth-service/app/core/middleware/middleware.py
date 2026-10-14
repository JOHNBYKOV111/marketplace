"""
Middleware для логирования, трассировки и идемпотентности.

Обеспечивает:
- TraceContextMiddleware: добавление trace_id и request_id в заголовки запросов/ответов
- LoggingMiddleware: логирование всех HTTP запросов с метриками
- IdempotencyMiddleware: кэширование идемпотентных запросов (POST, PUT, PATCH)
"""

import json
import time
import uuid
from typing import Optional, Dict, Any, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.logging import get_logger
from app.core.redis_client import redis_client

logger = get_logger(__name__)


class TraceContextMiddleware(BaseHTTPMiddleware):
    """Добавление trace_id и request_id в запросы/ответы."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        trace_id = request.headers.get("X-Trace-Id") or str(uuid.uuid4())
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())[:8]

        request.state.trace_id = trace_id
        request.state.request_id = request_id

        response = await call_next(request)

        response.headers["X-Trace-Id"] = trace_id
        response.headers["X-Request-Id"] = request_id
        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """Логирование HTTP запросов с метриками."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()

        client_ip = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()

        trace_id = getattr(request.state, "trace_id", None)
        request_id = getattr(request.state, "request_id", None)

        try:
            response = await call_next(request)
            duration_ms = (time.time() - start_time) * 1000

            logger.info(
                f"{request.method} {request.url.path} {response.status_code}",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": round(duration_ms, 2),
                    "client_ip": client_ip,
                    "trace_id": trace_id,
                    "request_id": request_id,
                },
            )
            return response

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000

            logger.error(
                f"{request.method} {request.url.path} 500",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": 500,
                    "duration_ms": round(duration_ms, 2),
                    "client_ip": client_ip,
                    "trace_id": trace_id,
                    "request_id": request_id,
                    "error": str(e),
                },
                exc_info=True,
            )
            raise


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """Кэширование идемпотентных запросов (POST, PUT, PATCH)."""

    IDEMPOTENT_METHODS = {"POST", "PUT", "PATCH"}
    CACHE_TTL = 86400

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method not in self.IDEMPOTENT_METHODS:
            return await call_next(request)

        idempotency_key = request.headers.get("Idempotency-Key")
        if not idempotency_key:
            return await call_next(request)

        cache_key = f"idempotency:{idempotency_key}"

        try:
            cached_response = await redis_client.get_json(cache_key)
            if cached_response:
                logger.debug(f"Idempotency cache hit: {cache_key}")
                return Response(
                    content=json.dumps(cached_response["body"]),
                    status_code=cached_response["status_code"],
                    headers=cached_response["headers"],
                    media_type="application/json",
                )

            response = await call_next(request)

            if 200 <= response.status_code < 300:
                body = b""
                async for chunk in response.body_iterator:
                    body += chunk

                response_body = json.loads(body) if body else None

                cache_data = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response_body,
                }
                await redis_client.setex(cache_key, self.CACHE_TTL, cache_data)
                logger.debug(f"Idempotency cached: {cache_key}")

                return Response(
                    content=body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type="application/json",
                )

            return response

        except Exception as e:
            logger.warning(f"Idempotency middleware error: {e}")
            return await call_next(request)