"""
Инфраструктурный слой ASGI-мидлвари приложения.
Реализует высокопроизводительную трассировку HTTP-запросов на уровне спецификации ASGI.
Гарантирует стабильность асинхронного контекста ContextVar и предотвращает утечки памяти.
"""

import logging
import time
from fastapi import status
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.debug import context

# Логгер внешнего контура приложения
_logger = logging.getLogger("app.middleware")


class AsgiLoggingMiddleware:
    """
    Высокопроизводительная ASGI мидлварь для сквозной трассировки границ HTTP-запросов.
    
    Категорически заменяет дефектный BaseHTTPMiddleware из Starlette.
    Работает напрямую с сырыми структурами данных (scope/receive/send) веб-сервера.
    """
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Пропускаем через мидлварь только HTTP-сессии (игнорируем веб-сокеты и lifespan-события старта)
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. Извлекаем входящие HTTP-заголовки без создания тяжелых объектов Request
        headers = Headers(scope=scope)
        inbound_trace_id = headers.get("X-Trace-ID")
        
        # Гарантируем, что trace_id существует во всей цепочке вызовов
        trace_id = context.ensure_trace_id(inbound_trace_id)
        
        # 2. Инициализируем ContextVar на самом входе в ASGI-приложение
        context_token = context.set_trace_id(trace_id)
        
        start_time = time.perf_counter()
        path = scope.get("path", "")
        method = scope.get("method", "")
        
        # Безопасно извлекаем IP-адрес клиента из кортежа ASGI scope
        client = scope.get("client")
        client_ip = client[0] if client and isinstance(client, tuple) else None

        # Записываем старт обработки (в TDD это покажет, что запрос успешно зашел на сервер)
        _logger.info(
            f"→ HTTP Request Inbound: {method} {path}",
            extra={
                "event": "request_start",
                "method": method,
                "path": path,
                "client_ip": client_ip,
                "user_agent": headers.get("user-agent"),
            }
        )

        # Контейнер для перехвата HTTP статус-кода из асинхронного потока ответов (используем список ради изменяемости в замыкании)
        status_code = [status.HTTP_500_INTERNAL_SERVER_ERROR]

        # 3. Создаем кастомную обертку над функцией отправки (send), чтобы перехватить ответ сервера
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_code[0] = message["status"]
                
                # Принудительно инжектируем X-Trace-ID в бинарный поток заголовков ответа веб-сервера
                headers_list = message.get("headers", [])
                # ASGI требует заголовки в виде кортежей байтовых строк: (b"name", b"value")
                headers_list.append((b"x-trace-id", trace_id.encode("utf-8")))
                message["headers"] = headers_list
                
            await send(message)

        try:
            # 4. Передаем управление дальше по ASGI-конвейеру к роутерам FastAPI
            await self.app(scope, receive, send_wrapper)
            
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            # Фиксируем успешное завершение за рамками роутера (метрика полного цикла запроса)
            _logger.info(
                f"← HTTP Request Outbound: {method} {path} → {status_code[0]}",
                extra={
                    "event": "request_end",
                    "method": method,
                    "path": path,
                    "status_code": status_code[0],
                    "duration_ms": round(duration_ms, 2),
                }
            )
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            # Этот блок сработает только если упала сама инфраструктура ASGI или произошел необработанный критический краш
            _logger.exception(
                f"❌ HTTP Request Crashed on ASGI level: {method} {path}",
                extra={
                    "event": "request_error",
                    "method": method,
                    "path": path,
                    "duration_ms": round(duration_ms, 2),
                    "error_type": type(exc).__name__,
                }
            )
            raise exc
        finally:
            # 5. КРИТИЧЕСКИ ВАЖНО: Гарантированная очистка токена ContextVar для текущей корутины
            context.reset_trace_id(context_token)