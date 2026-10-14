"""
Инфраструктурный модуль маршрутизации FastAPI.
Реализует безопасный перехват, трассировку и логирование жизненного цикла HTTP-запросов.
Полностью совместим со сквозным логированием в TDD и Production средах.
"""

import json
import logging
import time
from typing import Callable

from fastapi import Request, Response
from fastapi.routing import APIRoute

from app.core.debug import context

# Логгер слоя API
_logger = logging.getLogger("app.api")


class LoggingRoute(APIRoute):
    """
    Кастомный класс маршрутизации для сквозного логирования HTTP-запросов и ответов.
    
    Решает критическую уязвимость стандартных мидлварей FastAPI, безопасно вычитывая 
    тело (body) запроса до этапа Pydantic-валидации без блокировки асинхронного потока.
    """
    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> Response:
            # 1. Извлекаем trace_id из заголовков (если пришел от Gateway/Nginx) или генерируем новый
            inbound_trace_id = request.headers.get("X-Trace-ID")
            trace_id = context.ensure_trace_id(inbound_trace_id)
            
            # 2. Инициализируем контекст корутины и сохраняем токен для безопасного сброса
            context_token = context.set_trace_id(trace_id)
            
            start_time = time.perf_counter()
            
            # 3. Безопасно вычитываем сырые байты тела запроса до того, как поток заблокируется фреймворком
            body_bytes = await request.body()
            body_str = body_bytes.decode("utf-8") if body_bytes else ""
            
            # Парсим тело в структурированный Python-объект для сохранения вложенности в JSON/Логах
            try:
                request_payload = json.loads(body_str) if body_str else None
            except Exception:
                request_payload = body_str

            try:
                # 4. Передаем управление роутеру FastAPI для выполнения бизнес-логики и валидации
                response: Response = await original_route_handler(request)
                
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                # Логируем успешный запрос. Маскировка PII (паролей, токенов) произойдет автоматически в JsonFormatter
                _logger.info(
                    f"HTTP {request.method} {request.url.path} -> {response.status_code}",
                    extra={
                        "event": "http_request",
                        "status": "success",
                        "method": request.method,
                        "path": request.url.path,
                        "status_code": response.status_code,
                        "duration_ms": round(duration_ms, 2),
                        "request_body": request_payload
                    }
                )
                
                # 5. Инжектируем trace_id обратно в заголовки ответа для фронтенда и саппорта
                response.headers["X-Trace-ID"] = trace_id
                return response

            except Exception as exc:
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                # Фиксируем крэш эндпоинта. Полный рапорт ошибки с Locals соберется декоратором или глобальным хендлером
                _logger.exception(
                    f"HTTP {request.method} {request.url.path} -> CRASHED",
                    extra={
                        "event": "http_request_error",
                        "status": "error",
                        "method": request.method,
                        "path": request.url.path,
                        "duration_ms": round(duration_ms, 2),
                        "request_body": request_payload,
                        "error_type": type(exc).__name__
                    }
                )
                raise exc
            finally:
                # 6. КРИТИЧЕСКИ ВАЖНО: Гарантированно очищаем ContextVar корутины, исключая утечки памяти в WSL/Проде
                context.reset_trace_id(context_token)

        return custom_route_handler
