"""
Middleware для проверки прав доступа.
"""

from typing import Optional
from uuid import UUID

from fastapi import Request, HTTPException, status
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import get_logger
from app.core.security import decode_token, extract_jwt_from_header

logger = get_logger(__name__)


class AuthMiddleware:
    """
    ASGI Middleware для проверки прав доступа.
    
    Переписана с BaseHTTPMiddleware на ASGI-контракт для:
    - Корректной передачи исключений в ServerErrorMiddleware
    - Устранения багов с anyio.EndOfStream
    - Повышения производительности
    """
    
    def __init__(self, app: ASGIApp):
        """
        Инициализация ASGI middleware.

        Args:
            app: Следующее ASGI-приложение в цепочке
        """
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        Обработка ASGI запроса.

        Args:
            scope: ASGI scope (информация о запросе)
            receive: ASGI receive (получение данных)
            send: ASGI send (отправка ответа)
        """
        # Обрабатываем только HTTP запросы
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)

        # Пропускаем health check
        if request.url.path.startswith("/health") or request.url.path.startswith("/api/v1/health"):
            await self.app(scope, receive, send)
            return

        # ✅ ПРОПУСКАЕМ INTERNAL API ЗАПРОСЫ (межсервисное взаимодействие)
        # Internal API использует X-Internal-API-Key, а не JWT или X-User-Id
        if request.url.path.startswith("/internal") or request.url.path.startswith("/api/v1/internal"):
            logger.debug(f"Internal API request: {request.url.path} - skipping auth middleware")
            await self.app(scope, receive, send)
            return

        # По умолчанию пользователь анонимный
        user_id = None
        user_role = "anonymous"
        user = None

        # Проверяем наличие заголовка авторизации
        auth_header = request.headers.get("Authorization")

        # Новая логика: проверка JWT токена
        if auth_header and auth_header.startswith("Bearer "):
            token = extract_jwt_from_header(auth_header)
            if token:
                try:
                    # Декодирование токена
                    payload = decode_token(token)

                    # Извлечение user_id из токена
                    user_id_str = payload.get("sub")
                    if user_id_str:
                        try:
                            user_id = UUID(user_id_str)
                            # Для JWT токенов роль определяем из payload или ставим "user"
                            user_role = payload.get("role", "user")
                            logger.debug(f"JWT authenticated: user_id={user_id}, role={user_role}")
                        except ValueError:
                            logger.warning(f"Invalid UUID in token: {user_id_str}")
                except Exception as e:
                    # При ошибке декодирования JWT - не блокируем, а логируем
                    logger.debug(f"JWT decode failed (will use headers if present): {e}")

        # Существующая логика: заголовки X-User-Id и X-User-Role
        if not user_id:
            x_user_id = request.headers.get("X-User-Id")
            if x_user_id:
                try:
                    user_id = UUID(x_user_id)
                except ValueError:
                    # ✅ НЕ БЛОКИРУЕМ ЗАПРОС, а логируем ошибку
                    # Для Internal API запросов X-User-Id может отсутствовать
                    logger.warning(f"Invalid X-User-Id format: {x_user_id} - skipping user identification")
                    # Не выбрасываем HTTPException, чтобы не блокировать запрос

            x_user_role = request.headers.get("X-User-Role")
            if x_user_role:
                user_role = x_user_role

        # Сохраняем данные в request.state для использования в роутерах
        request.state.user_id = user_id
        request.state.user_role = user_role

        # Передаём управление дальше по цепочке ASGI
        # Любое исключение (ValueError, Exception) будет проброшено наверх
        # к ServerErrorMiddleware без разрыва стрима
        await self.app(scope, receive, send)