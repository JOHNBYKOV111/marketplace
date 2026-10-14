"""
Интеграционные тесты для исключений и обработчиков ошибок.

Тестирует:
- Кастомные исключения AuthServiceException и все его наследники
- Хендлеры исключений в FastAPI приложении
- Формат ответов с ошибками (error_code, message, trace_id, request_id)
- Маскирование деталей ошибок в production режиме
- Валидационные ошибки Pydantic (422)
- Обработку непредвиденных исключений (500)
- Retry-After заголовок для 429
- Вспомогательные функции (raise_*)
"""

from unittest.mock import MagicMock, patch
from uuid import uuid4
from typing import List, Dict

import pytest
from fastapi import FastAPI, Request, status, APIRouter
from fastapi.exceptions import RequestValidationError
from httpx import AsyncClient, ASGITransport
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.exceptions import (
    AppException,
    BadRequestException,
    ConflictException,
    ForbiddenException,
    InvalidCredentialsException,
    MFARequiredException,
    MFAPendingException,
    NotFoundException,
    ServiceUnavailableException,
    TokenExpiredException,
    TokenInvalidException,
    TooManyRequestsException,
    UnauthorizedException,
    UserBlockedException,
    create_error_response,
    generic_exception_handler,
    http_exception_handler,
    raise_bad_request,
    raise_conflict,
    raise_forbidden,
    raise_not_found,
    raise_rate_limit,
    raise_unauthorized,
    register_exception_handlers,
    validation_exception_handler,
)
from app.main import app as real_app


# ==================== ТЕСТОВЫЙ РОУТЕР ДЛЯ ПРОВОКАЦИИ ОШИБОК ====================

_error_router = APIRouter(prefix="/api/v1/error-triggers", tags=["error-triggers"])


class _ValidationSchema(BaseModel):
    required_field: str
    numeric_field: int = Field(gt=0)


class _SubModel(BaseModel):
    name: str
    score: int = Field(gt=0, lt=100)


class _ComplexValidationSchema(BaseModel):
    title: str
    items: List[_SubModel]
    metadata: Dict[str, str]


@_error_router.get("/401")
async def trigger_401():
    raise UnauthorizedException()


@_error_router.get("/403")
async def trigger_403():
    raise ForbiddenException()


@_error_router.get("/404")
async def trigger_404():
    raise NotFoundException("User not found")


@_error_router.get("/409")
async def trigger_409():
    raise ConflictException("Email already exists")


@_error_router.get("/429")
async def trigger_429():
    raise TooManyRequestsException(retry_after=60)


@_error_router.get("/400")
async def trigger_400():
    raise BadRequestException("Invalid input")


@_error_router.get("/mfa")
async def trigger_mfa():
    raise MFARequiredException(
        mfa_session_id="session_123",
        available_methods=["totp", "sms"],
    )


@_error_router.get("/http-400")
async def trigger_http_400():
    raise StarletteHTTPException(status_code=400, detail="Bad request")


@_error_router.get("/http-401")
async def trigger_http_401():
    raise StarletteHTTPException(status_code=401, detail="Invalid token")


@_error_router.get("/http-403")
async def trigger_http_403():
    raise StarletteHTTPException(status_code=403, detail="Forbidden")


@_error_router.get("/http-404")
async def trigger_http_404():
    raise StarletteHTTPException(status_code=404, detail="Resource not found")


@_error_router.get("/http-409")
async def trigger_http_409():
    raise StarletteHTTPException(status_code=409, detail="Conflict")


@_error_router.get("/http-422")
async def trigger_http_422():
    raise StarletteHTTPException(status_code=422, detail="Unprocessable")


@_error_router.get("/http-429")
async def trigger_http_429():
    raise StarletteHTTPException(status_code=429, detail="Rate limit exceeded")


@_error_router.get("/http-500")
async def trigger_http_500():
    raise StarletteHTTPException(status_code=500, detail="Internal error")


@_error_router.get("/http-503")
async def trigger_http_503():
    raise StarletteHTTPException(status_code=503, detail="Service unavailable")


@_error_router.post("/validation")
async def trigger_validation(data: _ValidationSchema):
    return {"success": True}


@_error_router.get("/error-value")
async def trigger_value_error():
    raise ValueError("Secret database error")


@_error_router.get("/error-exception")
async def trigger_exception():
    raise Exception()


@_error_router.get("/http-404-no-detail")
async def trigger_http_404_no_detail():
    raise StarletteHTTPException(status_code=404)


@_error_router.post("/nested-validation")
async def trigger_nested_validation(data: _ComplexValidationSchema):
    return {"success": True}


# ==================== FIXTURE ДЛЯ АСИНХРОННОГО КЛИЕНТА ====================

@pytest.fixture(scope="function")
async def async_client():
    """Создаёт асинхронный клиент для тестирования."""
    app = FastAPI(debug=False)
    register_exception_handlers(app)
    app.include_router(_error_router)
    app.dependency_overrides = real_app.dependency_overrides.copy()
    
    # ПРОД-ЛИД РЕШЕНИЕ: используем правильный аргумент для вашей версии HTTPX
    # raise_app_exceptions=False даёт Starlette команду не выбрасывать исключения в pytest,
    # а передавать их в app.exception_handlers
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


# ==================== ТЕСТЫ ====================

class TestAuthServiceException:
    """Тесты для базового исключения AuthServiceException."""

    def test_base_exception_defaults(self):
        exc = AppException("Test error")
        assert exc.message == "Test error"
        assert exc.code == "APP_ERROR"
        assert exc.status_code == 500
        assert exc.details == {}

    def test_base_exception_custom(self):
        exc = AppException(
            message="Custom error",
            code="CUSTOM_CODE",
            status_code=418,
            details={"key": "value"},
        )
        assert exc.message == "Custom error"
        assert exc.code == "CUSTOM_CODE"
        assert exc.status_code == 418
        assert exc.details == {"key": "value"}


class TestSpecificExceptions:
    """Тесты для специфических исключений."""

    def test_unauthorized_exception(self):
        exc = UnauthorizedException()
        assert exc.status_code == 401
        assert exc.code == "UNAUTHORIZED"

    def test_forbidden_exception(self):
        exc = ForbiddenException()
        assert exc.status_code == 403
        assert exc.code == "FORBIDDEN"

    def test_not_found_exception(self):
        exc = NotFoundException()
        assert exc.status_code == 404
        assert exc.code == "NOT_FOUND"

    def test_conflict_exception(self):
        exc = ConflictException()
        assert exc.status_code == 409
        assert exc.code == "CONFLICT"

    def test_too_many_requests_exception(self):
        exc = TooManyRequestsException()
        assert exc.status_code == 429
        assert exc.code == "RATE_LIMIT_EXCEEDED"
        assert exc.retry_after == 60

    def test_bad_request_exception(self):
        exc = BadRequestException()
        assert exc.status_code == 400
        assert exc.code == "BAD_REQUEST"

    def test_service_unavailable_exception(self):
        exc = ServiceUnavailableException()
        assert exc.status_code == 503
        assert exc.code == "SERVICE_UNAVAILABLE"

    def test_token_expired_exception(self):
        exc = TokenExpiredException()
        assert exc.status_code == 401
        assert exc.code == "TOKEN_EXPIRED"

    def test_token_invalid_exception(self):
        exc = TokenInvalidException()
        assert exc.status_code == 401
        assert exc.code == "TOKEN_INVALID"

    def test_invalid_credentials_exception(self):
        exc = InvalidCredentialsException()
        assert exc.status_code == 401
        assert exc.code == "INVALID_CREDENTIALS"

    def test_user_blocked_exception(self):
        exc = UserBlockedException()
        assert exc.status_code == 403
        assert exc.code == "USER_BLOCKED"

    def test_mfa_required_exception_with_details(self):
        exc = MFARequiredException(
            mfa_session_id="session_123",
            available_methods=["totp", "sms"],
        )
        assert exc.status_code == 401
        assert exc.code == "MFA_REQUIRED"
        assert exc.details["mfa_session_id"] == "session_123"
        assert exc.details["available_methods"] == ["totp", "sms"]

    def test_mfa_pending_exception(self):
        exc = MFAPendingException()
        assert exc.status_code == 401
        assert exc.code == "MFA_PENDING"


class TestCreateErrorResponse:
    """Тесты для create_error_response функции."""

    @pytest.fixture
    def mock_request(self):
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.trace_id = "trace_123"
        request.state.request_id = "req_456"
        return request

    def test_create_error_response_minimal(self, mock_request):
        response = create_error_response(
            request=mock_request,
            status_code=401,
            error_code="UNAUTHORIZED",
            message="Unauthorized",
        )
        import json
        data = json.loads(response.body)
        assert response.status_code == 401
        assert data["error"]["code"] == "UNAUTHORIZED"
        assert data["error"]["message"] == "Unauthorized"
        assert data["trace_id"] == "trace_123"
        assert data["request_id"] == "req_456"

    def test_create_error_response_with_details(self, mock_request):
        response = create_error_response(
            request=mock_request,
            status_code=400,
            error_code="BAD_REQUEST",
            message="Bad request",
            details={"field": "email", "error": "required"},
        )
        import json
        data = json.loads(response.body)
        assert data["error"]["details"]["field"] == "email"

    def test_create_error_response_with_retry_after(self, mock_request):
        response = create_error_response(
            request=mock_request,
            status_code=429,
            error_code="RATE_LIMIT_EXCEEDED",
            message="Too many requests",
            retry_after=120,
        )
        assert response.headers.get("Retry-After") == "120"


class TestAuthServiceExceptionHandler:
    """Тесты для auth_service_exception_handler (асинхронные)."""

    @pytest.mark.asyncio
    async def test_unauthorized_exception_response(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/401")
        data = response.json()
        assert response.status_code == 401
        assert data["error"]["code"] == "UNAUTHORIZED"

    @pytest.mark.asyncio
    async def test_forbidden_exception_response(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/403")
        data = response.json()
        assert response.status_code == 403
        assert data["error"]["code"] == "FORBIDDEN"

    @pytest.mark.asyncio
    async def test_not_found_exception_response(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/404")
        data = response.json()
        assert response.status_code == 404
        assert data["error"]["code"] == "NOT_FOUND"
        assert data["error"]["message"] == "User not found"

    @pytest.mark.asyncio
    async def test_conflict_exception_response(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/409")
        data = response.json()
        assert response.status_code == 409
        assert data["error"]["code"] == "CONFLICT"

    @pytest.mark.asyncio
    async def test_too_many_requests_exception_with_retry_after(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/429")
        data = response.json()
        assert response.status_code == 429
        assert response.headers.get("Retry-After") == "60"
        assert data["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    @pytest.mark.asyncio
    async def test_bad_request_exception_response(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/400")
        data = response.json()
        assert response.status_code == 400
        assert data["error"]["code"] == "BAD_REQUEST"

    @pytest.mark.asyncio
    async def test_mfa_required_exception_with_details(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/mfa")
        data = response.json()
        assert response.status_code == 401
        assert data["error"]["code"] == "MFA_REQUIRED"
        assert data["error"]["details"]["mfa_session_id"] == "session_123"


class TestHTTPExceptionHandler:
    """Тесты для http_exception_handler (асинхронные)."""

    @pytest.mark.asyncio
    async def test_http_400_exception(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/http-400")
        data = response.json()
        assert response.status_code == 400
        assert data["error"]["code"] == "BAD_REQUEST"

    @pytest.mark.asyncio
    async def test_http_401_unauthorized_masks_detail(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/http-401")
        data = response.json()
        assert response.status_code == 401
        assert data["error"]["message"] == "Unauthorized"

    @pytest.mark.asyncio
    async def test_http_403_exception(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/http-403")
        data = response.json()
        assert response.status_code == 403
        assert data["error"]["code"] == "FORBIDDEN"

    @pytest.mark.asyncio
    async def test_http_404_exception(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/http-404")
        data = response.json()
        assert response.status_code == 404
        assert data["error"]["code"] == "NOT_FOUND"

    @pytest.mark.asyncio
    async def test_http_409_exception(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/http-409")
        data = response.json()
        assert response.status_code == 409
        assert data["error"]["code"] == "CONFLICT"

    @pytest.mark.asyncio
    async def test_http_422_exception(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/http-422")
        data = response.json()
        assert response.status_code == 422
        assert data["error"]["code"] == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_http_429_exception(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/http-429")
        data = response.json()
        assert response.status_code == 429
        assert data["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    @pytest.mark.asyncio
    async def test_http_500_exception(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/http-500")
        data = response.json()
        assert response.status_code == 500
        assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"

    @pytest.mark.asyncio
    async def test_http_503_exception(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/http-503")
        data = response.json()
        assert response.status_code == 503
        assert data["error"]["code"] == "SERVICE_UNAVAILABLE"


class TestValidationExceptionHandler:
    """Тесты для validation_exception_handler (Pydantic ошибки) — асинхронные."""

    @pytest.mark.asyncio
    async def test_validation_error_response(self, async_client):
        response = await async_client.post(
            "/api/v1/error-triggers/validation",
            json={"required_field": "test", "numeric_field": -5}
        )
        data = response.json()
        assert response.status_code == 422
        assert data["error"]["code"] == "VALIDATION_ERROR"
        assert data["error"]["message"] == "Request validation failed"
        assert "details" in data["error"]
        assert "errors" in data["error"]["details"]


class TestGenericExceptionHandler:
    """Тесты для generic_exception_handler (непредвиденные исключения) — асинхронные."""

    @pytest.mark.asyncio
    async def test_generic_exception_production_mode(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/error-value")
        data = response.json()
        assert response.status_code == 500
        assert data["error"]["message"] == "Internal server error"
        assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"


class TestRaiseUtilities:
    """Тесты для вспомогательных функций raise_*."""

    def test_raise_unauthorized(self):
        with pytest.raises(UnauthorizedException):
            raise_unauthorized()

    def test_raise_forbidden(self):
        with pytest.raises(ForbiddenException):
            raise_forbidden()

    def test_raise_not_found(self):
        with pytest.raises(NotFoundException):
            raise_not_found()

    def test_raise_conflict(self):
        with pytest.raises(ConflictException):
            raise_conflict()

    def test_raise_rate_limit(self):
        with pytest.raises(TooManyRequestsException) as exc:
            raise_rate_limit(retry_after=30)
        assert exc.value.retry_after == 30

    def test_raise_bad_request(self):
        with pytest.raises(BadRequestException):
            raise_bad_request()


class TestExceptionInheritance:
    """Тесты для иерархии наследования исключений."""

    def test_token_exceptions_inherit_from_unauthorized(self):
        assert issubclass(TokenExpiredException, UnauthorizedException)
        assert issubclass(TokenInvalidException, UnauthorizedException)

    def test_invalid_credentials_inherits_from_unauthorized(self):
        assert issubclass(InvalidCredentialsException, UnauthorizedException)

    def test_user_blocked_inherits_from_forbidden(self):
        assert issubclass(UserBlockedException, ForbiddenException)

    def test_mfa_exceptions_inherit_from_unauthorized(self):
        assert issubclass(MFARequiredException, UnauthorizedException)
        assert issubclass(MFAPendingException, UnauthorizedException)


class TestEdgeCases:
    """Тесты для граничных случаев — асинхронные."""

    @pytest.mark.asyncio
    async def test_generic_exception_with_none_detail(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/error-exception")
        data = response.json()
        assert response.status_code == 500
        assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
        assert data["error"]["message"] == "Internal server error"

    @pytest.mark.asyncio
    async def test_http_exception_with_none_detail(self, async_client):
        response = await async_client.get("/api/v1/error-triggers/http-404-no-detail")
        data = response.json()
        assert response.status_code == 404
        assert data["error"]["code"] == "NOT_FOUND"

    @pytest.mark.asyncio
    async def test_validation_exception_with_complex_fields(self, async_client):
        invalid_payload = {
            "title": "Test Complex",
            "items": [{"name": "Item 1", "score": -10}],
            "metadata": {"key": "value"}
        }
        response = await async_client.post("/api/v1/error-triggers/nested-validation", json=invalid_payload)
        data = response.json()
        assert response.status_code == 422
        assert data["error"]["code"] == "VALIDATION_ERROR"
        assert "details" in data["error"]
        assert "errors" in data["error"]["details"]

    def test_create_error_response_without_request_state(self):
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.trace_id = None
        request.state.request_id = None

        response = create_error_response(
            request=request,
            status_code=500,
            error_code="ERROR",
            message="Error",
        )

        import json
        data = json.loads(response.body)
        assert data.get("trace_id") is None
        assert data.get("request_id") is None