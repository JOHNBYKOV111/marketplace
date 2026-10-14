"""
Unit tests for Core Exceptions.

Tests cover:
- Base AppException initialization, to_dict, log
- All HTTP exception classes with correct status codes and error codes
- Authentication/Authorization exceptions (Unauthorized, Forbidden, Token*, MFA*)
- Infrastructure exceptions (Redis*, Database*, Cache*, Session*, RateLimit*)
- Gateway exceptions (GatewayAuthentication*, MissingGatewayHeader*, InvalidGatewayHeader*)
- Security/Validation/ExternalService exceptions
- Exception handlers (app_exception_handler, http_exception_handler, validation_exception_handler, generic_exception_handler)
- create_error_response helper
- raise_* utility functions
- register_exception_handlers
- ErrorCodes constants
- Edge cases and inheritance chains
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import (
    AppException,
    AuthenticationError,
    AuthorizationError,
    BadRequestException,
    CacheError,
    ConflictException,
    DatabaseConnectionError,
    DatabaseError,
    EncryptionError,
    ExternalServiceError,
    ForbiddenException,
    GatewayAuthenticationError,
    GatewayRoleRequiredError,
    IntegrityError,
    InternalServerErrorException,
    InvalidCredentialsException,
    InvalidGatewayHeaderError,
    InvalidTokenError,
    MFAAlreadyEnabledError,
    MFAError,
    MFANotEnabledError,
    MFARequiredError,
    MFARequiredException,
    MFAPendingException,
    MFAVerificationFailedException,
    MissingGatewayHeaderError,
    NotFoundException,
    PasswordValidationError,
    RateLimitError,
    RedisConnectionError,
    RedisError,
    RedisOperationError,
    RefreshTokenError,
    RefreshTokenNotFoundError,
    RefreshTokenRevokedError,
    SecurityError,
    ServiceUnavailableException,
    SessionError,
    SMSServiceError,
    TimeoutError,
    TokenExpiredError,
    TokenExpiredException,
    TokenInvalidException,
    TokenRevokedError,
    TokenRevokedException,
    TooManyRequestsException,
    UnauthorizedException,
    UserBlockedException,
    UserNotFoundError,
    UserNotFoundException,
    ValidationError,
    ErrorCodes,
    app_exception_handler,
    create_error_response,
    generic_exception_handler,
    http_exception_handler,
    register_exception_handlers,
    validation_exception_handler,
    raise_bad_request,
    raise_conflict,
    raise_forbidden,
    raise_not_found,
    raise_rate_limit,
    raise_unauthorized,
    raise_invalid_credentials,
    raise_invalid_token,
    raise_token_expired,
    raise_token_revoked,
    raise_authentication_error,
    raise_authorization_error,
    raise_mfa_required_error,
    raise_user_blocked,
    raise_user_not_found,
    raise_internal_server_error,
    raise_service_unavailable,
    raise_redis_error,
    raise_cache_error,
    raise_session_error,
    raise_security_error,
    raise_refresh_token_error,
)


# ==================== HELPER FACTORY ====================

def _make_request():
    """Create a mock request with proper string trace_id/request_id for JSON serialization."""
    request = MagicMock(spec=Request)
    request.url.path = "/api/test"
    request.method = "GET"
    request.state = MagicMock()
    request.state.trace_id = None
    request.state.request_id = None
    return request


# ==================== BASE EXCEPTION TESTS ====================

class TestAppException:
    """Tests for base AppException."""

    def test_base_exception_defaults(self):
        exc = AppException(message="Something went wrong")
        assert exc.message == "Something went wrong"
        assert exc.code == "APP_ERROR"
        assert exc.status_code == 500
        assert exc.details == {}
        assert exc.user_id is None

    def test_base_exception_custom_values(self):
        from uuid import uuid4
        uid = uuid4()
        exc = AppException(
            message="Custom error",
            code="CUSTOM_CODE",
            status_code=418,
            details={"field": "value"},
            user_id=uid,
            context={"trace_id": "trace_123"},
        )
        assert exc.message == "Custom error"
        assert exc.code == "CUSTOM_CODE"
        assert exc.status_code == 418
        assert exc.details == {"field": "value", "user_id": str(uid)}
        assert exc.user_id == uid

    def test_base_exception_with_cause(self):
        cause = ValueError("inner error")
        exc = AppException(message="Outer", cause=cause)
        assert exc.context["cause"] == "inner error"
        assert exc.context["cause_type"] == "ValueError"

    def test_base_exception_inheritance(self):
        exc = AppException("test")
        assert isinstance(exc, Exception)

    def test_to_dict(self):
        exc = AppException(message="Test", code="TEST", status_code=400)
        result = exc.to_dict()
        assert result["error"]["code"] == "TEST"
        assert result["error"]["message"] == "Test"

    def test_to_dict_with_internal(self):
        from uuid import uuid4
        uid = uuid4()
        exc = AppException(message="Test", code="TEST", user_id=uid, context={"trace_id": "abc"})
        result = exc.to_dict(include_internal=True)
        assert result["internal"]["status_code"] == 500
        assert result["internal"]["user_id"] == str(uid)

    def test_log(self):
        exc = AppException(message="Test log")
        with patch("app.core.exceptions.logger") as mock_logger:
            exc.log(level="warning")
            mock_logger.warning.assert_called_once()


class TestErrorCodes:
    """Tests for ErrorCodes constants."""

    def test_error_codes_exist(self):
        assert ErrorCodes.APP_ERROR == "APP_ERROR"
        assert ErrorCodes.UNAUTHORIZED == "UNAUTHORIZED"
        assert ErrorCodes.FORBIDDEN == "FORBIDDEN"
        assert ErrorCodes.NOT_FOUND == "NOT_FOUND"
        assert ErrorCodes.BAD_REQUEST == "BAD_REQUEST"
        assert ErrorCodes.RATE_LIMIT_EXCEEDED == "RATE_LIMIT_EXCEEDED"
        assert ErrorCodes.INTERNAL_SERVER_ERROR == "INTERNAL_SERVER_ERROR"
        assert ErrorCodes.TOKEN_EXPIRED == "TOKEN_EXPIRED"
        assert ErrorCodes.TOKEN_INVALID == "TOKEN_INVALID"
        assert ErrorCodes.MFA_REQUIRED == "MFA_REQUIRED"
        assert ErrorCodes.USER_BLOCKED == "USER_BLOCKED"
        assert ErrorCodes.REDIS_ERROR == "REDIS_ERROR"
        assert ErrorCodes.DATABASE_ERROR == "DATABASE_ERROR"


class TestHTTPExceptions:
    """Tests for all HTTP exception classes."""

    def test_bad_request_exception(self):
        exc = BadRequestException()
        assert exc.status_code == 400
        assert exc.code == ErrorCodes.BAD_REQUEST

    def test_unauthorized_exception(self):
        exc = UnauthorizedException()
        assert exc.status_code == 401
        assert exc.code == ErrorCodes.UNAUTHORIZED
        assert exc.authenticate_header == "Bearer"

    def test_invalid_credentials_exception(self):
        exc = InvalidCredentialsException()
        assert exc.status_code == 401
        assert exc.code == ErrorCodes.INVALID_CREDENTIALS

    def test_token_expired_exception(self):
        exc = TokenExpiredException()
        assert exc.status_code == 401
        assert exc.code == ErrorCodes.TOKEN_EXPIRED

    def test_token_invalid_exception(self):
        exc = TokenInvalidException()
        assert exc.status_code == 401
        assert exc.code == ErrorCodes.TOKEN_INVALID

    def test_token_revoked_exception(self):
        exc = TokenRevokedException()
        assert exc.status_code == 401
        assert exc.code == ErrorCodes.TOKEN_REVOKED

    def test_mfa_required_exception(self):
        exc = MFARequiredException(mfa_session_id="sess_123", available_methods=["totp"])
        assert exc.status_code == 401
        assert exc.code == ErrorCodes.MFA_REQUIRED
        assert exc.details["mfa_session_id"] == "sess_123"
        assert exc.details["available_methods"] == ["totp"]

    def test_mfa_pending_exception(self):
        exc = MFAPendingException(mfa_session_id="sess_456")
        assert exc.status_code == 401
        assert exc.code == ErrorCodes.MFA_PENDING
        assert exc.details["mfa_session_id"] == "sess_456"

    def test_mfa_verification_failed_exception(self):
        exc = MFAVerificationFailedException()
        assert exc.status_code == 401
        assert exc.code == ErrorCodes.MFA_VERIFICATION_FAILED

    def test_forbidden_exception(self):
        exc = ForbiddenException()
        assert exc.status_code == 403
        assert exc.code == ErrorCodes.FORBIDDEN

    def test_user_blocked_exception(self):
        exc = UserBlockedException(block_reason="Spam")
        assert exc.status_code == 403
        assert exc.code == ErrorCodes.USER_BLOCKED
        assert exc.details["block_reason"] == "Spam"

    def test_not_found_exception(self):
        exc = NotFoundException(resource_type="user", resource_id="123")
        assert exc.status_code == 404
        assert exc.code == ErrorCodes.NOT_FOUND
        assert exc.details["resource_type"] == "user"

    def test_user_not_found_exception(self):
        from uuid import uuid4
        uid = uuid4()
        exc = UserNotFoundException(user_id=uid)
        assert exc.status_code == 404
        assert exc.code == ErrorCodes.USER_NOT_FOUND

    def test_conflict_exception(self):
        exc = ConflictException()
        assert exc.status_code == 409
        assert exc.code == ErrorCodes.CONFLICT

    def test_too_many_requests_exception(self):
        exc = TooManyRequestsException(retry_after=120)
        assert exc.status_code == 429
        assert exc.code == ErrorCodes.RATE_LIMIT_EXCEEDED
        assert exc.retry_after == 120

    def test_internal_server_error_exception(self):
        exc = InternalServerErrorException()
        assert exc.status_code == 500
        assert exc.code == ErrorCodes.INTERNAL_SERVER_ERROR

    def test_service_unavailable_exception(self):
        exc = ServiceUnavailableException()
        assert exc.status_code == 503
        assert exc.code == ErrorCodes.SERVICE_UNAVAILABLE


class TestAuthAliases:
    """Tests for authentication/authorization alias exceptions."""

    def test_authentication_error(self):
        exc = AuthenticationError()
        assert exc.status_code == 401
        assert isinstance(exc, UnauthorizedException)

    def test_authorization_error(self):
        exc = AuthorizationError()
        assert exc.status_code == 403
        assert isinstance(exc, ForbiddenException)

    def test_invalid_token_error(self):
        exc = InvalidTokenError()
        assert exc.status_code == 401
        assert isinstance(exc, UnauthorizedException)

    def test_token_expired_error(self):
        exc = TokenExpiredError()
        assert exc.status_code == 401
        assert isinstance(exc, UnauthorizedException)

    def test_token_revoked_error(self):
        exc = TokenRevokedError()
        assert exc.status_code == 401
        assert isinstance(exc, UnauthorizedException)

    def test_user_not_found_error(self):
        exc = UserNotFoundError()
        assert exc.status_code == 404
        assert isinstance(exc, NotFoundException)

    def test_mfa_required_error(self):
        exc = MFARequiredError()
        assert exc.status_code == 401
        assert isinstance(exc, UnauthorizedException)


class TestInfrastructureExceptions:
    """Tests for infrastructure exceptions."""

    def test_redis_error(self):
        exc = RedisError()
        assert exc.status_code == 500
        assert exc.code == ErrorCodes.REDIS_ERROR

    def test_redis_connection_error(self):
        exc = RedisConnectionError()
        assert exc.code == ErrorCodes.REDIS_CONNECTION_ERROR

    def test_redis_operation_error(self):
        exc = RedisOperationError(operation="GET")
        assert exc.code == ErrorCodes.REDIS_OPERATION_ERROR
        assert exc.details["operation"] == "GET"

    def test_cache_error(self):
        exc = CacheError()
        assert exc.status_code == 500
        assert exc.code == ErrorCodes.CACHE_ERROR

    def test_session_error(self):
        exc = SessionError()
        assert exc.status_code == 400
        assert exc.code == ErrorCodes.SESSION_ERROR

    def test_rate_limit_error(self):
        exc = RateLimitError(retry_after=30)
        assert exc.status_code == 429
        assert exc.code == ErrorCodes.RATE_LIMIT_EXCEEDED
        assert exc.retry_after == 30

    def test_database_error(self):
        exc = DatabaseError()
        assert exc.status_code == 500
        assert exc.code == ErrorCodes.DATABASE_ERROR

    def test_database_connection_error(self):
        exc = DatabaseConnectionError()
        assert exc.code == ErrorCodes.DATABASE_CONNECTION_ERROR

    def test_integrity_error(self):
        exc = IntegrityError()
        assert exc.status_code == 409
        assert exc.code == ErrorCodes.INTEGRITY_ERROR

    def test_encryption_error(self):
        exc = EncryptionError()
        assert exc.status_code == 500
        assert exc.code == ErrorCodes.ENCRYPTION_ERROR


class TestGatewayExceptions:
    """Tests for Gateway exceptions."""

    def test_gateway_authentication_error(self):
        exc = GatewayAuthenticationError()
        assert exc.status_code == 401
        assert exc.code == ErrorCodes.GATEWAY_AUTH_ERROR
        assert exc.authenticate_header == "Gateway"

    def test_missing_gateway_header_error(self):
        exc = MissingGatewayHeaderError(header_name="X-User-Id")
        assert exc.code == ErrorCodes.MISSING_GATEWAY_HEADER
        assert exc.details["header_name"] == "X-User-Id"

    def test_invalid_gateway_header_error(self):
        exc = InvalidGatewayHeaderError(header_name="X-User-Id", reason="not a UUID")
        assert exc.code == ErrorCodes.INVALID_GATEWAY_HEADER
        assert exc.details["reason"] == "not a UUID"

    def test_gateway_role_required_error(self):
        exc = GatewayRoleRequiredError(required_roles=["admin"], user_roles=["user"])
        assert exc.status_code == 403
        assert exc.code == ErrorCodes.GATEWAY_ROLE_REQUIRED
        assert exc.required_roles == ["admin"]


class TestOtherExceptions:
    """Tests for remaining exception classes."""

    def test_security_error(self):
        exc = SecurityError()
        assert exc.status_code == 403

    def test_validation_error(self):
        exc = ValidationError(errors=[{"field": "email", "msg": "required"}])
        assert exc.status_code == 422
        assert exc.details["errors"] == [{"field": "email", "msg": "required"}]

    def test_password_validation_error(self):
        exc = PasswordValidationError()
        assert exc.status_code == 422

    def test_external_service_error(self):
        exc = ExternalServiceError(service_name="payment")
        assert exc.status_code == 502
        assert exc.details["service_name"] == "payment"

    def test_timeout_error(self):
        exc = TimeoutError(operation="db_query")
        assert exc.status_code == 504
        assert exc.details["operation"] == "db_query"

    def test_mfa_already_enabled_error(self):
        exc = MFAAlreadyEnabledError()
        assert exc.status_code == 409

    def test_mfa_not_enabled_error(self):
        exc = MFANotEnabledError()
        assert exc.status_code == 404

    def test_refresh_token_error(self):
        exc = RefreshTokenError()
        assert exc.status_code == 401

    def test_refresh_token_not_found_error(self):
        exc = RefreshTokenNotFoundError()
        assert exc.code == "REFRESH_TOKEN_NOT_FOUND"

    def test_refresh_token_revoked_error(self):
        exc = RefreshTokenRevokedError()
        assert exc.code == "REFRESH_TOKEN_REVOKED"


class TestCreateErrorResponse:
    """Tests for create_error_response helper."""

    @pytest.fixture
    def mock_request(self):
        return _make_request()

    def test_minimal(self, mock_request):
        response = create_error_response(mock_request, 401, "UNAUTHORIZED", "Unauthorized")
        assert response.status_code == 401

    def test_with_details(self, mock_request):
        response = create_error_response(mock_request, 400, "BAD", "Bad", details={"field": "x"})
        content = json.loads(response.body.decode())
        assert content["error"]["details"] == {"field": "x"}

    def test_with_retry_after(self, mock_request):
        response = create_error_response(mock_request, 429, "RATE", "Rate", retry_after=60)
        assert response.headers["Retry-After"] == "60"


class TestExceptionHandlers:
    """Tests for exception handlers."""

    @pytest.fixture
    def mock_request(self):
        return _make_request()

    @pytest.mark.asyncio
    async def test_app_exception_handler(self, mock_request):
        exc = BadRequestException(message="Bad")
        response = await app_exception_handler(mock_request, exc)
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_http_exception_handler_401_masks_detail(self, mock_request):
        exc = StarletteHTTPException(status_code=401, detail="Invalid token")
        response = await http_exception_handler(mock_request, exc)
        content = json.loads(response.body.decode())
        assert content["error"]["message"] == "Unauthorized"

    @pytest.mark.asyncio
    async def test_http_exception_handler_404(self, mock_request):
        exc = StarletteHTTPException(status_code=404, detail="Not found")
        response = await http_exception_handler(mock_request, exc)
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_validation_exception_handler(self, mock_request):
        exc = RequestValidationError(
            errors=[{"loc": ("body", "email"), "msg": "required", "type": "missing"}],
            body=None,
        )
        response = await validation_exception_handler(mock_request, exc)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_generic_handler_debug(self, mock_request):
        with patch("app.core.exceptions.settings") as mock_settings:
            mock_settings.DEBUG = True
            exc = ValueError("test error")
            response = await generic_exception_handler(mock_request, exc)
            content = json.loads(response.body.decode())
            assert content["error"]["message"] == "test error"

    @pytest.mark.asyncio
    async def test_generic_handler_production(self, mock_request):
        with patch("app.core.exceptions.settings") as mock_settings:
            mock_settings.DEBUG = False
            exc = ValueError("secret info")
            response = await generic_exception_handler(mock_request, exc)
            content = json.loads(response.body.decode())
            assert content["error"]["message"] == "Internal server error"


class TestRegisterExceptionHandlers:
    """Tests for register_exception_handlers."""

    def test_register_all_handlers(self):
        app = MagicMock(spec=FastAPI)
        register_exception_handlers(app)
        assert app.add_exception_handler.call_count == 4


class TestRaiseUtilities:
    """Tests for raise_* utility functions."""

    def test_raise_bad_request(self):
        with pytest.raises(BadRequestException):
            raise_bad_request("Bad")

    def test_raise_unauthorized(self):
        with pytest.raises(UnauthorizedException):
            raise_unauthorized("Unauthorized")

    def test_raise_invalid_credentials(self):
        with pytest.raises(InvalidCredentialsException):
            raise_invalid_credentials("Invalid")

    def test_raise_forbidden(self):
        with pytest.raises(ForbiddenException):
            raise_forbidden("Forbidden")

    def test_raise_not_found(self):
        with pytest.raises(NotFoundException):
            raise_not_found("Not found")

    def test_raise_user_not_found(self):
        from uuid import uuid4
        with pytest.raises(UserNotFoundError):
            raise_user_not_found(uuid4())

    def test_raise_user_blocked(self):
        with pytest.raises(UserBlockedException):
            raise_user_blocked("Blocked")

    def test_raise_conflict(self):
        with pytest.raises(ConflictException):
            raise_conflict("Conflict")

    def test_raise_rate_limit(self):
        with pytest.raises(TooManyRequestsException) as exc_info:
            raise_rate_limit(retry_after=30)
        assert exc_info.value.retry_after == 30

    def test_raise_internal_server_error(self):
        with pytest.raises(InternalServerErrorException):
            raise_internal_server_error()

    def test_raise_service_unavailable(self):
        with pytest.raises(ServiceUnavailableException):
            raise_service_unavailable()

    def test_raise_redis_error(self):
        with pytest.raises(RedisError):
            raise_redis_error()

    def test_raise_cache_error(self):
        with pytest.raises(CacheError):
            raise_cache_error()

    def test_raise_session_error(self):
        with pytest.raises(SessionError):
            raise_session_error()

    def test_raise_security_error(self):
        with pytest.raises(SecurityError):
            raise_security_error()

    def test_raise_invalid_token(self):
        with pytest.raises(InvalidTokenError):
            raise_invalid_token()

    def test_raise_token_expired(self):
        with pytest.raises(TokenExpiredError):
            raise_token_expired()

    def test_raise_token_revoked(self):
        with pytest.raises(TokenRevokedError):
            raise_token_revoked()

    def test_raise_authentication_error(self):
        with pytest.raises(AuthenticationError):
            raise_authentication_error()

    def test_raise_authorization_error(self):
        with pytest.raises(AuthorizationError):
            raise_authorization_error()

    def test_raise_mfa_required_error(self):
        with pytest.raises(MFARequiredError):
            raise_mfa_required_error()

    def test_raise_refresh_token_error(self):
        with pytest.raises(RefreshTokenError):
            raise_refresh_token_error()


class TestInheritanceChains:
    """Tests for exception inheritance chains."""

    def test_all_http_exceptions_inherit_from_app_exception(self):
        exceptions = [
            BadRequestException, UnauthorizedException, ForbiddenException,
            NotFoundException, ConflictException, TooManyRequestsException,
            InternalServerErrorException, ServiceUnavailableException,
        ]
        for exc_class in exceptions:
            assert issubclass(exc_class, AppException), f"{exc_class.__name__} does not inherit from AppException"

    def test_token_exceptions_inherit_from_unauthorized(self):
        assert issubclass(TokenExpiredException, UnauthorizedException)
        assert issubclass(TokenInvalidException, UnauthorizedException)
        assert issubclass(TokenRevokedException, UnauthorizedException)

    def test_mfa_exceptions_inherit_from_unauthorized(self):
        assert issubclass(MFARequiredException, UnauthorizedException)
        assert issubclass(MFAPendingException, UnauthorizedException)
        assert issubclass(MFAVerificationFailedException, UnauthorizedException)

    def test_user_blocked_inherits_from_forbidden(self):
        assert issubclass(UserBlockedException, ForbiddenException)

    def test_redis_errors_inherit_from_redis_error(self):
        assert issubclass(RedisConnectionError, RedisError)
        assert issubclass(RedisOperationError, RedisError)

    def test_database_errors_inherit_from_database_error(self):
        assert issubclass(DatabaseConnectionError, DatabaseError)
        assert issubclass(IntegrityError, DatabaseError)

    def test_gateway_errors_inherit_correctly(self):
        assert issubclass(GatewayAuthenticationError, UnauthorizedException)
        assert issubclass(MissingGatewayHeaderError, GatewayAuthenticationError)
        assert issubclass(InvalidGatewayHeaderError, GatewayAuthenticationError)
        assert issubclass(GatewayRoleRequiredError, ForbiddenException)