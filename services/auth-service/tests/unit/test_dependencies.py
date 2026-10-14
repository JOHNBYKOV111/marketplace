"""
Unit tests for Core Dependencies.

Tests cover:
- GatewayHeaders constants
- CurrentUserClaims model (has_role, has_any_role, has_all_roles, is_admin, dict)
- CurrentUserClaimsOptional model
- get_current_user_claims_required (success, missing header, invalid UUID)
- get_current_user_claims_optional (present, missing, invalid UUID)
- get_current_user_from_gateway_headers (success, missing header, invalid UUID)
- GatewayUser class
- require_roles factory (success, forbidden)
- require_all_roles factory (success, forbidden)
- require_admin (admin success, non-admin forbidden)
- get_client_ip, get_user_agent
- Infrastructure factories (get_user_repository, get_token_service)
- Pagination params
- Internal API verification
- Edge cases and error handling

Note: All dependencies are async functions and must be awaited.
"""

import asyncio
import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException, Request

from app.core.dependencies import (
    GatewayHeaders,
    GatewayUser,
    get_current_user_claims_required,
    get_current_user_claims_optional,
    get_current_user_from_gateway_headers,
    require_roles,
    require_all_roles,
    require_admin,
    get_client_ip,
    get_user_agent,
    get_pagination_params,
    verify_internal_api_key,
    get_user_repository,
    get_token_service,
)
from app.core.exceptions import UnauthorizedException
from app.schemas.claims import CurrentUserClaims, CurrentUserClaimsOptional


class TestGatewayHeaders:
    """Tests for GatewayHeaders constants."""

    def test_gateway_headers_constants(self):
        """Test all gateway header constants have correct values."""
        assert GatewayHeaders.USER_ID == "X-User-Id"
        assert GatewayHeaders.USER_ROLES == "X-User-Roles"
        assert GatewayHeaders.USER_EMAIL == "X-User-Email"
        assert GatewayHeaders.USER_NAME == "X-User-Name"
        assert GatewayHeaders.SESSION_ID == "X-Session-Id"
        assert GatewayHeaders.CLIENT_TYPE == "X-Client-Type"
        assert GatewayHeaders.CLIENT_VERSION == "X-Client-Version"


class TestCurrentUserClaims:
    """Tests for CurrentUserClaims model."""

    @pytest.fixture
    def user_id(self):
        return uuid.uuid4()

    @pytest.fixture
    def current_user(self, user_id):
        return CurrentUserClaims(
            user_id=user_id,
            roles=["user", "admin"],
            email="user@example.com",
            name="Test User",
            session_id="session_123",
            client_type="web",
            client_version="1.0",
        )

    def test_current_user_claims_initialization(self, user_id, current_user):
        """Test CurrentUserClaims initialization."""
        assert current_user.user_id == user_id
        assert current_user.roles == ["user", "admin"]
        assert current_user.email == "user@example.com"
        assert current_user.name == "Test User"
        assert current_user.session_id == "session_123"
        assert current_user.client_type == "web"
        assert current_user.client_version == "1.0"

    def test_has_role_true(self, current_user):
        """Test has_role returns True for existing role."""
        assert current_user.has_role("admin") is True
        assert current_user.has_role("user") is True

    def test_has_role_false(self, current_user):
        """Test has_role returns False for non-existing role."""
        assert current_user.has_role("superadmin") is False
        assert current_user.has_role("moderator") is False

    def test_has_any_role_true(self, current_user):
        """Test has_any_role returns True when any role matches."""
        assert current_user.has_any_role(["admin", "moderator"]) is True
        assert current_user.has_any_role(["superadmin", "user"]) is True

    def test_has_any_role_false(self, current_user):
        """Test has_any_role returns False when no roles match."""
        assert current_user.has_any_role(["superadmin", "moderator"]) is False

    def test_has_all_roles_true(self, current_user):
        """Test has_all_roles returns True when all roles present."""
        assert current_user.has_all_roles(["user", "admin"]) is True

    def test_has_all_roles_false(self, current_user):
        """Test has_all_roles returns False when any role missing."""
        assert current_user.has_all_roles(["user", "superadmin"]) is False

    def test_is_admin_true(self, current_user):
        """Test is_admin returns True for admin role."""
        assert current_user.is_admin() is True

    def test_is_admin_false(self, user_id):
        """Test is_admin returns False without admin role."""
        user = CurrentUserClaims(user_id=user_id, roles=["user"])
        assert user.is_admin() is False

    def test_dict_method(self, user_id, current_user):
        """Test dict() returns correct dictionary."""
        result = current_user.dict()
        assert result["user_id"] == user_id
        assert result["roles"] == ["user", "admin"]
        assert result["email"] == "user@example.com"


class TestCurrentUserClaimsOptional:
    """Tests for CurrentUserClaimsOptional model."""

    def test_authenticated_user(self):
        """Test authenticated user."""
        user_id = uuid.uuid4()
        user = CurrentUserClaimsOptional(
            user_id=user_id,
            roles=["user"],
            is_authenticated=True,
        )
        assert user.user_id == user_id
        assert user.is_authenticated is True

    def test_unauthenticated_user(self):
        """Test unauthenticated user."""
        user = CurrentUserClaimsOptional(
            user_id=None,
            roles=[],
            is_authenticated=False,
        )
        assert user.user_id is None
        assert user.is_authenticated is False

    def test_from_claims(self):
        """Test from_claims factory method."""
        claims = CurrentUserClaims(
            user_id=uuid.uuid4(),
            roles=["admin"],
        )
        optional = CurrentUserClaimsOptional.from_claims(claims)
        assert optional.user_id == claims.user_id
        assert optional.roles == claims.roles
        assert optional.is_authenticated is True


class TestGatewayUser:
    """Tests for GatewayUser class."""

    def test_gateway_user_initialization(self):
        """Test GatewayUser initialization."""
        user_id = uuid.uuid4()
        user = GatewayUser(
            id=user_id,
            email="user@example.com",
            roles=["user", "admin"],
        )
        assert user.id == user_id
        assert user.email == "user@example.com"
        assert user.roles == ["user", "admin"]
        assert user.is_active is True

    def test_gateway_user_default_roles(self):
        """Test GatewayUser default roles."""
        user_id = uuid.uuid4()
        user = GatewayUser(id=user_id)
        assert user.roles == ["user"]

    def test_gateway_user_is_superuser_true(self):
        """Test is_superuser returns True for admin role."""
        user = GatewayUser(id=uuid.uuid4(), roles=["admin"])
        assert user.is_superuser is True

    def test_gateway_user_is_superuser_false(self):
        """Test is_superuser returns False without admin role."""
        user = GatewayUser(id=uuid.uuid4(), roles=["user"])
        assert user.is_superuser is False

    def test_gateway_user_str(self):
        """Test __str__ method."""
        user_id = uuid.uuid4()
        user = GatewayUser(id=user_id, email="test@test.com", roles=["user"])
        assert str(user_id) in str(user)
        assert "test@test.com" in str(user)


class TestGetCurrentUserClaimsRequired:
    """Tests for get_current_user_claims_required dependency."""

    @pytest.fixture
    def user_id(self):
        return uuid.uuid4()

    @pytest.mark.asyncio
    async def test_get_current_user_claims_required_success(self, user_id):
        """Test successful extraction of user claims."""
        request = MagicMock(spec=Request)
        request.headers = {
            GatewayHeaders.USER_ID: str(user_id),
            GatewayHeaders.USER_ROLES: "user,admin",
            GatewayHeaders.USER_EMAIL: "user@example.com",
            GatewayHeaders.USER_NAME: "Test User",
            GatewayHeaders.SESSION_ID: "session_123",
            GatewayHeaders.CLIENT_TYPE: "web",
            GatewayHeaders.CLIENT_VERSION: "1.0",
        }

        result = await get_current_user_claims_required(request)

        assert result.user_id == user_id
        assert result.roles == ["user", "admin"]
        assert result.email == "user@example.com"
        assert result.name == "Test User"
        assert result.session_id == "session_123"

    @pytest.mark.asyncio
    async def test_get_current_user_claims_required_missing_header(self):
        """Test missing X-User-Id header raises 401."""
        request = MagicMock(spec=Request)
        request.headers = {}

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_claims_required(request)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_get_current_user_claims_required_invalid_uuid(self):
        """Test invalid UUID format raises 401."""
        request = MagicMock(spec=Request)
        request.headers = {GatewayHeaders.USER_ID: "not-a-uuid"}

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_claims_required(request)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_get_current_user_claims_required_empty_roles(self, user_id):
        """Test empty roles are parsed as empty list."""
        request = MagicMock(spec=Request)
        request.headers = {GatewayHeaders.USER_ID: str(user_id)}

        result = await get_current_user_claims_required(request)

        assert result.roles == []

    @pytest.mark.asyncio
    async def test_get_current_user_claims_required_roles_with_spaces(self, user_id):
        """Test roles with spaces are properly stripped."""
        request = MagicMock(spec=Request)
        request.headers = {
            GatewayHeaders.USER_ID: str(user_id),
            GatewayHeaders.USER_ROLES: " user , admin , moderator ",
        }

        result = await get_current_user_claims_required(request)

        assert result.roles == ["user", "admin", "moderator"]


class TestGetCurrentUserClaimsOptional:
    """Tests for get_current_user_claims_optional dependency."""

    @pytest.mark.asyncio
    async def test_get_current_user_claims_optional_success(self):
        """Test successful extraction returns CurrentUserClaimsOptional."""
        user_id = uuid.uuid4()
        request = MagicMock(spec=Request)
        request.headers = {GatewayHeaders.USER_ID: str(user_id)}

        result = await get_current_user_claims_optional(request)

        assert result is not None
        assert result.user_id == user_id
        assert result.is_authenticated is True

    @pytest.mark.asyncio
    async def test_get_current_user_claims_optional_missing_header(self):
        """Test missing header returns unauthenticated."""
        request = MagicMock(spec=Request)
        request.headers = {}

        result = await get_current_user_claims_optional(request)

        assert result.user_id is None
        assert result.is_authenticated is False

    @pytest.mark.asyncio
    async def test_get_current_user_claims_optional_invalid_uuid(self):
        """Test invalid UUID returns unauthenticated."""
        request = MagicMock(spec=Request)
        request.headers = {GatewayHeaders.USER_ID: "not-a-uuid"}

        result = await get_current_user_claims_optional(request)

        assert result.is_authenticated is False


class TestGetCurrentUserFromGatewayHeaders:
    """Tests for get_current_user_from_gateway_headers dependency."""

    @pytest.mark.asyncio
    async def test_success(self):
        """Test successful extraction of GatewayUser."""
        user_id = uuid.uuid4()
        request = MagicMock(spec=Request)
        request.headers = {
            "X-User-Id": str(user_id),
            "X-User-Roles": "admin,user",
            "X-User-Email": "admin@example.com",
        }

        result = await get_current_user_from_gateway_headers(request)

        assert isinstance(result, GatewayUser)
        assert result.id == user_id
        assert result.roles == ["admin", "user"]
        assert result.email == "admin@example.com"

    @pytest.mark.asyncio
    async def test_missing_user_id(self):
        """Test missing X-User-Id raises 401."""
        request = MagicMock(spec=Request)
        request.headers = {}

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_from_gateway_headers(request)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_uuid(self):
        """Test invalid UUID raises 401."""
        request = MagicMock(spec=Request)
        request.headers = {"X-User-Id": "invalid"}

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_from_gateway_headers(request)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_default_roles(self):
        """Test default roles when X-User-Roles is missing."""
        user_id = uuid.uuid4()
        request = MagicMock(spec=Request)
        request.headers = {"X-User-Id": str(user_id)}

        result = await get_current_user_from_gateway_headers(request)

        assert result.roles == ["user"]


class TestRequireRoles:
    """Tests for require_roles factory."""

    @pytest.fixture
    def user_id(self):
        return uuid.uuid4()

    @pytest.mark.asyncio
    async def test_require_roles_success(self, user_id):
        """Test user with required role passes."""
        claims = CurrentUserClaims(user_id=user_id, roles=["admin", "user"])
        dependency = require_roles(["admin"])
        result = await dependency(claims)
        assert result == claims

    @pytest.mark.asyncio
    async def test_require_roles_forbidden(self, user_id):
        """Test user without required role raises 403."""
        claims = CurrentUserClaims(user_id=user_id, roles=["user"])
        dependency = require_roles(["admin"])

        with pytest.raises(HTTPException) as exc_info:
            await dependency(claims)

        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_require_roles_multiple_any_one(self, user_id):
        """Test user with any of required roles passes."""
        claims = CurrentUserClaims(user_id=user_id, roles=["moderator"])
        dependency = require_roles(["admin", "moderator"])
        result = await dependency(claims)
        assert result == claims


class TestRequireAllRoles:
    """Tests for require_all_roles factory."""

    @pytest.fixture
    def user_id(self):
        return uuid.uuid4()

    @pytest.mark.asyncio
    async def test_require_all_roles_success(self, user_id):
        """Test user with all required roles passes."""
        claims = CurrentUserClaims(user_id=user_id, roles=["admin", "user"])
        dependency = require_all_roles(["admin", "user"])
        result = await dependency(claims)
        assert result == claims

    @pytest.mark.asyncio
    async def test_require_all_roles_missing_one(self, user_id):
        """Test user missing one role raises 403."""
        claims = CurrentUserClaims(user_id=user_id, roles=["user"])
        dependency = require_all_roles(["admin", "user"])

        with pytest.raises(HTTPException) as exc_info:
            await dependency(claims)

        assert exc_info.value.status_code == 403


class TestRequireAdmin:
    """Tests for require_admin dependency."""

    @pytest.fixture
    def mock_user(self):
        user = MagicMock()
        user.is_superuser = True
        return user

    @pytest.fixture
    def mock_regular_user(self):
        user = MagicMock()
        user.is_superuser = False
        return user

    @pytest.mark.asyncio
    async def test_require_admin_success(self, mock_user):
        """Test admin user passes."""
        result = await require_admin(mock_user)
        assert result == mock_user

    @pytest.mark.asyncio
    async def test_require_admin_forbidden(self, mock_regular_user):
        """Test regular user raises 403."""
        with pytest.raises(HTTPException) as exc_info:
            await require_admin(mock_regular_user)

        assert exc_info.value.status_code == 403
        assert "Admin access required" in exc_info.value.detail


class TestMetadataExtractors:
    """Tests for request metadata extractor functions."""

    @pytest.mark.asyncio
    async def test_get_client_ip_from_x_forwarded_for(self):
        """Test client IP extraction from X-Forwarded-For header."""
        request = MagicMock(spec=Request)
        request.headers = {"X-Forwarded-For": "192.168.1.1, 10.0.0.1"}
        result = await get_client_ip(request)
        assert result == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_get_client_ip_from_x_real_ip(self):
        """Test client IP extraction from X-Real-IP header."""
        request = MagicMock(spec=Request)
        request.headers = {"X-Real-IP": "10.0.0.1"}
        result = await get_client_ip(request)
        assert result == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_get_client_ip_from_client(self):
        """Test client IP extraction from request.client.host."""
        request = MagicMock(spec=Request)
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        result = await get_client_ip(request)
        assert result == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_get_client_ip_unknown(self):
        """Test unknown IP fallback."""
        request = MagicMock(spec=Request)
        request.headers = {}
        request.client = None
        result = await get_client_ip(request)
        assert result == "unknown"

    @pytest.mark.asyncio
    async def test_get_user_agent(self):
        """Test user agent extraction."""
        request = MagicMock(spec=Request)
        request.headers = {"user-agent": "Mozilla/5.0"}
        result = await get_user_agent(request)
        assert result == "Mozilla/5.0"

    @pytest.mark.asyncio
    async def test_get_user_agent_missing(self):
        """Test missing user agent returns empty string."""
        request = MagicMock(spec=Request)
        request.headers = {}
        result = await get_user_agent(request)
        assert result == ""


class TestPaginationParams:
    """Tests for get_pagination_params dependency."""

    @pytest.mark.asyncio
    async def test_default_values(self):
        """Test default pagination values."""
        result = await get_pagination_params(limit=20, offset=0)
        assert result == {"limit": 20, "offset": 0}

    @pytest.mark.asyncio
    async def test_custom_values(self):
        """Test custom pagination values."""
        result = await get_pagination_params(limit=50, offset=10)
        assert result == {"limit": 50, "offset": 10}

    @pytest.mark.asyncio
    async def test_limit_capped(self):
        """Test limit is capped at 100."""
        result = await get_pagination_params(limit=200, offset=0)
        assert result == {"limit": 100, "offset": 0}

    @pytest.mark.asyncio
    async def test_offset_min_zero(self):
        """Test offset is floored at 0."""
        result = await get_pagination_params(limit=20, offset=-10)
        assert result == {"limit": 20, "offset": 0}


class TestInternalApiVerification:
    """Tests for verify_internal_api_key dependency."""

    @pytest.fixture
    def mock_request(self):
        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        return request

    @pytest.mark.asyncio
    async def test_verify_internal_api_key_success(self, mock_request):
        """Test valid API key passes."""
        with patch("app.core.dependencies.settings") as mock_settings:
            mock_settings.INTERNAL_API_KEY = "test_key"
            mock_settings.INTERNAL_ALLOWED_IPS = []
            await verify_internal_api_key(mock_request, x_internal_api_key="test_key")

    @pytest.mark.asyncio
    async def test_verify_internal_api_key_missing(self, mock_request):
        """Test missing API key raises UnauthorizedException."""
        with pytest.raises(UnauthorizedException):
            await verify_internal_api_key(mock_request, x_internal_api_key=None)

    @pytest.mark.asyncio
    async def test_verify_internal_api_key_invalid(self, mock_request):
        """Test invalid API key raises UnauthorizedException."""
        with patch("app.core.dependencies.settings") as mock_settings:
            mock_settings.INTERNAL_API_KEY = "correct_key"
            mock_settings.INTERNAL_ALLOWED_IPS = []
            with pytest.raises(UnauthorizedException):
                await verify_internal_api_key(mock_request, x_internal_api_key="wrong_key")


class TestInfrastructureFactories:
    """Tests for infrastructure factory functions."""

    @pytest.mark.asyncio
    async def test_get_user_repository(self):
        """Test get_user_repository returns UserRepository."""
        with patch("app.core.dependencies.UserRepository") as mock_repo:
            mock_repo.return_value = "repo_instance"
            result = await get_user_repository()
            assert result == "repo_instance"

    @pytest.mark.asyncio
    async def test_get_token_service(self):
        """Test get_token_service returns TokenService."""
        with patch("app.core.dependencies.TokenService") as mock_service:
            mock_service.return_value = "token_service_instance"
            result = await get_token_service(refresh_repo=MagicMock())
            assert result == "token_service_instance"