"""
Зависимости FastAPI для извлечения данных из запросов.

Обеспечивает:
- Извлечение текущего пользователя из request.state
- Проверку ролей (админ, пользователь)
- Валидацию токенов и сессий
- Кэширование результатов
- Логирование доступа
- Фабрики для всех сервисов
- Gateway-зависимости для работы с заголовками
- Поддержку асинхронных контекстов
- Декораторы для проверки прав

Совместимость с тестами MFA:
- TestMFAAuthorization::test_mfa_endpoints_require_auth — проверка 401 без заголовков
- Все позитивные тесты MFA — используют заголовки X-User-Id, X-User-Roles, X-User-Email
- Зависимость get_current_user_from_gateway_headers() извлекает пользователя из заголовков
  и возвращает User-like объект для использования в MFA роутере

Совместимость с тестами OAuth:
- setup_oauth_test_environment: мокает get_oauth_service и get_auth_service_for_oauth
- Фабрики get_oauth_service() и get_auth_service_for_oauth() используются в роутере
  и подменяются через app.dependency_overrides в тестах

Совместимость с тестами Password:
- setup_password_test_environment: мокает get_auth_service, get_rate_limit_service
- Использует реальный get_password_service (криптография)
- Зависимость get_current_user_from_gateway_headers используется для авторизации

Связанные модули:
- app.routers.mfa — использует get_current_user_from_gateway_headers
- app.routers.oauth — использует get_oauth_service, get_auth_service_for_oauth
- app.routers.password — использует get_auth_service, get_password_service, get_rate_limit_service
- app.core.headers — GatewayHeaders, HeaderParser
- app.schemas.claims — CurrentUserClaims
"""

import ipaddress
from typing import Optional, Annotated, Any, List, Callable, Dict, Union
from uuid import UUID
from functools import wraps
import asyncio

from fastapi import Depends, HTTPException, Request, status, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.exceptions import AuthenticationError, AuthorizationError, UnauthorizedException, ForbiddenException
from app.core.headers import GatewayHeaders, HeaderParser
from app.core.logging import get_logger
from app.core.security import decode_token, extract_jwt_from_header
from app.core.metrics import token_metrics, http_metrics
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_security_settings_repository import UserSecuritySettingsRepository
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.jwk_key_repository import JWKKeyRepository
from app.schemas.claims import CurrentUserClaims, CurrentUserClaimsOptional
from app.services.auth_service import AuthService
from app.services.token_service import TokenService
from app.services.password_service import PasswordService
from app.services.totp_service import TOTPService
from app.services.audit_service import AuditService
from app.services.admin_service import AdminService
from app.services.metrics_service import MetricsService
from app.services.user_security_service import UserSecurityService
from app.services.jwk_service import JWKService

logger = get_logger(__name__)


# ==================== ФАБРИКИ ДЛЯ РЕПОЗИТОРИЕВ ====================

async def get_user_repository(
    session: AsyncSession = Depends(get_db),
) -> UserRepository:
    """Фабрика для UserRepository."""
    return UserRepository(session)


async def get_refresh_token_repository(
    session: AsyncSession = Depends(get_db),
) -> RefreshTokenRepository:
    """Фабрика для RefreshTokenRepository."""
    return RefreshTokenRepository(session)


async def get_user_security_settings_repository(
    session: AsyncSession = Depends(get_db),
) -> UserSecuritySettingsRepository:
    """Фабрика для UserSecuritySettingsRepository."""
    return UserSecuritySettingsRepository(session)


async def get_audit_log_repository(
    session: AsyncSession = Depends(get_db),
) -> AuditLogRepository:
    """Фабрика для AuditLogRepository."""
    return AuditLogRepository(session)


async def get_jwk_key_repository(
    session: AsyncSession = Depends(get_db),
) -> JWKKeyRepository:
    """Фабрика для JWKKeyRepository."""
    return JWKKeyRepository(session)


# ==================== ФАБРИКИ ДЛЯ СЕРВИСОВ ====================

async def get_token_service(
    refresh_repo: Annotated[Any, Depends(get_refresh_token_repository)],
) -> TokenService:
    """Фабрика для TokenService."""
    return TokenService(refresh_repo=refresh_repo, redis_client=None)


async def get_password_service(
    user_repo: Annotated[Any, Depends(get_user_repository)],
) -> PasswordService:
    """Фабрика для PasswordService."""
    return PasswordService(user_repo=user_repo)


async def get_totp_service() -> TOTPService:
    """Фабрика для TOTPService."""
    return TOTPService()


async def get_audit_service(
    session: AsyncSession = Depends(get_db),
) -> AuditService:
    """Фабрика для AuditService."""
    return AuditService(session)


async def get_user_security_service(
    session: AsyncSession = Depends(get_db),
) -> UserSecurityService:
    """Фабрика для UserSecurityService."""
    return UserSecurityService(session=session)


async def get_auth_service(
    session: Annotated[AsyncSession, Depends(get_db)],
    user_repo: Annotated[Any, Depends(get_user_repository)],
    refresh_repo: Annotated[Any, Depends(get_refresh_token_repository)],
    settings_repo: Annotated[Any, Depends(get_user_security_settings_repository)],
    totp_service: Annotated[TOTPService, Depends(get_totp_service)],
) -> AuthService:
    """Фабрика для AuthService."""
    return AuthService(
        session=session,
        user_repo=user_repo,
        refresh_repo=refresh_repo,
        settings_repo=settings_repo,
        totp_service=totp_service,
    )


async def get_admin_service(
    session: AsyncSession = Depends(get_db),
) -> AdminService:
    """Фабрика для AdminService."""
    return AdminService(session)


async def get_metrics_service(
    session: AsyncSession = Depends(get_db),
) -> MetricsService:
    """Фабрика для MetricsService."""
    return MetricsService(session)


async def get_jwk_service(
    jwk_repo: Annotated[JWKKeyRepository, Depends(get_jwk_key_repository)],
) -> JWKService:
    """Фабрика для JWKService."""
    return JWKService(jwk_repo)


# ==================== OAUTH ФАБРИКИ ====================

async def get_oauth_service() -> Any:
    from app.services.oauth_service import oauth_service
    return oauth_service


async def get_auth_service_for_oauth(
    session: Annotated[AsyncSession, Depends(get_db)],
    user_repo: Annotated[Any, Depends(get_user_repository)],
    refresh_repo: Annotated[Any, Depends(get_refresh_token_repository)],
) -> AuthService:
    from app.services.auth_service import AuthService
    from app.services.totp_service import TOTPService

    return AuthService(
        session=session,
        user_repo=user_repo,
        refresh_repo=refresh_repo,
        settings_repo=None,
        totp_service=TOTPService(),
    )


# ==================== PASSWORD ФАБРИКИ ====================

async def get_password_service_for_password_router() -> PasswordService:
    return PasswordService()


async def get_auth_service_for_password_router(
    session: Annotated[AsyncSession, Depends(get_db)],
    user_repo: Annotated[Any, Depends(get_user_repository)],
    refresh_repo: Annotated[Any, Depends(get_refresh_token_repository)],
) -> AuthService:
    from app.services.auth_service import AuthService
    from app.services.totp_service import TOTPService

    return AuthService(
        session=session,
        user_repo=user_repo,
        refresh_repo=refresh_repo,
        settings_repo=None,
        totp_service=TOTPService(),
    )


async def get_rate_limit_service_for_password_router() -> Any:
    from app.services.rate_limit_service import RateLimitService
    return RateLimitService()


# ==================== КЭШИРОВАНИЕ ПОЛЬЗОВАТЕЛЕЙ ====================

_user_cache: Dict[UUID, User] = {}
_cache_ttl: Dict[UUID, float] = {}
CACHE_TTL = 60


async def get_cached_user(
    user_id: UUID,
    user_repo: UserRepository,
    force_refresh: bool = False,
) -> Optional[User]:
    import time

    now = time.time()

    if not force_refresh and user_id in _user_cache:
        if now - _cache_ttl.get(user_id, 0) < CACHE_TTL:
            logger.debug(f"Cache hit for user {user_id}")
            return _user_cache[user_id]

    user = await user_repo.get_by_id(user_id)
    if user:
        _user_cache[user_id] = user
        _cache_ttl[user_id] = now
        logger.debug(f"Cached user {user_id}")
    else:
        _user_cache[user_id] = None
        _cache_ttl[user_id] = now

    return user


def clear_user_cache(user_id: Optional[UUID] = None) -> None:
    if user_id:
        _user_cache.pop(user_id, None)
        _cache_ttl.pop(user_id, None)
        logger.debug(f"Cleared cache for user {user_id}")
    else:
        _user_cache.clear()
        _cache_ttl.clear()
        logger.debug("Cleared all user cache")


# ==================== КОНТЕКСТ ПОЛЬЗОВАТЕЛЯ ====================

class UserContext:
    def __init__(
        self,
        user_id: UUID,
        user: Optional[User] = None,
        role: str = "user",
        is_authenticated: bool = True,
        is_admin: bool = False,
        email: Optional[str] = None,
        session_id: Optional[str] = None,
        client_type: str = "unknown",
        source: str = "token",
    ):
        self.user_id = user_id
        self.user = user
        self.role = role
        self.is_authenticated = is_authenticated
        self.is_admin = is_admin
        self.email = email
        self.session_id = session_id
        self.client_type = client_type
        self.source = source
        self._permissions_cache: Optional[set] = None

    @classmethod
    async def from_token(
        cls,
        request: Request,
        user_repo: UserRepository,
        token_service: TokenService,
    ) -> "UserContext":
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            raise AuthenticationError("Missing authorization header")

        token = extract_jwt_from_header(auth_header)
        if not token:
            raise AuthenticationError("Invalid authorization header format")

        try:
            payload = await token_service.decode_token(token, "access")
            token_metrics.increment_validated("access")
        except Exception as e:
            token_metrics.increment_invalid("access")
            logger.warning(f"Token validation failed: {e}")
            raise AuthenticationError("Invalid or expired token")

        user_id_str = payload.get("sub")
        if not user_id_str:
            raise AuthenticationError("Invalid token: missing subject")

        try:
            user_id = UUID(user_id_str)
        except ValueError:
            raise AuthenticationError("Invalid token: invalid subject format")

        user = await get_cached_user(user_id, user_repo)

        if not user:
            logger.warning(f"User not found for token: {user_id}")
            raise AuthenticationError("User not found")

        if not user.is_active:
            logger.warning(f"User is blocked: {user_id}")
            raise AuthorizationError("User account is blocked")

        role = "admin" if user.is_superuser else "user"

        return cls(
            user_id=user_id,
            user=user,
            role=role,
            is_authenticated=True,
            is_admin=user.is_superuser,
            email=user.email,
        )

    @classmethod
    async def from_gateway(
        cls,
        request: Request,
        user_repo: UserRepository,
    ) -> "UserContext":
        user_id = HeaderParser.get_user_id(request)
        if not user_id:
            raise AuthenticationError("Missing user ID header")

        user = await user_repo.get_by_id(user_id)

        if not user:
            logger.warning(f"User not found from gateway: {user_id}")
            raise AuthenticationError("User not found")

        if not user.is_active:
            logger.warning(f"User is blocked: {user_id}")
            raise AuthorizationError("User account is blocked")

        roles = HeaderParser.get_user_roles(request)
        is_admin = "admin" in roles or user.is_superuser

        return cls(
            user_id=user_id,
            user=user,
            role="admin" if is_admin else "user",
            is_authenticated=True,
            is_admin=is_admin,
            email=user.email,
            client_type=HeaderParser.get_client_type(request),
            session_id=request.headers.get(GatewayHeaders.SESSION_ID),
            source="gateway",
        )

    def has_permission(self, permission: str) -> bool:
        if self.is_admin:
            return True
        if self._permissions_cache is None:
            if self.user and hasattr(self.user, 'permissions'):
                self._permissions_cache = set(self.user.permissions)
            else:
                self._permissions_cache = set()
        return permission in self._permissions_cache

    def has_role(self, role: str) -> bool:
        if self.is_admin:
            return True
        return self.role == role


# ==================== ОСНОВНЫЕ ЗАВИСИМОСТИ ====================

async def get_current_user_context(
    request: Request,
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
) -> UserContext:
    start_time = asyncio.get_event_loop().time()

    try:
        auth_header = request.headers.get("Authorization")
        gateway_user_id = request.headers.get(GatewayHeaders.USER_ID)

        if auth_header and auth_header.startswith("Bearer "):
            context = await UserContext.from_token(request, user_repo, token_service)
            logger.debug(f"User {context.user_id} authenticated via token")
        elif gateway_user_id:
            context = await UserContext.from_gateway(request, user_repo)
            logger.debug(f"User {context.user_id} authenticated via gateway")
        else:
            raise AuthenticationError("Authentication required")

        request.state.user_context = context
        request.state.user_id = context.user_id
        request.state.user_role = context.role
        request.state.is_admin = context.is_admin
        request.state.user_email = context.email

        duration = asyncio.get_event_loop().time() - start_time
        http_metrics.requests_duration.observe(duration, {"path": request.url.path})

        return context

    except AuthenticationError as e:
        token_metrics.increment_invalid("authentication")
        logger.warning(f"Authentication failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

    except AuthorizationError as e:
        logger.warning(f"Authorization failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )


async def get_current_user_id(request: Request) -> UUID:
    user_id = getattr(request.state, "user_id", None)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user_id


async def get_current_user_role(request: Request) -> str:
    user_role = getattr(request.state, "user_role", None)
    if user_role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user_role


async def get_current_user(
    context: Annotated[UserContext, Depends(get_current_user_context)],
) -> User:
    if not context.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return context.user


async def get_current_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


async def get_current_superuser(
    context: Annotated[UserContext, Depends(get_current_user_context)],
) -> User:
    if not context.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required",
        )
    if not context.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return context.user


async def get_optional_user_context(
    request: Request,
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
) -> Optional[UserContext]:
    try:
        return await get_current_user_context(request, user_repo, token_service)
    except HTTPException:
        return None


async def get_current_user_optional(
    request: Request,
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
) -> Optional[User]:
    try:
        context = await get_current_user_context(request, user_repo, token_service)
        return context.user
    except HTTPException:
        return None


async def get_refresh_token_from_request(request: Request) -> str:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing",
        )
    return refresh_token


# ==================== MFA GATEWAY-ЗАВИСИМОСТЬ ====================

class GatewayUser:
    def __init__(
        self,
        id: UUID,
        email: Optional[str] = None,
        roles: Optional[List[str]] = None,
        is_active: bool = True,
    ):
        self.id = id
        self.email = email
        self.roles = roles or ["user"]
        self.is_active = is_active

    @property
    def is_superuser(self) -> bool:
        return "admin" in self.roles

    def __str__(self) -> str:
        return f"GatewayUser(id={self.id}, email={self.email}, roles={self.roles})"


async def get_current_user_from_gateway_headers(
    request: Request,
) -> GatewayUser:
    user_id_header = request.headers.get("X-User-Id")
    roles_header = request.headers.get("X-User-Roles", "user")
    email_header = request.headers.get("X-User-Email")

    if not user_id_header:
        logger.warning("Missing X-User-Id header in request")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    try:
        user_id = UUID(user_id_header)
    except ValueError:
        logger.warning(f"Invalid UUID in X-User-Id header: {user_id_header}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    roles = [r.strip() for r in roles_header.split(",") if r.strip()] if roles_header else ["user"]

    user = GatewayUser(
        id=user_id,
        email=email_header,
        roles=roles,
        is_active=True,
    )

    logger.debug(f"Gateway user extracted: {user}")
    return user


# ==================== НОВЫЕ GATEWAY-ЗАВИСИМОСТИ ====================

async def get_current_user_claims_required(request: Request) -> CurrentUserClaims:
    user_id_header = request.headers.get(GatewayHeaders.USER_ID)
    roles_header = request.headers.get(GatewayHeaders.USER_ROLES, "")

    if not user_id_header:
        logger.warning("Missing X-User-Id header in request")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User ID header is required",
            headers={"WWW-Authenticate": "Gateway"},
        )

    try:
        user_id = UUID(user_id_header)
    except ValueError:
        logger.warning(f"Invalid UUID format in X-User-Id header: {user_id_header}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user ID format",
            headers={"WWW-Authenticate": "Gateway"},
        )

    roles = []
    if roles_header:
        roles = [r.strip() for r in roles_header.split(",") if r.strip()]

    email = request.headers.get(GatewayHeaders.USER_EMAIL)
    name = request.headers.get(GatewayHeaders.USER_NAME)
    session_id = request.headers.get(GatewayHeaders.SESSION_ID)
    client_type = request.headers.get(GatewayHeaders.CLIENT_TYPE, "unknown")
    client_version = request.headers.get(GatewayHeaders.CLIENT_VERSION)

    claims = CurrentUserClaims(
        user_id=user_id,
        roles=roles,
        email=email,
        name=name,
        session_id=session_id,
        client_type=client_type,
        client_version=client_version,
    )

    request.state.user_claims = claims
    request.state.user_id_from_gateway = user_id

    logger.info(f"User authenticated via Gateway: {user_id}, roles: {roles}")
    return claims


async def get_current_user_claims_optional(request: Request) -> CurrentUserClaimsOptional:
    user_id_header = request.headers.get(GatewayHeaders.USER_ID)

    if not user_id_header:
        return CurrentUserClaimsOptional(user_id=None, roles=[], is_authenticated=False)

    try:
        claims = await get_current_user_claims_required(request)
        return CurrentUserClaimsOptional.from_claims(claims)
    except HTTPException:
        return CurrentUserClaimsOptional(user_id=None, roles=[], is_authenticated=False)


# ==================== ДЕКОРАТОРЫ ДЛЯ ПРОВЕРКИ ПРАВ ====================

def require_roles(roles: List[str]) -> Callable:
    async def check_roles(
        claims: CurrentUserClaims = Depends(get_current_user_claims_required),
    ) -> CurrentUserClaims:
        has_required_role = claims.has_any_role(roles)
        if not has_required_role:
            logger.warning(f"User {claims.user_id} has roles {claims.roles}, but requires one of: {roles}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required roles: {', '.join(roles)}",
            )
        logger.info(f"User {claims.user_id} passed role check: {roles}")
        return claims
    return check_roles


def require_all_roles(roles: List[str]) -> Callable:
    async def check_all_roles(
        claims: CurrentUserClaims = Depends(get_current_user_claims_required),
    ) -> CurrentUserClaims:
        has_all_roles = claims.has_all_roles(roles)
        if not has_all_roles:
            logger.warning(f"User {claims.user_id} has roles {claims.roles}, but requires all of: {roles}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"All roles required: {', '.join(roles)}",
            )
        logger.info(f"User {claims.user_id} passed all roles check: {roles}")
        return claims
    return check_all_roles


def require_any_permission(permissions: List[str]) -> Callable:
    async def check_permissions(
        context: UserContext = Depends(get_current_user_context),
    ) -> UserContext:
        for permission in permissions:
            if context.has_permission(permission):
                logger.debug(f"User {context.user_id} has permission: {permission}")
                return context
        logger.warning(f"User {context.user_id} lacks required permissions: {permissions}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Required permissions: {', '.join(permissions)}",
        )
    return check_permissions


# ==================== INTERNAL API ЗАВИСИМОСТИ ====================

def _ip_allowed(client_ip: str, allowed_ips: list) -> bool:
    """Check if client_ip is in the allowed list, supporting CIDR notation."""
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    for allowed in allowed_ips:
        try:
            if "/" in allowed:
                if ip in ipaddress.ip_network(allowed, strict=False):
                    return True
            else:
                if ip == ipaddress.ip_address(allowed):
                    return True
        except ValueError:
            continue

    return False


async def verify_internal_api_key(
    request: Request,
    x_internal_api_key: Optional[str] = Header(None, alias="X-Internal-API-Key"),
) -> None:
    if not x_internal_api_key:
        raise UnauthorizedException("Internal API key required")
    if x_internal_api_key != settings.INTERNAL_API_KEY:
        raise UnauthorizedException("Invalid internal API key")
    if settings.INTERNAL_ALLOWED_IPS:
        client_ip = request.client.host if request.client else None
        if client_ip and not _ip_allowed(client_ip, settings.INTERNAL_ALLOWED_IPS):
            raise ForbiddenException(f"IP {client_ip} not allowed for internal API")
    logger.debug(f"Internal API authenticated from {request.client.host if request.client else 'unknown'}")


# ==================== JWKS ЗАВИСИМОСТИ ====================

async def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


# ==================== ВСПОМОГАТЕЛЬНЫЕ ЗАВИСИМОСТИ ====================

async def get_pagination_params(limit: int = 20, offset: int = 0) -> Dict[str, int]:
    return {"limit": min(limit, 100), "offset": max(offset, 0)}


async def get_user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")


async def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"


__all__ = [
    "get_user_repository",
    "get_refresh_token_repository",
    "get_user_security_settings_repository",
    "get_audit_log_repository",
    "get_jwk_key_repository",
    "get_token_service",
    "get_password_service",
    "get_totp_service",
    "get_audit_service",
    "get_user_security_service",
    "get_auth_service",
    "get_admin_service",
    "get_metrics_service",
    "get_jwk_service",
    "get_oauth_service",
    "get_auth_service_for_oauth",
    "get_password_service_for_password_router",
    "get_auth_service_for_password_router",
    "get_rate_limit_service_for_password_router",
    "get_cached_user",
    "clear_user_cache",
    "UserContext",
    "get_current_user_context",
    "get_current_user_id",
    "get_current_user_role",
    "get_current_user",
    "get_current_admin",
    "get_current_superuser",
    "get_optional_user_context",
    "get_current_user_optional",
    "get_refresh_token_from_request",
    "GatewayUser",
    "get_current_user_from_gateway_headers",
    "get_current_user_claims_required",
    "get_current_user_claims_optional",
    "require_roles",
    "require_all_roles",
    "require_any_permission",
    "verify_internal_api_key",
    "require_admin",
    "get_pagination_params",
    "get_user_agent",
    "get_client_ip",
]