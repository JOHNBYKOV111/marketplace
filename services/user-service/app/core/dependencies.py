"""
Application dependencies for FastAPI dependency injection.
"""

from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, status
import jwt

from app.core.config import settings
from app.core.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from app.core.http_client import AuthServiceHttpClient
from app.services.user_service import UserService
from app.core.database import get_db


async def get_current_user_id(
    x_user_id: UUID | None = Header(None, alias="X-User-Id"),
) -> UUID:
    """
    Extract and validate the current user ID from API Gateway headers.

    Returns 401 if header is missing, 422 if invalid UUID format.
    """
    if x_user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    return x_user_id


async def get_current_user_from_jwt(
    authorization: str = Header(..., alias="Authorization"),
) -> UUID:
    """
    Extract user ID from JWT Bearer token.

    Validates token signature and expiration.
    Returns user_id from 'sub' claim.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format",
        )

    token = authorization.split("Bearer ")[1].strip()

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        user_id = UUID(payload["sub"])
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


async def require_admin(
    request: Request,
    x_user_roles: str | None = Header(None, alias="X-User-Roles"),
) -> None:
    """
    Verify the request has admin role.

    Priority:
    1. If X-User-Roles header present (Gateway mode), use it.
    2. If Authorization header present (JWT mode), decode token and check is_superuser.
    Returns 401 if no auth, 403 if user lacks admin role.
    """
    # Gateway mode: X-User-Roles header
    if x_user_roles and x_user_roles.strip():
        roles = [role.strip().lower() for role in x_user_roles.split(",") if role.strip()]
        if "admin" in roles:
            return
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    # JWT mode: Authorization header
    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1].strip()
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
            )
            if payload.get("is_superuser") or "admin" in payload.get("roles", []):
                return
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
    )


# ==================== CIRCUIT BREAKER & HTTP CLIENT ====================

_circuit_breaker: CircuitBreaker | None = None
_auth_http_client: AuthServiceHttpClient | None = None


def _build_circuit_breaker_config() -> CircuitBreakerConfig:
    """Build CircuitBreakerConfig from application settings."""
    return CircuitBreakerConfig(
        failure_threshold=settings.CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        recovery_timeout=settings.CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
        half_open_max_requests=settings.CIRCUIT_BREAKER_HALF_OPEN_MAX_REQUESTS,
        success_threshold=settings.CIRCUIT_BREAKER_SUCCESS_THRESHOLD,
        excluded_status_codes=set(settings.CIRCUIT_BREAKER_EXCLUDED_STATUS_CODES),
        failure_status_codes=set(settings.CIRCUIT_BREAKER_FAILURE_STATUS_CODES),
    )


async def get_circuit_breaker() -> CircuitBreaker:
    """Dependency injection for CircuitBreaker — singleton per process."""
    global _circuit_breaker
    if _circuit_breaker is None:
        config = _build_circuit_breaker_config()
        _circuit_breaker = CircuitBreaker(config)
    return _circuit_breaker


async def get_auth_http_client(
    circuit_breaker: CircuitBreaker = Depends(get_circuit_breaker),
) -> AuthServiceHttpClient:
    """Dependency injection for AuthServiceHttpClient — singleton per process."""
    global _auth_http_client
    if _auth_http_client is None:
        _auth_http_client = AuthServiceHttpClient(
            base_url=settings.AUTH_SERVICE_URL,
            api_key=settings.AUTH_SERVICE_INTERNAL_API_KEY,
            timeout=settings.AUTH_SERVICE_TIMEOUT,
            max_connections=settings.AUTH_SERVICE_MAX_CONNECTIONS,
            keepalive=settings.AUTH_SERVICE_KEEPALIVE,
            circuit_breaker=circuit_breaker if settings.CIRCUIT_BREAKER_ENABLED else None,
        )
    return _auth_http_client


# ==================== USER SERVICE ====================

async def get_user_service(
    db=Depends(get_db),
    http_client: AuthServiceHttpClient = Depends(get_auth_http_client),
) -> UserService:
    """Dependency injection for UserService with Circuit-Breaker-protected HTTP client."""
    from app.repositories.user_repository import UserRepository
    from app.repositories.audit_log_repository import AuditLogRepository

    user_repo = UserRepository(db)
    audit_repo = AuditLogRepository(db)
    return UserService(
        db=db,
        user_repo=user_repo,
        audit_repo=audit_repo,
        http_client=http_client,
    )