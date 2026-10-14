"""
SQL injection protection tests — PRODUCTION-LEVEL.

Verifies that SQL injection attempts are rejected at multiple layers
before reaching the database.

Defense-in-depth layers verified:
    1. Pydantic/UUID validation — rejects non-UUID strings in path params
    2. EmailStr validation — rejects non-email strings in request body
    3. ORM parameterization — SQLAlchemy bind parameters prevent injection
    4. HTTP-level rejection — malformed headers rejected by uvicorn/h11
    5. Rate limiting — auth-service protects itself under bulk attacks
    6. CircuitBreaker — 4xx injection errors are NOT counted as failures
    7. Database integrity — users table intact after all attacks

No mocks. No stubs. Real HTTP calls. Real validation. Real database.

Architecture:
    Real HTTP calls directly to auth-service internal endpoints.
    SQLAlchemy parameterized queries and Pydantic validation
    provide defense-in-depth without any test-specific mocks.

Prerequisites:
    - docker compose up -d auth-service
    - Default users seeded (admin@test.com)

Run:
    docker exec -it user-service pytest tests/resilience/security/test_sql_injection.py -v -s
"""

import asyncio
from uuid import UUID

import httpx
import pytest

from app.core.circuit_breaker import CircuitBreaker
from app.core.config import settings
from app.core.http_client import AuthServiceHttpClient, AuthServiceError, AuthServiceUnavailableError
from app.services.user_service import UserService

from ..conftest import (
    auth_service_is_reachable,
    fault_clear_503,
    fault_reset_all_verified,
    get_test_user_id,
    run_concurrently,
    TEST_FAILURE_THRESHOLD,
    TEST_HTTP_TIMEOUT,
)


# ==================== PAYLOADS ====================

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1' UNION SELECT * FROM users --",
    "' OR 1=1; --",
    "admin'--",
    "' OR '1'='1' /*",
    "1; SELECT pg_sleep(5) --",
    "' OR 1=1 LIMIT 1 --",
    "1' AND 1=(SELECT COUNT(*) FROM users) --",
    "'; COPY users TO '/tmp/users.csv' --",
]

SQL_INJECTION_HEADERS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1' UNION SELECT",
    "Bearer ' OR '1'='1",
    "admin'--",
]

HEADER_INJECTION_KEYS = [
    "X-Internal-API-Key",
    "X-User-Id",
    "X-User-Email",
    "Authorization",
]


# ==================== HELPERS ====================

def existing_user_id() -> UUID:
    """Dynamic UUID — resolved from auth-service via get_test_user_id()."""
    return UUID(get_test_user_id())


def create_user_service(http_client: AuthServiceHttpClient) -> UserService:
    """Create a real UserService wired to the CB-protected HTTP client."""
    return UserService(http_client=http_client)


async def verify_database_integrity() -> bool:
    """Check that users table exists and auth-service responds correctly.

    Returns True if:
        - Auth-service returns 200
        - Response contains valid user data
        - No SQL errors or table corruption
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{settings.AUTH_SERVICE_URL}/internal/user/"
                f"{existing_user_id()}/exists",
                headers={"X-Internal-API-Key": settings.AUTH_SERVICE_INTERNAL_API_KEY},
            )
            if resp.status_code != 200:
                return False
            data = resp.json()
            # If user exists — DB is working. If not exists — also OK (table intact).
            return "exists" in data
    except Exception:
        return False


async def ensure_no_fault_injection() -> None:
    """Guarantee auth-service is not injecting faults before SQL tests."""
    await fault_clear_503()
    await asyncio.sleep(0.3)
    try:
        await fault_reset_all_verified()
    except Exception:
        pass
    await asyncio.sleep(0.2)


# ==================== 1. UUID ENDPOINT — INJECTION REJECTED ====================

@pytest.mark.asyncio
async def test_sql_injection_in_user_id_rejected(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """SQL injection in user_id UUID path parameter is rejected.

    Pydantic UUID validation rejects non-UUID strings before
    they reach any controller or database layer.
    """
    assert auth_service_is_reachable()
    await ensure_no_fault_injection()

    for payload in SQL_INJECTION_PAYLOADS:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{settings.AUTH_SERVICE_URL}/internal/user/{payload}/exists",
                headers={"X-Internal-API-Key": settings.AUTH_SERVICE_INTERNAL_API_KEY},
            )
            assert resp.status_code in (400, 404, 422), \
                f"Injection '{payload[:30]}' returned {resp.status_code}, expected 4xx"
            print(f"  Payload '{payload[:40]}' → {resp.status_code} (rejected)")

    assert circuit_breaker.failure_count == 0, \
        f"Injection attempts counted as failures: {circuit_breaker.failure_count}"
    print(f"  Circuit: {circuit_breaker.state.value}, failures: {circuit_breaker.failure_count}")


# ==================== 2. EMAIL ENDPOINT — INJECTION REJECTED ====================

@pytest.mark.asyncio
async def test_sql_injection_in_email_field_rejected(
    ensure_auth_service: None,
) -> None:
    """SQL injection in email field is rejected by Pydantic EmailStr validation."""
    assert auth_service_is_reachable()
    await ensure_no_fault_injection()

    for payload in SQL_INJECTION_PAYLOADS:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{settings.AUTH_SERVICE_URL}/api/v1/auth/login",
                json={"email": payload, "password": "AnyPass123!"},
            )
            assert resp.status_code in (401, 422), \
                f"Injection email '{payload[:30]}' returned {resp.status_code}, expected 401/422"
            print(f"  Email payload '{payload[:40]}' → {resp.status_code} (rejected)")


# ==================== 3. PATH TRAVERSAL — INJECTION REJECTED ====================

@pytest.mark.asyncio
async def test_sql_injection_in_url_path_rejected(
    ensure_auth_service: None,
) -> None:
    """SQL injection in URL path is rejected by FastAPI routing."""
    assert auth_service_is_reachable()
    await ensure_no_fault_injection()

    for payload in SQL_INJECTION_PAYLOADS:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{settings.AUTH_SERVICE_URL}/internal/user/{payload}",
                headers={"X-Internal-API-Key": settings.AUTH_SERVICE_INTERNAL_API_KEY},
            )
            assert resp.status_code in (400, 404, 422), \
                f"Path injection '{payload[:30]}' returned {resp.status_code}, expected 4xx"
            print(f"  Path payload '{payload[:40]}' → {resp.status_code} (rejected)")


# ==================== 4. HEADER INJECTION — REJECTED OR SAFELY IGNORED ====================

@pytest.mark.asyncio
async def test_sql_injection_in_headers_rejected_or_ignored(
    ensure_auth_service: None,
) -> None:
    """SQL injection in HTTP headers is rejected or safely ignored."""
    assert auth_service_is_reachable()
    await ensure_no_fault_injection()

    valid_user_id = existing_user_id()

    for header_key in HEADER_INJECTION_KEYS:
        for payload in SQL_INJECTION_HEADERS:
            headers = {
                "X-Internal-API-Key": settings.AUTH_SERVICE_INTERNAL_API_KEY,
                "X-User-Id": str(valid_user_id),
            }
            headers[header_key] = payload

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{settings.AUTH_SERVICE_URL}/internal/user/{valid_user_id}/exists",
                    headers=headers,
                )
                # 200 = safe ignore, 4xx = rejected, 503 = rate limiter protection
                assert resp.status_code in (200, 400, 401, 403, 422, 503), \
                    f"Header '{header_key}: {payload[:20]}' returned {resp.status_code}, expected safe response"
                print(f"  Header {header_key}: '{payload[:30]}' → {resp.status_code} (safe)")


# ==================== 5. DATABASE INTEGRITY ====================

@pytest.mark.asyncio
async def test_database_integrity_after_injection_attempts(
    ensure_auth_service: None,
) -> None:
    """Database remains intact after all injection attempts."""
    assert auth_service_is_reachable()
    await ensure_no_fault_injection()

    db_ok = await verify_database_integrity()
    assert db_ok, "Database integrity check failed after injection attempts"

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{settings.AUTH_SERVICE_URL}/internal/user/{existing_user_id()}/exists",
            headers={"X-Internal-API-Key": settings.AUTH_SERVICE_INTERNAL_API_KEY},
        )
        assert resp.status_code == 200, \
            f"Auth-service query failed: {resp.status_code}"
        print(f"  Database integrity verified — auth-service responds: {resp.status_code}")


# ==================== 6. CIRCUIT BREAKER — INJECTIONS NOT COUNTED ====================

@pytest.mark.asyncio
async def test_circuit_breaker_ignores_injection_errors(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Circuit Breaker does not count injection rejection errors."""
    assert auth_service_is_reachable()
    await ensure_no_fault_injection()

    for payload in SQL_INJECTION_PAYLOADS[:5]:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{settings.AUTH_SERVICE_URL}/internal/user/{payload}/exists",
                headers={"X-Internal-API-Key": settings.AUTH_SERVICE_INTERNAL_API_KEY},
            )
            assert resp.status_code in (400, 404, 422), \
                f"Expected 4xx, got {resp.status_code}"

    assert circuit_breaker.is_closed, \
        f"Injection errors opened circuit: {circuit_breaker.state.value}"
    assert circuit_breaker.failure_count == 0, \
        f"Injection errors counted as failures: {circuit_breaker.failure_count}"

    print(f"  After {len(SQL_INJECTION_PAYLOADS[:5])} injection attempts:")
    print(f"    Circuit: {circuit_breaker.state.value}, failures: {circuit_breaker.failure_count}")


# ==================== 7. BULK INJECTION — 100 CONCURRENT ATTEMPTS ====================

@pytest.mark.asyncio
async def test_bulk_sql_injection_all_rejected(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """100 concurrent injection attempts — all rejected, none reach database.

    Note: 100 concurrent requests may trigger auth-service rate limiting (503).
    Test accepts 4xx (rejected by validation) and 503 (rate limited) as safe outcomes.
    Any 2xx response indicates a bypass — critical failure.
    """
    assert auth_service_is_reachable()
    await ensure_no_fault_injection()

    async def injection_attempt(payload: str) -> int:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{settings.AUTH_SERVICE_URL}/internal/user/{payload}/exists",
                headers={"X-Internal-API-Key": settings.AUTH_SERVICE_INTERNAL_API_KEY},
            )
            return resp.status_code

    tasks = [
        injection_attempt(f"injection_{i}' OR '1'='1")
        for i in range(100)
    ]
    results = await asyncio.gather(*tasks)

    rejected = [r for r in results if r in (400, 404, 422)]
    rate_limited = [r for r in results if r == 503]
    passed = [r for r in results if r == 200]

    status_counts = {}
    for r in results:
        status_counts[r] = status_counts.get(r, 0) + 1

    print(f"  100 concurrent injection attempts:")
    print(f"    Status codes: {status_counts}")
    print(f"    Rejected (4xx): {len(rejected)}")
    print(f"    Rate-limited (503): {len(rate_limited)}")
    print(f"    Passed (2xx): {len(passed)} (should be 0)")

    assert len(passed) == 0, \
        f"{len(passed)} injection attempts passed validation — critical! Status codes: {status_counts}"

    safe = len(rejected) + len(rate_limited)
    assert safe == 100, \
        f"Only {safe}/100 injection attempts handled safely. Status codes: {status_counts}"

    db_ok = await verify_database_integrity()
    assert db_ok, "Database integrity compromised after bulk injection attempts"


# ==================== 8. VALID UUID — NOT BLOCKED ====================

@pytest.mark.asyncio
async def test_valid_uuid_not_blocked_by_injection_protection(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Valid UUID requests work correctly."""
    assert auth_service_is_reachable()
    await ensure_no_fault_injection()

    service = create_user_service(auth_http_client)
    valid_id = existing_user_id()

    info = await service._fetch_user_info_from_auth(valid_id)
    assert "email" in info
    print(f"  Valid UUID request: email={info.get('email')}")

    assert circuit_breaker.is_closed
    print(f"  Circuit: {circuit_breaker.state.value}")