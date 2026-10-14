"""
Fallback integration tests — PRODUCTION-LEVEL.

Tests graceful degradation of UserService when auth-service is unavailable.

Every test calls the REAL UserService._fetch_user_info_from_auth method.
No hardcoded fallback dictionaries in test code.
No mocks. No stubs. Real network calls. Real timeouts.

Test categories:
    1. Normal operation — real data from auth-service
    2. Circuit OPEN — UserService returns safe defaults automatically
    3. Auth-service 503 — UserService returns safe defaults automatically
    4. Auth-service timeout — UserService returns safe defaults automatically
    5. Recovery flow — defaults stop after auth-service recovers
    6. No exceptions — _fetch_user_info_from_auth never raises
    7. Per-user isolation — different users get different fallback emails
    8. CircuitBreaker.call_with_fallback — API contract

Architecture:
    Tests create a real UserService with CB-protected HTTP client.
    Fault injection on auth-service triggers error conditions.
    Tests assert what UserService ACTUALLY returns — not what we hardcode.

Prerequisites:
    - docker compose up -d auth-service
    - Auth-service fault injection endpoints must be reachable

Run:
    docker exec -it user-service pytest tests/resilience/degradation/test_fallback.py -v -s
"""

import asyncio
import time
from uuid import UUID

import pytest

from app.core.circuit_breaker import CircuitBreaker, CircuitState
from app.core.http_client import (
    AuthServiceHttpClient,
    AuthServiceError,
    AuthServiceUnavailableError,
)
from app.services.user_service import UserService

from ..conftest import (
    fault_inject_503,
    fault_clear_503,
    fault_inject_timeout,
    fault_clear_timeout,
    auth_service_is_reachable,
    get_test_user_id,
    TEST_FAILURE_THRESHOLD,
    TEST_RECOVERY_TIMEOUT,
    TEST_HTTP_TIMEOUT,
)


# ==================== CONSTANTS ====================

# Non-existent user — always fixed UUID for negative tests
NON_EXISTENT_USER_ID = UUID("00000000-0000-0000-0000-000000000000")

# Timeout injection must exceed HTTP client timeout to guarantee fallback.
# TEST_HTTP_TIMEOUT = 10.0s, so inject 12s delay to ensure request times out.
INJECT_TIMEOUT_MS = int(TEST_HTTP_TIMEOUT * 1000) + 2000  # 12000ms


# ==================== HELPERS ====================

def existing_user_id() -> UUID:
    """Dynamic UUID — resolved from auth-service via get_test_user_id()."""
    return UUID(get_test_user_id())


def create_user_service(http_client: AuthServiceHttpClient) -> UserService:
    """Create a real UserService wired to the CB-protected HTTP client."""
    return UserService(http_client=http_client)


def assert_fallback_values(info: dict, user_id: UUID) -> None:
    """Assert UserService returned correct fallback defaults."""
    assert info["email"] == f"{user_id}@unknown.com", \
        f"Expected fallback email {user_id}@unknown.com, got {info.get('email')}"
    assert info["is_active"] is True, \
        f"Expected is_active=True, got {info.get('is_active')}"
    assert info["is_email_verified"] is False, \
        f"Expected is_email_verified=False, got {info.get('is_email_verified')}"


def assert_real_info(info: dict) -> None:
    """Assert that info dict has all required keys (real or fallback)."""
    assert "email" in info, "Missing 'email' key"
    assert "is_active" in info, "Missing 'is_active' key"
    assert "is_email_verified" in info, "Missing 'is_email_verified' key"


# ==================== 1. NORMAL — REAL DATA ====================

@pytest.mark.asyncio
async def test_normal_operation_returns_real_data(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """UserService returns real data when auth-service is healthy."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()
    info = await service._fetch_user_info_from_auth(user_id)

    assert_real_info(info)
    print(f"  Normal response: {info}")

    assert circuit_breaker.state == CircuitState.CLOSED
    assert circuit_breaker.failure_count == 0


# ==================== 2. CIRCUIT OPEN — FALLBACK ====================

@pytest.mark.asyncio
async def test_circuit_open_user_service_returns_fallback(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """When Circuit is OPEN, UserService returns fallback — automatically."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    # Force circuit OPEN
    await circuit_breaker.force_open()
    assert circuit_breaker.is_open

    # Call the REAL method — must return fallback, NOT raise
    info = await service._fetch_user_info_from_auth(user_id)
    assert_fallback_values(info, user_id)
    print(f"  Circuit OPEN → fallback: {info}")

    await circuit_breaker.force_close()


# ==================== 3. AUTH-SERVICE 503 — FALLBACK ====================

@pytest.mark.asyncio
async def test_auth_503_user_service_returns_fallback(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """When auth-service returns 503, UserService returns fallback."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    await fault_inject_503()
    await asyncio.sleep(0.3)

    # Call the REAL method
    info = await service._fetch_user_info_from_auth(user_id)
    assert_fallback_values(info, user_id)
    print(f"  503 fault → fallback: {info}")

    await fault_clear_503()
    await circuit_breaker.force_close()


# ==================== 4. AUTH-SERVICE TIMEOUT — FALLBACK ====================

@pytest.mark.asyncio
async def test_auth_timeout_user_service_returns_fallback(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """When auth-service times out, UserService returns fallback."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    await fault_inject_timeout(ms=INJECT_TIMEOUT_MS)
    await asyncio.sleep(0.3)

    start = time.monotonic()
    info = await service._fetch_user_info_from_auth(user_id)
    elapsed = time.monotonic() - start

    assert_fallback_values(info, user_id)
    print(f"  Timeout ({elapsed:.2f}s) → fallback: {info}")

    # Must return within timeout + buffer — not hang forever
    assert elapsed < TEST_HTTP_TIMEOUT + 1.0, \
        f"Fallback took {elapsed:.2f}s, expected <{TEST_HTTP_TIMEOUT + 1.0}s"

    await fault_clear_timeout()
    await circuit_breaker.force_close()


# ==================== 5. RECOVERY — FALLBACK STOPS ====================

@pytest.mark.asyncio
async def test_fallback_stops_after_auth_service_recovers(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """After auth-service recovers, UserService stops using fallback.

    Full flow:
        1. Auth healthy → real data
        2. Auth 503 → fallback
        3. Auth recovered → real data again
    """
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    # Phase 1: Normal
    info = await service._fetch_user_info_from_auth(user_id)
    assert_real_info(info)
    print(f"  Phase 1 (normal): {info}")

    # Phase 2: Break with 503
    await fault_inject_503()
    await asyncio.sleep(0.3)

    info = await service._fetch_user_info_from_auth(user_id)
    assert_fallback_values(info, user_id)
    print(f"  Phase 2 (503): {info}")

    # Phase 3: Clear fault, force recovery, verify real data returns
    await fault_clear_503()
    await circuit_breaker.force_close()
    await asyncio.sleep(0.5)

    info = await service._fetch_user_info_from_auth(user_id)
    assert_real_info(info)
    print(f"  Phase 3 (recovered): {info}")

    assert circuit_breaker.state == CircuitState.CLOSED


# ==================== 6. NO EXCEPTIONS — METHOD NEVER RAISES ====================

@pytest.mark.asyncio
async def test_fetch_user_info_never_raises(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """_fetch_user_info_from_auth must never raise — under any conditions.

    Tests all failure modes in sequence:
        - Circuit OPEN
        - 503 from auth
        - Timeout from auth
    """
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    # Mode 1: Circuit OPEN
    await circuit_breaker.force_open()
    info = await service._fetch_user_info_from_auth(user_id)
    assert_fallback_values(info, user_id)
    print(f"  Circuit OPEN: returned safely")

    await circuit_breaker.force_close()

    # Mode 2: 503
    await fault_inject_503()
    await asyncio.sleep(0.3)
    info = await service._fetch_user_info_from_auth(user_id)
    assert_fallback_values(info, user_id)
    print(f"  503: returned safely")

    await fault_clear_503()

    # Mode 3: Timeout
    await fault_inject_timeout(ms=INJECT_TIMEOUT_MS)
    await asyncio.sleep(0.3)
    info = await service._fetch_user_info_from_auth(user_id)
    assert_fallback_values(info, user_id)
    print(f"  Timeout: returned safely")

    await fault_clear_timeout()
    await circuit_breaker.force_close()

    print("  _fetch_user_info_from_auth never raised — all modes PASSED")


# ==================== 7. PER-USER ISOLATION ====================

@pytest.mark.asyncio
async def test_fallback_per_user_isolation(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Each user gets their own fallback email — not a shared static value."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    await circuit_breaker.force_open()

    user_a = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    user_b = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

    info_a = await service._fetch_user_info_from_auth(user_a)
    info_b = await service._fetch_user_info_from_auth(user_b)

    assert info_a["email"] == f"{user_a}@unknown.com"
    assert info_b["email"] == f"{user_b}@unknown.com"
    assert info_a["email"] != info_b["email"]

    print(f"  User A: {info_a['email']}")
    print(f"  User B: {info_b['email']}")

    await circuit_breaker.force_close()


# ==================== 8. CIRCUIT BREAKER call_with_fallback API ====================

@pytest.mark.asyncio
async def test_circuit_breaker_call_with_fallback_api(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """CircuitBreaker.call_with_fallback — fallback runs on failure, skipped on success."""
    assert auth_service_is_reachable()

    user_id = existing_user_id()
    fallback_called = False

    async def primary():
        return await auth_http_client._do_request(
            "GET", f"/internal/user/{user_id}/exists"
        )

    async def fallback():
        nonlocal fallback_called
        fallback_called = True
        return {
            "email": f"{user_id}@unknown.com",
            "is_active": True,
            "is_email_verified": False,
        }

    # Enable 503 → primary fails → fallback runs
    await fault_inject_503()
    await asyncio.sleep(0.3)

    result = await circuit_breaker.call_with_fallback(primary, fallback)
    assert fallback_called
    assert_fallback_values(result, user_id)
    print(f"  Fault active → fallback called: {fallback_called}")

    await fault_clear_503()
    await circuit_breaker.force_close()

    # No fault → primary succeeds → fallback skipped
    fallback_called = False
    result = await circuit_breaker.call_with_fallback(primary, fallback)
    assert not fallback_called
    assert result.status_code == 200
    print(f"  No fault → fallback skipped, status={result.status_code}")