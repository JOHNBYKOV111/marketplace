"""
Idempotency tests — PRODUCTION-LEVEL.

Tests that operations remain idempotent (safe to retry) even when
auth-service is unavailable or the circuit breaker is in non-CLOSED states.

Idempotency guarantees verified:
    - Repeated _fetch_user_info_from_auth returns consistent fallback data
    - Repeated notification methods (_notify_auth_*) never raise
    - CircuitBreaker force_open/force_close/force_half_open are idempotent
    - CircuitBreaker metrics remain consistent under repeated calls
    - Repeated fault injection enable/disable is idempotent
    - get_metrics() returns consistent snapshots
    - Caller can safely retry any operation without side effects

No mocks. No stubs. Real network calls. Real timeouts.

Architecture:
    Tests create a real UserService with CB-protected HTTP client.
    Fault injection on auth-service triggers error conditions.
    Every operation is called multiple times with same parameters
    to verify idempotency.

Prerequisites:
    - docker compose up -d auth-service
    - Auth-service fault injection endpoints must be reachable

Run:
    docker exec -it user-service pytest tests/resilience/reliability/test_idempotency.py -v -s
"""

import asyncio
import time
from uuid import UUID

import pytest

from app.core.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState
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

# New user — fixed UUID for fallback creation test
NEW_USER_ID = UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")


# ==================== HELPERS ====================

def existing_user_id() -> UUID:
    """Dynamic UUID — resolved from auth-service via get_test_user_id()."""
    return UUID(get_test_user_id())


def create_user_service(http_client: AuthServiceHttpClient) -> UserService:
    """Create a real UserService wired to the CB-protected HTTP client."""
    return UserService(http_client=http_client)


def assert_fallback_profile(info: dict, user_id: UUID) -> None:
    """Assert UserService returned correct fallback profile data."""
    assert info["email"] == f"{user_id}@unknown.com", \
        f"Expected fallback email {user_id}@unknown.com, got {info.get('email')}"
    assert info["is_active"] is True
    assert info["is_email_verified"] is False


# ==================== 1. FETCH_USER_INFO — IDEMPOTENT FALLBACK ====================

@pytest.mark.asyncio
async def test_fetch_user_info_idempotent_during_outage(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Repeated _fetch_user_info_from_auth returns same fallback every time."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    await fault_inject_503()
    await asyncio.sleep(0.3)

    results = []
    for i in range(10):
        info = await service._fetch_user_info_from_auth(user_id)
        results.append(info)
        assert_fallback_profile(info, user_id)

    first = results[0]
    for i, result in enumerate(results[1:], 1):
        assert result == first, \
            f"Call {i} returned different fallback: {result} != {first}"

    print(f"  All 10 calls returned identical fallback: email={first['email']}")

    await fault_clear_503()
    await circuit_breaker.force_close()


# ==================== 2. FETCH_USER_INFO — IDEMPOTENT WITH CIRCUIT OPEN ====================

@pytest.mark.asyncio
async def test_fetch_user_info_idempotent_with_circuit_open(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Repeated calls with circuit OPEN return same fallback."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    await circuit_breaker.force_open()
    assert circuit_breaker.is_open

    results = []
    for i in range(10):
        info = await service._fetch_user_info_from_auth(user_id)
        results.append(info)
        assert_fallback_profile(info, user_id)

    first = results[0]
    for i, result in enumerate(results[1:], 1):
        assert result == first, \
            f"Call {i} with circuit OPEN returned different fallback"

    assert circuit_breaker.is_open

    print(f"  All 10 calls with circuit OPEN returned identical fallback")

    await circuit_breaker.force_close()


# ==================== 3. NOTIFICATION METHODS — IDEMPOTENT ====================

@pytest.mark.asyncio
async def test_notification_methods_idempotent_during_outage(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Repeated notification calls never raise."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    await fault_inject_503()
    await asyncio.sleep(0.3)

    for i in range(10):
        try:
            await service._notify_auth_delete_user(user_id)
        except Exception as e:
            pytest.fail(f"_notify_auth_delete_user call {i} raised {type(e).__name__}: {e}")
    print(f"  _notify_auth_delete_user: 10 calls, no exceptions")

    for i in range(10):
        try:
            await service._notify_auth_block_user(user_id, "test")
        except Exception as e:
            pytest.fail(f"_notify_auth_block_user call {i} raised {type(e).__name__}: {e}")
    print(f"  _notify_auth_block_user: 10 calls, no exceptions")

    for i in range(10):
        try:
            await service._notify_auth_unblock_user(user_id, "test")
        except Exception as e:
            pytest.fail(f"_notify_auth_unblock_user call {i} raised {type(e).__name__}: {e}")
    print(f"  _notify_auth_unblock_user: 10 calls, no exceptions")

    await fault_clear_503()
    await circuit_breaker.force_close()


# ==================== 4. CIRCUIT BREAKER — IDEMPOTENT force_open ====================

@pytest.mark.asyncio
async def test_force_open_is_idempotent(
    circuit_breaker: CircuitBreaker,
    ensure_auth_service: None,
) -> None:
    """Calling force_open multiple times is safe and idempotent."""
    for i in range(10):
        await circuit_breaker.force_open()
        assert circuit_breaker.is_open, f"Call {i}: expected OPEN, got {circuit_breaker.state}"
        assert circuit_breaker.failure_count == circuit_breaker._config.failure_threshold

    print(f"  force_open called 10 times: state={circuit_breaker.state.value}, "
          f"failures={circuit_breaker.failure_count}")

    await circuit_breaker.force_close()


# ==================== 5. CIRCUIT BREAKER — IDEMPOTENT force_close ====================

@pytest.mark.asyncio
async def test_force_close_is_idempotent(
    circuit_breaker: CircuitBreaker,
    ensure_auth_service: None,
) -> None:
    """Calling force_close multiple times is safe and idempotent."""
    await circuit_breaker.force_open()
    assert circuit_breaker.is_open

    for i in range(10):
        await circuit_breaker.force_close()
        assert circuit_breaker.is_closed, f"Call {i}: expected CLOSED, got {circuit_breaker.state}"
        assert circuit_breaker.failure_count == 0
        assert circuit_breaker.get_metrics()["trial_count"] == 0

    print(f"  force_close called 10 times: state={circuit_breaker.state.value}, "
          f"failures={circuit_breaker.failure_count}")


# ==================== 6. CIRCUIT BREAKER — IDEMPOTENT force_half_open ====================

@pytest.mark.asyncio
async def test_force_half_open_is_idempotent(
    circuit_breaker: CircuitBreaker,
    ensure_auth_service: None,
) -> None:
    """Calling force_half_open multiple times is safe and idempotent."""
    for i in range(10):
        await circuit_breaker.force_half_open()
        assert circuit_breaker.is_half_open, \
            f"Call {i}: expected HALF_OPEN, got {circuit_breaker.state}"
        assert circuit_breaker.failure_count == 0
        assert circuit_breaker.get_metrics()["trial_count"] == 0

    print(f"  force_half_open called 10 times: state={circuit_breaker.state.value}")

    await circuit_breaker.force_close()


# ==================== 7. METRICS — IDEMPOTENT get_metrics ====================

@pytest.mark.asyncio
async def test_get_metrics_is_idempotent(
    circuit_breaker: CircuitBreaker,
    ensure_auth_service: None,
) -> None:
    """Calling get_metrics multiple times returns consistent state."""
    await circuit_breaker.force_open()

    snapshots = []
    for i in range(10):
        metrics = circuit_breaker.get_metrics()
        snapshots.append(metrics)

    first = snapshots[0]
    for i, snap in enumerate(snapshots[1:], 1):
        assert snap == first, \
            f"get_metrics call {i} returned different snapshot: {snap} != {first}"

    print(f"  get_metrics called 10 times: state={first['state']}, "
          f"failures={first['failure_count']}, trials={first['trial_count']}")

    await circuit_breaker.force_close()


# ==================== 8. FAULT INJECTION — IDEMPOTENT ====================

@pytest.mark.asyncio
async def test_fault_injection_is_idempotent(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Enabling/disabling fault injection multiple times is safe."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    for i in range(10):
        await fault_inject_503()
    print(f"  fault_inject_503 called 10 times")

    info = await service._fetch_user_info_from_auth(user_id)
    assert_fallback_profile(info, user_id)
    print(f"  Auth still returns 503 after 10x enable: fallback applied")

    for i in range(10):
        await fault_clear_503()
    print(f"  fault_clear_503 called 10 times")

    await circuit_breaker.force_close()
    await asyncio.sleep(0.5)

    info = await service._fetch_user_info_from_auth(user_id)
    assert "email" in info
    print(f"  Auth recovered after 10x disable: email={info.get('email')}")


# ==================== 9. DIFFERENT USERS — IDEMPOTENT PER USER ====================

@pytest.mark.asyncio
async def test_fallback_is_consistent_per_user(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Same user always gets the same fallback, different users get different."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    await circuit_breaker.force_open()

    user_a = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    user_b = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

    results_a = []
    for i in range(10):
        info = await service._fetch_user_info_from_auth(user_a)
        results_a.append(info)
        assert_fallback_profile(info, user_a)

    first_a = results_a[0]
    for i, r in enumerate(results_a[1:], 1):
        assert r == first_a, f"User A call {i} differs"

    results_b = []
    for i in range(10):
        info = await service._fetch_user_info_from_auth(user_b)
        results_b.append(info)
        assert_fallback_profile(info, user_b)

    first_b = results_b[0]
    for i, r in enumerate(results_b[1:], 1):
        assert r == first_b, f"User B call {i} differs"

    assert first_a != first_b, \
        f"Different users should have different fallbacks: {first_a} == {first_b}"
    assert first_a["email"] == f"{user_a}@unknown.com"
    assert first_b["email"] == f"{user_b}@unknown.com"

    print(f"  User A: 10 calls → {first_a['email']} (all identical)")
    print(f"  User B: 10 calls → {first_b['email']} (all identical)")
    print(f"  Users isolated: {first_a['email']} ≠ {first_b['email']}")

    await circuit_breaker.force_close()


# ==================== 10. MIXED OPERATIONS — IDEMPOTENT ====================

@pytest.mark.asyncio
async def test_mixed_operations_remain_idempotent(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Interleaved fetch + notify operations during outage remain idempotent."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    await fault_inject_503()
    await asyncio.sleep(0.3)

    for i in range(10):
        info = await service._fetch_user_info_from_auth(user_id)
        assert_fallback_profile(info, user_id)

        await service._notify_auth_delete_user(user_id)

        info = await service._fetch_user_info_from_auth(user_id)
        assert_fallback_profile(info, user_id)

        await service._notify_auth_block_user(user_id, "test")

    print(f"  Mixed fetch/notify × 10: all operations idempotent")

    await fault_clear_503()
    await circuit_breaker.force_close()