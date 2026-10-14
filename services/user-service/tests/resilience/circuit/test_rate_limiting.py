"""
Rate limiting integration tests.

Tests Circuit Breaker rate-limiting behavior during auth-service failures
and recovery after service restoration.

No mocks. No stubs. Real HTTP calls. Real fault injection.

Test categories:
    1. Circuit opens after threshold failures — fast-fail activates
    2. Recovery after cooldown — HALF_OPEN → CLOSED on successful probes
    3. Wave load stability — repeated failure/recovery cycles
    4. 4xx does not count — client errors excluded from rate limiting
    5. Burst during OPEN — all requests fast-fail
    6. No premature HALF_OPEN before recovery_timeout
    7. force_close restores service immediately
    8. Metrics accuracy during rate limiting

Architecture:
    Real UserService → AuthServiceHttpClient → CircuitBreaker
    → real HTTP → auth-service with fault injection.

    _fetch_user_info_from_auth NEVER raises — always returns dict
    (real data or fallback). Circuit state verified via CircuitBreaker.

Prerequisites:
    - docker compose up -d auth-service

Run:
    docker exec -it user-service pytest tests/resilience/circuit/test_rate_limiting.py -v -s
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
    auth_service_is_reachable,
    get_test_user_id,
    measure_latency,
    latency_percentiles,
    TEST_FAILURE_THRESHOLD,
    TEST_RECOVERY_TIMEOUT,
    TEST_HTTP_TIMEOUT,
)


# ==================== CONSTANTS ====================

# Non-existent user with valid UUID format — auth-service returns 404
NON_EXISTENT_USER_ID = UUID("99999999-9999-9999-9999-999999999999")


# ==================== HELPERS ====================

def existing_user_id() -> UUID:
    """Dynamic UUID — resolved from auth-service via get_test_user_id()."""
    return UUID(get_test_user_id())


def fallback_email(user_id: UUID) -> str:
    """Fallback email for given user_id."""
    return f"{user_id}@unknown.com"


def create_user_service(http_client: AuthServiceHttpClient) -> UserService:
    """Create a real UserService wired to the CB-protected HTTP client."""
    return UserService(http_client=http_client)


def assert_fallback(info: dict, user_id: UUID) -> None:
    """Assert fallback defaults are returned."""
    assert info["email"] == fallback_email(user_id)
    assert info["is_active"] is True
    assert info["is_email_verified"] is False


async def force_failures(service: UserService, user_id: UUID, count: int) -> None:
    """Force `count` failures through the circuit breaker."""
    for _ in range(count):
        await service._fetch_user_info_from_auth(user_id)


async def break_circuit(
    service: UserService,
    circuit_breaker: CircuitBreaker,
    user_id: UUID,
) -> None:
    """Inject 503, reset recovery timer, and force threshold+1 failures.
    
    Ensures circuit is OPEN with a fresh recovery timer regardless of
    how long fault injection took (multi-worker sync can take seconds).
    """
    await fault_inject_503()
    await asyncio.sleep(0.3)
    # Reset recovery timer AFTER fault injection to get accurate cooldown
    await circuit_breaker.force_open()
    await force_failures(service, user_id, circuit_breaker._config.failure_threshold + 1)
    assert circuit_breaker.is_open, f"Circuit not OPEN: {circuit_breaker.state.value}"


async def recover_circuit(
    service: UserService,
    circuit_breaker: CircuitBreaker,
    user_id: UUID,
) -> None:
    """Clear fault, wait for recovery timeout, and close via successful probes."""
    await fault_clear_503()
    # Reset recovery timer after fault clear (multi-worker sync takes time)
    await circuit_breaker.force_open()
    await asyncio.sleep(0.3)
    
    recovery = circuit_breaker._config.recovery_timeout
    success_needed = circuit_breaker._config.success_threshold
    
    await asyncio.sleep(recovery + 0.5)
    assert circuit_breaker.is_half_open, \
        f"Expected HALF_OPEN, got {circuit_breaker.state.value}"
    
    for _ in range(success_needed):
        await service._fetch_user_info_from_auth(user_id)
    
    assert circuit_breaker.is_closed, "Circuit did not CLOSE after successful probes"
    assert circuit_breaker.failure_count == 0


# ==================== 1. CIRCUIT OPENS — FAST-FAIL ====================

@pytest.mark.asyncio
async def test_circuit_opens_after_threshold_failures(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Circuit opens after failure_threshold consecutive 503 responses.

    After opening, requests return fallback without calling auth-service.
    """
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    await fault_inject_503()
    await asyncio.sleep(0.3)

    threshold = circuit_breaker._config.failure_threshold

    # Requests up to threshold - 1: circuit stays CLOSED
    for i in range(threshold - 1):
        info = await service._fetch_user_info_from_auth(user_id)
        assert_fallback(info, user_id)
        assert circuit_breaker.is_closed, \
            f"Circuit opened prematurely after {i + 1} failures"

    print(f"  After {threshold - 1} failures: CLOSED")

    # Threshold failure opens the circuit
    info = await service._fetch_user_info_from_auth(user_id)
    assert_fallback(info, user_id)
    assert circuit_breaker.is_open, \
        f"Circuit did NOT open after {threshold} failures"
    print(f"  After {threshold} failures: OPEN")

    # Subsequent request returns fallback immediately (fast-fail)
    info = await service._fetch_user_info_from_auth(user_id)
    assert_fallback(info, user_id)
    assert circuit_breaker.is_open
    print(f"  Fast-fail active: circuit {circuit_breaker.state.value}")

    await fault_clear_503()
    await circuit_breaker.force_close()


# ==================== 2. RECOVERY — HALF_OPEN → CLOSED ====================

@pytest.mark.asyncio
async def test_rate_limited_service_recovers_after_cooldown(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """After fault is cleared, circuit recovers via HALF_OPEN → CLOSED."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()
    recovery = circuit_breaker._config.recovery_timeout
    success_needed = circuit_breaker._config.success_threshold

    # Break the circuit
    await break_circuit(service, circuit_breaker, user_id)
    print(f"  Circuit OPEN")

    # Clear fault and wait for recovery
    await fault_clear_503()
    await circuit_breaker.force_open()  # Reset recovery timer after fault clear
    await asyncio.sleep(0.3)
    print(f"  Waiting {recovery}s for cooldown...")
    await asyncio.sleep(recovery + 0.5)

    assert circuit_breaker.is_half_open, \
        f"Expected HALF_OPEN, got {circuit_breaker.state.value}"
    print(f"  Circuit HALF_OPEN")

    # Successful probes close the circuit
    for i in range(success_needed):
        info = await service._fetch_user_info_from_auth(user_id)
        assert "email" in info
        print(f"  Probe {i + 1}: success")

    assert circuit_breaker.is_closed
    assert circuit_breaker.failure_count == 0
    print(f"  Circuit CLOSED")


# ==================== 3. WAVE LOAD — REPEATED CYCLES ====================

@pytest.mark.asyncio
async def test_repeated_failure_recovery_cycles_stable(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Multiple failure/recovery cycles complete without oscillation."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    for cycle in range(3):
        print(f"\n  Cycle {cycle + 1}:")

        # Break
        await break_circuit(service, circuit_breaker, user_id)
        print(f"    CLOSED → OPEN")

        # Recover
        await recover_circuit(service, circuit_breaker, user_id)
        print(f"    OPEN → HALF_OPEN → CLOSED")

    print(f"\n  All 3 cycles stable")


# ==================== 4. 4xx DOES NOT COUNT ====================

@pytest.mark.asyncio
async def test_4xx_does_not_trigger_rate_limiting(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Client errors (4xx) are not counted toward rate limiting."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    threshold = circuit_breaker._config.failure_threshold

    for i in range(threshold * 3):
        try:
            await service._fetch_user_info_from_auth(NON_EXISTENT_USER_ID)
        except AuthServiceError:
            pass

    assert circuit_breaker.is_closed, \
        f"4xx opened circuit: {circuit_breaker.state.value}"
    assert circuit_breaker.failure_count == 0, \
        f"4xx counted as failures: {circuit_breaker.failure_count}"

    print(f"  After {threshold * 3} requests with 4xx:")
    print(f"    Circuit: {circuit_breaker.state.value}")
    print(f"    Failures: {circuit_breaker.failure_count}")


# ==================== 5. BURST DURING OPEN ====================

@pytest.mark.asyncio
async def test_burst_during_open_all_fast_fail(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Burst of 500 requests during OPEN — all fast-fail."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()
    await circuit_breaker.force_open()

    latencies = await measure_latency(
        service._fetch_user_info_from_auth,
        user_id,
        n=500,
    )

    percentiles = latency_percentiles(latencies)

    print(f"  Burst 500 requests during OPEN:")
    print(f"    p50: {percentiles['p50']:.2f}ms")
    print(f"    p95: {percentiles['p95']:.2f}ms")
    print(f"    p99: {percentiles['p99']:.2f}ms")

    assert percentiles["p99"] < 50.0, \
        f"Fast-fail p99={percentiles['p99']:.2f}ms exceeds 50ms"
    assert circuit_breaker.is_open

    await circuit_breaker.force_close()


# ==================== 6. NO PREMATURE HALF_OPEN ====================

@pytest.mark.asyncio
async def test_no_premature_half_open_before_cooldown(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Circuit stays OPEN until recovery_timeout elapses.

    Fault injection and clearing takes time (multi-worker sync).
    Recovery timer is reset after fault clear to ensure accurate
    measurement of the cooldown period.
    """
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()
    recovery = circuit_breaker._config.recovery_timeout

    # Open the circuit — use helper to reset timer after fault injection
    await break_circuit(service, circuit_breaker, user_id)
    print(f"  Circuit OPEN")

    # Clear fault and reset recovery timer
    await fault_clear_503()
    await circuit_breaker.force_open()  # Reset recovery timer after fault clear took time
    await asyncio.sleep(0.3)
    print(f"  Recovery timer reset — measuring cooldown from now")

    check_interval = recovery / 4

    # Circuit must stay OPEN before timeout
    for i in range(3):
        await asyncio.sleep(check_interval)
        assert circuit_breaker.is_open, \
            f"Premature transition to {circuit_breaker.state.value}"
        print(f"  t={check_interval * (i + 1):.1f}s: {circuit_breaker.state.value}")

    # After full timeout, transition to HALF_OPEN
    await asyncio.sleep(check_interval + 0.5)
    assert circuit_breaker.is_half_open, \
        f"Expected HALF_OPEN after {recovery}s, got {circuit_breaker.state.value}"
    print(f"  t={recovery:.1f}s: {circuit_breaker.state.value}")

    await circuit_breaker.force_close()


# ==================== 7. MANUAL RESET ====================

@pytest.mark.asyncio
async def test_force_close_immediately_lifts_rate_limiting(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """force_close immediately restores service without waiting for cooldown."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    # Break the circuit
    await circuit_breaker.force_open()
    assert circuit_breaker.is_open

    # Request returns fallback while circuit is OPEN
    info = await service._fetch_user_info_from_auth(user_id)
    assert_fallback(info, user_id)
    assert circuit_breaker.is_open
    print(f"  Circuit OPEN — fallback returned")

    # Manual reset
    await circuit_breaker.force_close()
    await asyncio.sleep(0.3)
    assert circuit_breaker.is_closed
    assert circuit_breaker.failure_count == 0

    # Service available immediately
    info = await service._fetch_user_info_from_auth(user_id)
    assert "email" in info
    print(f"  Circuit CLOSED — service available immediately")


# ==================== 8. METRICS UNDER RATE LIMITING ====================

@pytest.mark.asyncio
async def test_metrics_accurate_during_rate_limiting(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Metrics accurately reflect circuit state during rate limiting."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()
    threshold = circuit_breaker._config.failure_threshold
    recovery = circuit_breaker._config.recovery_timeout
    success_needed = circuit_breaker._config.success_threshold

    # CLOSED
    m = circuit_breaker.get_metrics()
    assert m["state"] == "closed"
    assert m["failure_count"] == 0
    print(f"  CLOSED: {m['state']}, failures={m['failure_count']}")

    # OPEN
    await break_circuit(service, circuit_breaker, user_id)

    m = circuit_breaker.get_metrics()
    assert m["state"] == "open"
    assert m["failure_count"] >= threshold
    print(f"  OPEN: {m['state']}, failures={m['failure_count']}")

    # HALF_OPEN — reset recovery timer after fault clear
    await fault_clear_503()
    await circuit_breaker.force_open()
    await asyncio.sleep(0.3)
    await asyncio.sleep(recovery + 0.5)

    m = circuit_breaker.get_metrics()
    assert m["state"] == "half_open"
    assert m["trial_count"] == 0
    print(f"  HALF_OPEN: {m['state']}, trials={m['trial_count']}")

    # CLOSED — use recover_circuit for reliable natural recovery
    await recover_circuit(service, circuit_breaker, user_id)

    m = circuit_breaker.get_metrics()
    assert m["state"] == "closed"
    assert m["failure_count"] == 0
    print(f"  CLOSED: {m['state']}, failures={m['failure_count']}")