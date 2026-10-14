"""
Circuit Breaker integration tests.

Tests the FULL resilience stack end-to-end:
    - Real auth-service with Application-Level Fault Injection
    - Real CircuitBreaker with real timeouts
    - Real 503 fault injection for failure simulation
    - Real timeout injection for slow-service simulation

No mocks. No stubs. No Docker CLI. No TestClient. Real network calls. Real timeouts.

Test categories:
    1. Closed circuit — normal operation
    2. Closed → Open — after consecutive 503 injections
    3. Open — fast-fail rejection
    4. Open → Half-Open — recovery timeout
    5. Half-Open → Closed — successful trial
    6. Half-Open → Open — failed trial
    7. Full recovery cycle (503 injection + recovery)
    8. Timeout fault injection — circuit opens on slow responses
    9. 4xx exclusion — does NOT affect circuit
    10. Metrics accuracy

Architecture:
    Tests call AuthServiceHttpClient directly (NOT TestClient / FastAPI routing).
    The CircuitBreaker lives at the HTTP client layer, not the API layer.
    This tests the REAL resilience stack without routing indirection.

Prerequisites:
    - docker compose up -d auth-service
    - Auth-service fault injection endpoints must be reachable

Run:
    docker exec -it user-service pytest tests/resilience/circuit/test_circuit_breaker.py -v -s
"""

import asyncio
import time
from uuid import UUID

import pytest

from app.core.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState
from app.core.http_client import AuthServiceHttpClient, AuthServiceError, AuthServiceUnavailableError

from ..conftest import (
    fault_inject_503,
    fault_clear_503,
    fault_inject_timeout,
    fault_clear_timeout,
    auth_service_is_reachable,
    get_test_user_id,
    TEST_HTTP_TIMEOUT,
)


# ==================== CONSTANTS ====================

# Non-existent user — always fixed UUID for negative tests
NON_EXISTENT_USER_ID = UUID("00000000-0000-0000-0000-000000000000")

# Small threshold for timeout test — avoids 100 × 10s = 1000s runtime
TIMEOUT_TEST_FAILURE_THRESHOLD = 5


def existing_user_id() -> UUID:
    """Dynamic UUID — resolved from auth-service via get_test_user_id()."""
    return UUID(get_test_user_id())


# ==================== HELPERS ====================

async def wait_for_state(
    cb: CircuitBreaker,
    expected: CircuitState,
    timeout: float = 10.0,
    interval: float = 0.2,
) -> bool:
    """Poll until circuit reaches expected state or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cb.state == expected:
            return True
        await asyncio.sleep(interval)
    return False


# ==================== 1. CLOSED — NORMAL OPERATION ====================

@pytest.mark.asyncio
async def test_closed_circuit_normal_flow(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Circuit is CLOSED. Normal requests pass through successfully."""
    assert auth_service_is_reachable(), "auth-service fault injection must be reachable"

    user_id = existing_user_id()
    for i in range(5):
        result = await auth_http_client.get_user_exists(user_id)
        print(f"  Request {i}: exists={result.get('exists')}")
        assert "exists" in result

    assert circuit_breaker.state == CircuitState.CLOSED, \
        f"Expected CLOSED, got {circuit_breaker.state}"
    assert circuit_breaker.failure_count == 0, \
        f"Expected 0 failures, got {circuit_breaker.failure_count}"


# ==================== 2. CLOSED → OPEN — CONSECUTIVE 503 ====================

@pytest.mark.asyncio
async def test_closed_to_open_on_503_fault(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Circuit opens after consecutive 503 responses from fault injection."""
    await fault_inject_503()
    await asyncio.sleep(0.3)

    user_id = existing_user_id()
    failures_needed = circuit_breaker._config.failure_threshold

    for i in range(failures_needed + 2):
        try:
            await auth_http_client.get_user_exists(user_id)
            print(f"  Request {i}: OK (unexpected)")
        except AuthServiceUnavailableError as e:
            print(f"  Request {i}: AuthServiceUnavailableError — CB: {circuit_breaker.state}, failures: {circuit_breaker.failure_count}")

    assert circuit_breaker.state == CircuitState.OPEN, \
        f"Expected OPEN after {failures_needed} failures, got {circuit_breaker.state}"

    await fault_clear_503()
    await circuit_breaker.force_close()


# ==================== 3. OPEN — FAST-FAIL REJECTION ====================

@pytest.mark.asyncio
async def test_open_circuit_rejects_immediately(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """When circuit is OPEN, requests fail fast without calling auth-service."""
    await circuit_breaker.force_open()
    assert circuit_breaker.state == CircuitState.OPEN

    user_id = existing_user_id()
    start = time.monotonic()
    try:
        await auth_http_client.get_user_exists(user_id)
    except AuthServiceUnavailableError as e:
        elapsed = time.monotonic() - start
        print(f"  Rejected in {elapsed*1000:.0f}ms: {e}")
        assert elapsed < 1.0, f"Fast-fail took {elapsed:.2f}s, expected <1.0s"

    await circuit_breaker.force_close()


# ==================== 4. OPEN → HALF-OPEN — RECOVERY TIMEOUT ====================

@pytest.mark.asyncio
async def test_open_to_half_open_after_timeout(
    circuit_breaker: CircuitBreaker,
    ensure_auth_service: None,
) -> None:
    """Circuit transitions OPEN → HALF_OPEN after recovery_timeout."""
    await circuit_breaker.force_open()
    assert circuit_breaker.state == CircuitState.OPEN

    recovery = circuit_breaker._config.recovery_timeout
    await asyncio.sleep(recovery + 0.5)

    assert circuit_breaker.state == CircuitState.HALF_OPEN, \
        f"Expected HALF_OPEN after {recovery}s, got {circuit_breaker.state}"

    await circuit_breaker.force_close()


# ==================== 5. HALF-OPEN → CLOSED — SUCCESSFUL TRIAL ====================

@pytest.mark.asyncio
async def test_half_open_to_closed_on_success(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Successful requests in HALF_OPEN transition back to CLOSED."""
    assert auth_service_is_reachable()

    await circuit_breaker.force_half_open()
    assert circuit_breaker.state == CircuitState.HALF_OPEN

    user_id = existing_user_id()
    success_needed = circuit_breaker._config.success_threshold
    for i in range(success_needed):
        result = await auth_http_client.get_user_exists(user_id)
        print(f"  Trial {i}: exists={result.get('exists')}, CB: {circuit_breaker.state}")

    assert circuit_breaker.state == CircuitState.CLOSED, \
        f"Expected CLOSED after {success_needed} successes, got {circuit_breaker.state}"
    assert circuit_breaker.failure_count == 0


# ==================== 6. HALF-OPEN → OPEN — FAILED TRIAL ====================

@pytest.mark.asyncio
async def test_half_open_to_open_on_failure(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """A single failure in HALF_OPEN sends the circuit back to OPEN."""
    await circuit_breaker.force_half_open()
    assert circuit_breaker.state == CircuitState.HALF_OPEN

    await fault_inject_503()
    await asyncio.sleep(0.3)

    user_id = existing_user_id()
    try:
        await auth_http_client.get_user_exists(user_id)
    except AuthServiceUnavailableError:
        pass

    assert circuit_breaker.state == CircuitState.OPEN, \
        f"Expected OPEN after failure in HALF_OPEN, got {circuit_breaker.state}"

    await fault_clear_503()
    await circuit_breaker.force_close()


# ==================== 7. FULL RECOVERY CYCLE ====================

@pytest.mark.asyncio
async def test_full_recovery_cycle(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """End-to-end: CLOSED → OPEN → HALF_OPEN → CLOSED."""
    assert auth_service_is_reachable()

    await fault_inject_503()
    await asyncio.sleep(0.3)

    user_id = existing_user_id()
    failures_needed = circuit_breaker._config.failure_threshold
    for i in range(failures_needed + 1):
        try:
            await auth_http_client.get_user_exists(user_id)
        except AuthServiceUnavailableError:
            pass

    assert circuit_breaker.state == CircuitState.OPEN, \
        f"Phase 1 failed: expected OPEN, got {circuit_breaker.state}"

    await fault_clear_503()
    recovery_timeout = circuit_breaker._config.recovery_timeout
    print(f"  Waiting {recovery_timeout}s for recovery...")
    await asyncio.sleep(recovery_timeout + 0.5)

    assert circuit_breaker.state == CircuitState.HALF_OPEN, \
        f"Phase 2 failed: expected HALF_OPEN, got {circuit_breaker.state}"

    success_needed = circuit_breaker._config.success_threshold
    for i in range(success_needed):
        result = await auth_http_client.get_user_exists(user_id)
        print(f"  Trial {i}: exists={result.get('exists')}, CB: {circuit_breaker.state}")

    assert circuit_breaker.state == CircuitState.CLOSED, \
        f"Phase 3 failed: expected CLOSED, got {circuit_breaker.state}"
    assert circuit_breaker.failure_count == 0


# ==================== 8. TIMEOUT FAULT — CIRCUIT OPENS ====================

@pytest.mark.asyncio
async def test_timeout_fault_opens_circuit(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Slow responses cause the circuit to open.

    Uses a separate CircuitBreaker with small failure threshold
    to keep test runtime reasonable (5 timeouts, not 100).
    """
    assert auth_service_is_reachable()

    # Create a dedicated CB with small threshold for timeout test
    timeout_cb = CircuitBreaker(CircuitBreakerConfig(
        failure_threshold=TIMEOUT_TEST_FAILURE_THRESHOLD,
        recovery_timeout=3.0,
    ))
    timeout_client = AuthServiceHttpClient(
        base_url=auth_http_client._base_url,
        api_key=auth_http_client._api_key,
        timeout=TEST_HTTP_TIMEOUT,
        circuit_breaker=timeout_cb,
    )

    # Inject delay longer than HTTP client timeout to guarantee timeouts
    timeout_ms = int(TEST_HTTP_TIMEOUT * 1000) + 2000
    await fault_inject_timeout(ms=timeout_ms)
    await asyncio.sleep(0.3)

    user_id = existing_user_id()
    for i in range(TIMEOUT_TEST_FAILURE_THRESHOLD + 1):
        try:
            await timeout_client.get_user_exists(user_id)
            print(f"  Request {i}: OK (unexpected)")
        except AuthServiceUnavailableError as e:
            print(f"  Request {i}: {type(e).__name__}, CB: {timeout_cb.state}, failures: {timeout_cb.failure_count}")

    assert timeout_cb.state == CircuitState.OPEN, \
        f"Expected OPEN after timeout failures, got {timeout_cb.state}"

    await fault_clear_timeout()
    await timeout_client.close()


# ==================== 9. 4xx DOES NOT AFFECT CIRCUIT ====================

@pytest.mark.asyncio
async def test_4xx_does_not_open_circuit(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Client errors (4xx) are NOT counted as failures."""
    assert auth_service_is_reachable()

    for i in range(10):
        try:
            result = await auth_http_client.get_user_exists(NON_EXISTENT_USER_ID)
            print(f"  Request {i}: exists={result.get('exists')}")
        except AuthServiceError as e:
            print(f"  Request {i}: AuthServiceError {e.status_code} (expected for non-existent user)")

    assert circuit_breaker.state == CircuitState.CLOSED, \
        f"4xx opened the circuit! State: {circuit_breaker.state}"
    assert circuit_breaker.failure_count == 0, \
        f"4xx counted as failures: {circuit_breaker.failure_count}"


# ==================== 10. METRICS ACCURACY ====================

@pytest.mark.asyncio
async def test_metrics_reflect_real_state(
    circuit_breaker: CircuitBreaker,
    ensure_auth_service: None,
) -> None:
    """Metrics API returns accurate state after transitions."""
    metrics = circuit_breaker.get_metrics()
    assert metrics["state"] == "closed"
    assert metrics["failure_count"] == 0

    await circuit_breaker.force_open()
    metrics = circuit_breaker.get_metrics()
    assert metrics["state"] == "open"

    await circuit_breaker.force_half_open()
    metrics = circuit_breaker.get_metrics()
    assert metrics["state"] == "half_open"
    assert metrics["trial_count"] == 0

    await circuit_breaker.force_close()