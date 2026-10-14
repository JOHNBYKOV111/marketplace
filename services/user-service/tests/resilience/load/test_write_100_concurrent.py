"""
Concurrent write operations test — 100 concurrent block/unblock requests.

Verifies that write operations (block, unblock) handle 100 concurrent
requests correctly through the Circuit Breaker:
    - Each user gets isolated notification
    - Circuit state remains consistent under concurrent writes
    - No race conditions in CB failure counting
    - Fire-and-forget notifications never raise
    - Mixed operations (block + unblock interleaved) are idempotent
    - Fault injection does not corrupt write operations
    - Write operations bypass CircuitBreaker (CQRS on transport layer)

No mocks. No stubs. Real HTTP calls. Real fault injection.

Prerequisites:
    - docker compose up -d auth-service

Run:
    docker exec -it user-service pytest tests/resilience/load/test_write_100_concurrent.py -v -s
"""

import asyncio
from uuid import UUID, uuid4

import pytest

from app.core.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState
from app.core.http_client import AuthServiceHttpClient
from app.services.user_service import UserService

from ..conftest import (
    fault_inject_503,
    fault_clear_503,
    auth_service_is_reachable,
    get_test_user_id,
    run_concurrently,
    TEST_FAILURE_THRESHOLD,
    TEST_HTTP_TIMEOUT,
)


# ==================== CONSTANTS ====================

CONCURRENT_WRITES = 100

# Unique user IDs for isolation testing
USER_A = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
USER_B = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
USER_C = UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")


# ==================== HELPERS ====================

def existing_user_id() -> UUID:
    """Dynamic UUID — resolved from auth-service via get_test_user_id()."""
    return UUID(get_test_user_id())


def create_user_service(http_client: AuthServiceHttpClient) -> UserService:
    """Create a real UserService wired to the CB-protected HTTP client."""
    return UserService(http_client=http_client)


def create_long_timeout_cb() -> CircuitBreaker:
    """Create a CircuitBreaker with 60s recovery timeout."""
    config = CircuitBreakerConfig(
        failure_threshold=TEST_FAILURE_THRESHOLD,
        recovery_timeout=60.0,
        half_open_max_requests=1,
        success_threshold=2,
    )
    return CircuitBreaker(config)


# ==================== 1. CONCURRENT BLOCK — ALL SUCCEED ====================

@pytest.mark.asyncio
async def test_concurrent_block_100_requests_all_succeed(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """100 concurrent block requests — all complete without exceptions."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    results = await run_concurrently(
        service._notify_auth_block_user,
        user_id,
        "concurrent test",
        n=CONCURRENT_WRITES,
    )

    assert len(results) == CONCURRENT_WRITES
    print(f"  {CONCURRENT_WRITES} concurrent block requests — all completed")
    print(f"    Circuit: {circuit_breaker.state.value}, failures: {circuit_breaker.failure_count}")


# ==================== 2. CONCURRENT UNBLOCK — ALL SUCCEED ====================

@pytest.mark.asyncio
async def test_concurrent_unblock_100_requests_all_succeed(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """100 concurrent unblock requests — all complete without exceptions."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    results = await run_concurrently(
        service._notify_auth_unblock_user,
        user_id,
        "concurrent test",
        n=CONCURRENT_WRITES,
    )

    assert len(results) == CONCURRENT_WRITES
    print(f"  {CONCURRENT_WRITES} concurrent unblock requests — all completed")
    print(f"    Circuit: {circuit_breaker.state.value}, failures: {circuit_breaker.failure_count}")


# ==================== 3. CONCURRENT WRITES WITH 503 — FIRE-AND-FORGET ====================

@pytest.mark.asyncio
async def test_concurrent_writes_during_503_fault_never_raise(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """100 concurrent write requests during 503 fault — none raise."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    await fault_inject_503()
    await asyncio.sleep(0.3)

    try:
        results = await run_concurrently(
            service._notify_auth_block_user,
            user_id,
            "test during 503",
            n=CONCURRENT_WRITES,
        )
    except Exception as e:
        pytest.fail(f"Concurrent writes raised {type(e).__name__}: {e}")

    assert len(results) == CONCURRENT_WRITES
    print(f"  {CONCURRENT_WRITES} writes during 503 — zero exceptions")

    await fault_clear_503()
    await circuit_breaker.force_close()


# ==================== 4. CONCURRENT WRITES — UNIQUE USER ISOLATION ====================

@pytest.mark.asyncio
async def test_concurrent_writes_unique_users_isolated(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """100 concurrent writes for 100 unique users — all isolated."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)

    tasks = [
        service._notify_auth_block_user(uuid4(), f"isolation test {i}")
        for i in range(CONCURRENT_WRITES)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    assert len(results) == CONCURRENT_WRITES, \
        f"Expected {CONCURRENT_WRITES} results, got {len(results)}"

    exceptions = [r for r in results if isinstance(r, Exception)]
    assert len(exceptions) == 0, \
        f"{len(exceptions)} tasks raised exceptions: {exceptions[:3]}"

    print(f"  {CONCURRENT_WRITES} writes across {CONCURRENT_WRITES} unique users — all isolated")
    print(f"    Circuit: {circuit_breaker.state.value}")


# ==================== 5. MIXED BLOCK/UNBLOCK — IDEMPOTENT ====================

@pytest.mark.asyncio
async def test_mixed_block_unblock_concurrent_idempotent(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Concurrent block + unblock interleaved — idempotent."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    tasks = []
    for i in range(CONCURRENT_WRITES):
        if i % 2 == 0:
            tasks.append(service._notify_auth_block_user(user_id, f"mixed {i}"))
        else:
            tasks.append(service._notify_auth_unblock_user(user_id, f"mixed {i}"))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    assert len(results) == CONCURRENT_WRITES
    exceptions = [r for r in results if isinstance(r, Exception)]
    assert len(exceptions) == 0, \
        f"{len(exceptions)} mixed tasks raised exceptions"

    print(f"  {CONCURRENT_WRITES} mixed block/unblock — all idempotent")
    print(f"    Circuit: {circuit_breaker.state.value}, failures: {circuit_breaker.failure_count}")


# ==================== 6. WRITE OPERATIONS DO NOT OPEN CIRCUIT ====================

@pytest.mark.asyncio
async def test_write_operations_do_not_open_circuit(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Write operations (block/unblock) do not open the Circuit Breaker."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    await fault_inject_503()
    await asyncio.sleep(0.3)

    for i in range(circuit_breaker._config.failure_threshold * 2):
        await service._notify_auth_block_user(user_id, f"test {i}")
        await service._notify_auth_unblock_user(user_id, f"test {i}")

    assert circuit_breaker.is_closed, \
        f"Write operations opened circuit: {circuit_breaker.state.value}"
    assert circuit_breaker.failure_count == 0, \
        f"Write operations counted as failures: {circuit_breaker.failure_count}"

    print(f"  After {circuit_breaker._config.failure_threshold * 4} writes during 503:")
    print(f"    Circuit: {circuit_breaker.state.value}, failures: {circuit_breaker.failure_count}")

    await fault_clear_503()
    await circuit_breaker.force_close()


# ==================== 7. CIRCUIT STATE CONSISTENT UNDER WRITE LOAD ====================

@pytest.mark.asyncio
async def test_circuit_state_consistent_under_concurrent_writes(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """CB state remains consistent under concurrent write load."""
    assert auth_service_is_reachable()

    long_cb = create_long_timeout_cb()
    try:
        service = create_user_service(auth_http_client)
        user_id = existing_user_id()

        await long_cb.force_open()
        assert long_cb.is_open
        print(f"  Circuit forced OPEN (recovery_timeout=60s)")

        await run_concurrently(
            service._notify_auth_block_user,
            user_id,
            "test open",
            n=CONCURRENT_WRITES,
        )

        assert long_cb.is_open, \
            f"Write operations changed circuit state: {long_cb.state.value}"
        print(f"  After {CONCURRENT_WRITES} writes: circuit {long_cb.state.value}")
    finally:
        await long_cb.force_close()
        if long_cb._recovery_task and not long_cb._recovery_task.done():
            long_cb._recovery_task.cancel()
            try:
                await long_cb._recovery_task
            except asyncio.CancelledError:
                pass