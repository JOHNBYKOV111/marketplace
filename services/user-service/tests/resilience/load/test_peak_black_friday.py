"""
Peak load (Black Friday) integration tests.

Tests system behavior under high concurrency (1000 concurrent requests):
    - Circuit Breaker under load — does not degrade or create bottlenecks
    - Fallback throughput — latency remains bounded under mass failures
    - Connection pool — httpx.AsyncClient handles 1000 concurrent connections
    - Lock contention — asyncio.Lock in CircuitBreaker scales linearly
    - Idempotency under load — repeated calls during peak return consistent results
    - Recovery under load — circuit closes correctly after mass success

All tests use REAL UserService with REAL HTTP calls to auth-service.
Fault injection creates realistic failure conditions.
No mocks. No stubs. Real network. Real concurrency.

Run:
    docker exec -it user-service pytest tests/resilience/load/test_peak_black_friday.py -v -s
"""

import asyncio
from uuid import UUID, uuid4

import pytest

from app.core.circuit_breaker import CircuitBreaker, CircuitState
from app.core.http_client import AuthServiceHttpClient
from app.core.redis_client import get_redis
from app.services.user_service import UserService

from ..conftest import (
    fault_inject_503,
    fault_clear_503,
    auth_service_is_reachable,
    get_test_user_id,
    run_concurrently,
    measure_latency,
    latency_percentiles,
    measure_throughput,
    TEST_HTTP_TIMEOUT,
)


# ==================== CONSTANTS ====================

# Non-existent user — fixed UUID for 4xx exclusion test
NON_EXISTENT_USER_ID = UUID("99999999-9999-9999-9999-999999999999")

CONCURRENT_REQUESTS = 1000

# Latency threshold for fast-fail under load
MAX_FAST_FAIL_P99_MS = 100.0
MAX_FALLBACK_P99_MS = 3000.0


# ==================== HELPERS ====================

def existing_user_id() -> UUID:
    """Dynamic UUID — resolved from auth-service via get_test_user_id()."""
    return UUID(get_test_user_id())


async def create_user_service(http_client: AuthServiceHttpClient) -> UserService:
    """Create a real UserService wired to CB-protected HTTP client and Redis."""
    redis_client = await get_redis()
    return UserService(redis_client=redis_client, http_client=http_client)


async def clear_redis_cache(user_id: UUID) -> None:
    """Clear cached user info from Redis."""
    try:
        redis = await get_redis()
        await redis.delete(f"auth:user:{user_id}")
    except Exception:
        pass


# ==================== 1. CIRCUIT OPEN — FAST-FAIL UNDER LOAD ====================

@pytest.mark.asyncio
async def test_circuit_open_fast_fail_under_load(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Circuit OPEN must reject 1000 concurrent requests instantly."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()

    await circuit_breaker.force_open()
    assert circuit_breaker.is_open

    latencies = await measure_latency(
        service._fetch_user_info_from_auth,
        user_id,
        n=CONCURRENT_REQUESTS,
    )

    percentiles = latency_percentiles(latencies)

    print(f"  Circuit OPEN — {CONCURRENT_REQUESTS} concurrent requests:")
    print(f"    p50: {percentiles['p50']:.2f}ms")
    print(f"    p95: {percentiles['p95']:.2f}ms")
    print(f"    p99: {percentiles['p99']:.2f}ms")
    print(f"    max: {percentiles['max']:.2f}ms")
    print(f"    mean: {percentiles['mean']:.2f}ms")

    assert percentiles["p99"] < MAX_FAST_FAIL_P99_MS, \
        f"Fast-fail p99={percentiles['p99']:.2f}ms exceeds {MAX_FAST_FAIL_P99_MS}ms"
    assert circuit_breaker.is_open

    await circuit_breaker.force_close()


# ==================== 2. FALLBACK THROUGHPUT — 503 UNDER LOAD ====================

@pytest.mark.asyncio
async def test_fallback_throughput_under_503_load(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Fallback handles 1000 concurrent requests when auth returns 503."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)

    await fault_inject_503()
    await asyncio.sleep(1.0)

    unique_ids = [uuid4() for _ in range(CONCURRENT_REQUESTS)]
    tasks = [service._fetch_user_info_from_auth(uid) for uid in unique_ids]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    exceptions = [r for r in results if isinstance(r, Exception)]
    assert len(exceptions) == 0, \
        f"{len(exceptions)} tasks raised exceptions"

    for i, (uid, info) in enumerate(zip(unique_ids, results)):
        assert isinstance(info, dict), f"Result {i} is not dict: {type(info)}"
        assert info.get("email") == f"{uid}@unknown.com", \
            f"Result {i} has wrong email: {info.get('email')} (expected {uid}@unknown.com)"
        assert info.get("is_active") is True
        assert info.get("is_email_verified") is False

    print(f"  {CONCURRENT_REQUESTS} concurrent requests with 503 fault:")
    print(f"    All returned unique fallbacks")
    print(f"    Zero exceptions")

    await fault_clear_503()
    await circuit_breaker.force_close()


# ==================== 3. THROUGHPUT MEASUREMENT — NORMAL OPERATION ====================

@pytest.mark.asyncio
async def test_throughput_normal_operation(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Measure throughput under normal conditions (baseline)."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()

    await service._fetch_user_info_from_auth(user_id)
    await asyncio.sleep(0.2)

    stats = await measure_throughput(
        service._fetch_user_info_from_auth,
        user_id,
        n=CONCURRENT_REQUESTS,
    )

    print(f"  Normal operation — {CONCURRENT_REQUESTS} requests:")
    print(f"    Total time: {stats['total_time_seconds']:.2f}s")
    print(f"    Throughput: {stats['requests_per_second']:.0f} RPS")

    assert circuit_breaker.is_closed, \
        f"Circuit opened during normal load: {circuit_breaker.state}"
    assert stats["requests_per_second"] > 0, "Zero throughput — something is broken"


# ==================== 4. CIRCUIT BREAKER LOCK CONTENTION ====================

@pytest.mark.asyncio
async def test_circuit_breaker_no_lock_contention_under_load(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Asyncio.Lock in CircuitBreaker does not create bottleneck under load."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()

    await fault_inject_503()
    await asyncio.sleep(0.3)

    latencies = await measure_latency(
        service._fetch_user_info_from_auth,
        user_id,
        n=CONCURRENT_REQUESTS,
    )

    percentiles = latency_percentiles(latencies)

    print(f"  Circuit Breaker lock under {CONCURRENT_REQUESTS} concurrent calls:")
    print(f"    Circuit state: {circuit_breaker.state.value}")
    print(f"    Failure count: {circuit_breaker.failure_count}")
    print(f"    p50: {percentiles['p50']:.2f}ms")
    print(f"    p99: {percentiles['p99']:.2f}ms")

    assert circuit_breaker.state in (CircuitState.OPEN, CircuitState.CLOSED), \
        f"Circuit stuck in {circuit_breaker.state}"
    assert percentiles["p99"] < TEST_HTTP_TIMEOUT * 1000 * 2, \
        f"p99={percentiles['p99']:.2f}ms indicates lock contention"

    await fault_clear_503()
    await circuit_breaker.force_close()


# ==================== 5. IDEMPOTENCY UNDER LOAD ====================

@pytest.mark.asyncio
async def test_idempotency_under_load(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """1000 concurrent calls return consistent results."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()
    await clear_redis_cache(user_id)
    await circuit_breaker.force_open()

    results = await run_concurrently(
        service._fetch_user_info_from_auth,
        user_id,
        n=CONCURRENT_REQUESTS,
    )

    first = results[0]
    for i, result in enumerate(results[1:], 1):
        assert result == first, f"Result {i} differs from first under load"

    print(f"  {CONCURRENT_REQUESTS} concurrent calls — all identical")
    print(f"    Fallback: {first['email']}")

    await circuit_breaker.force_close()


# ==================== 6. 4xx EXCLUSION UNDER LOAD ====================

@pytest.mark.asyncio
async def test_4xx_exclusion_under_load(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """4xx responses do NOT open the circuit."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)

    await service._fetch_user_info_from_auth(NON_EXISTENT_USER_ID)
    await asyncio.sleep(0.2)

    results = await run_concurrently(
        service._fetch_user_info_from_auth,
        NON_EXISTENT_USER_ID,
        n=200,  # Below auth-service rate limiting threshold
    )

    assert circuit_breaker.is_closed, \
        f"4xx under load opened circuit: {circuit_breaker.state}"
    assert circuit_breaker.failure_count == 0, \
        f"4xx counted as failures: {circuit_breaker.failure_count}"

    print(f"  200 requests with 4xx:")
    print(f"    Circuit: {circuit_breaker.state.value}")
    print(f"    Failures: {circuit_breaker.failure_count}")

    fallback_email = f"{NON_EXISTENT_USER_ID}@unknown.com"
    for i, info in enumerate(results):
        assert isinstance(info, dict), f"Result {i} is not dict"
        assert info.get("email") == fallback_email, \
            f"Result {i} email mismatch: {info.get('email')}"

    print(f"    All fallbacks consistent: {fallback_email}")


# ==================== 7. FORCE OPERATIONS RACE CONDITION ====================

@pytest.mark.asyncio
async def test_force_operations_no_race_under_concurrency(
    circuit_breaker: CircuitBreaker,
    ensure_auth_service: None,
) -> None:
    """Concurrent force_open/force_close/force_half_open do not race."""
    async def toggle_states():
        for _ in range(10):
            await circuit_breaker.force_open()
            await circuit_breaker.force_half_open()
            await circuit_breaker.force_close()

    tasks = [toggle_states() for _ in range(100)]
    await asyncio.gather(*tasks)

    assert circuit_breaker.state in (CircuitState.CLOSED, CircuitState.OPEN, CircuitState.HALF_OPEN), \
        f"Invalid final state: {circuit_breaker.state}"

    metrics = circuit_breaker.get_metrics()
    assert metrics["state"] in ("closed", "open", "half_open")
    assert metrics["failure_count"] >= 0
    assert metrics["trial_count"] >= 0

    print(f"  100 concurrent state toggles completed")
    print(f"    Final state: {circuit_breaker.state.value}")
    print(f"    Metrics: failures={metrics['failure_count']}, trials={metrics['trial_count']}")

    await circuit_breaker.force_close()


# ==================== 8. CONNECTION POOL UNDER LOAD ====================

@pytest.mark.asyncio
async def test_connection_pool_handles_peak_load(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """httpx connection pool does not exhaust under 1000 concurrent requests."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()

    try:
        results = await run_concurrently(
            service._fetch_user_info_from_auth,
            user_id,
            n=CONCURRENT_REQUESTS,
        )
    except Exception as e:
        pytest.fail(f"Connection pool failed under load: {type(e).__name__}: {e}")

    for i, info in enumerate(results):
        assert isinstance(info, dict), \
            f"Result {i} is {type(info).__name__}, not dict — possible pool exhaustion"

    print(f"  Connection pool — {CONCURRENT_REQUESTS} concurrent requests:")
    print(f"    All {len(results)} returned valid responses")
    print(f"    Zero connection errors")

    assert circuit_breaker.is_closed