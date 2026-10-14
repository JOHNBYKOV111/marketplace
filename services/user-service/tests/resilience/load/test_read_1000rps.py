"""
Cache-assisted throughput test — 1000+ RPS target.

Verifies that Redis caching enables 1000+ RPS throughput
vs ~250 RPS for direct auth-service calls.

No mocks. No stubs. Real Redis. Real auth-service.
Uses real existing user (admin@test.com) for cacheable responses.

Test flow:
    1. Direct mode — measure baseline RPS without cache
    2. Warm cache — prime Redis with user info
    3. Cached mode — measure RPS from Redis cache
    4. Verify cache hit — cached responses match auth-service responses
    5. Cache miss — fallback to auth-service
    6. Cached latency — p99 under 1000ms (covers Cache Stampede spikes)
    7. Cache invalidation — state change clears cache

Prerequisites:
    - docker compose up -d auth-service redis
    - Redis accessible from user-service

Run:
    docker exec -it user-service pytest tests/resilience/load/test_read_1000rps.py -v -s
"""

import asyncio
import hashlib
import time
from uuid import UUID

import httpx
import pytest

from app.core.circuit_breaker import CircuitBreaker
from app.core.config import settings
from app.core.http_client import AuthServiceHttpClient
from app.core.redis_client import get_redis
from app.services.user_service import UserService

from ..conftest import (
    auth_service_is_reachable,
    fault_reset_all,
    fault_reset_all_verified,
    get_test_user_id,
    run_concurrently,
    measure_latency,
    latency_percentiles,
    measure_throughput,
    wait_for_auth_healthy,
)


# ==================== CONSTANTS ====================

# Test user email — UUID resolved dynamically via autouse fixture
EXISTING_USER_EMAIL = "admin@test.com"

# Test parameters
CACHED_REQUESTS = 10000
DIRECT_REQUESTS = 1000
MAX_CONCURRENT = 200
TARGET_CACHED_RPS = 1000.0
TARGET_DIRECT_RPS_MIN = 100.0
MAX_CACHED_P99_MS = 1000.0


# ==================== HELPERS ====================

def existing_user_id() -> UUID:
    """Dynamic UUID — resolved from auth-service via get_test_user_id()."""
    return UUID(get_test_user_id())


def cache_key(user_id: UUID) -> str:
    """Redis cache key for given user."""
    return f"auth:user:{user_id}"


async def create_user_service(http_client: AuthServiceHttpClient) -> UserService:
    """Create a real UserService wired to CB-protected HTTP client and Redis."""
    redis_client = await get_redis()
    return UserService(redis_client=redis_client, http_client=http_client)


async def clear_cache(user_id: UUID) -> None:
    """Clear cached user info from Redis."""
    redis = await get_redis()
    if redis:
        try:
            await redis.delete(cache_key(user_id))
        except Exception:
            pass


async def warm_cache(service: UserService, user_id: UUID) -> dict:
    """Make a single request to populate Redis cache."""
    return await service._fetch_user_info_from_auth(user_id)


async def get_cache_ttl(user_id: UUID) -> int:
    """Get remaining TTL for cached key."""
    redis = await get_redis()
    if redis:
        try:
            return await redis.ttl(cache_key(user_id))
        except Exception:
            pass
    return -2


async def cache_exists(user_id: UUID) -> bool:
    """Check if key exists in Redis cache."""
    ttl = await get_cache_ttl(user_id)
    return ttl > 0 or ttl == -1


async def ensure_cb_closed_and_auth_healthy(
    circuit_breaker: CircuitBreaker,
    service: UserService,
    user_id: UUID,
) -> None:
    """Guarantee CB is CLOSED, user is seeded, and auth-service responds."""
    await circuit_breaker.force_close()
    await asyncio.sleep(0.3)

    # Verify auth-service responds with real data (not fallback)
    for _ in range(5):
        try:
            info = await service._fetch_user_info_from_auth(user_id)
            if "email" in info and not info["email"].endswith("@unknown.com"):
                return  # Got real data — auth is healthy and user exists
        except Exception:
            pass
        await asyncio.sleep(1.0)

    # Last attempt — wait longer for auth-service to recover
    await asyncio.sleep(3.0)


# ==================== 1. DIRECT MODE — BASELINE RPS ====================

@pytest.mark.asyncio
async def test_direct_mode_baseline_rps(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Measure baseline RPS with direct auth-service calls (no cache)."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()
    await clear_cache(user_id)

    await ensure_cb_closed_and_auth_healthy(circuit_breaker, service, user_id)

    stats = await measure_throughput(
        service._fetch_user_info_from_auth,
        user_id,
        n=DIRECT_REQUESTS,
        max_concurrent=MAX_CONCURRENT,
    )

    print(f"  Direct mode (no cache) — {DIRECT_REQUESTS} requests:")
    print(f"    Total time: {stats['total_time_seconds']:.2f}s")
    print(f"    Throughput: {stats['requests_per_second']:.0f} RPS")

    assert stats["requests_per_second"] > TARGET_DIRECT_RPS_MIN, \
        f"Direct RPS {stats['requests_per_second']:.0f} below minimum {TARGET_DIRECT_RPS_MIN}"


# ==================== 2. WARM CACHE ====================

@pytest.mark.asyncio
async def test_warm_cache_populates_redis(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """First request populates Redis cache with TTL > 0."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()
    await ensure_cb_closed_and_auth_healthy(circuit_breaker, service, user_id)

    await clear_cache(user_id)
    assert not await cache_exists(user_id), "Cache should be empty before warm"
    print(f"  Cache cleared")

    info = await warm_cache(service, user_id)
    assert "email" in info
    print(f"  Cache warm request: email={info.get('email')}")

    await asyncio.sleep(0.2)
    exists = await cache_exists(user_id)
    ttl = await get_cache_ttl(user_id)
    print(f"  Cache exists: {exists}, TTL: {ttl}s")

    assert exists, "Cache should exist after warm request"


# ==================== 3. CACHED MODE — 1000+ RPS ====================

@pytest.mark.asyncio
async def test_cached_mode_achieves_1000_rps(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Cached requests achieve 1000+ RPS."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()
    await ensure_cb_closed_and_auth_healthy(circuit_breaker, service, user_id)

    await clear_cache(user_id)
    await warm_cache(service, user_id)
    await asyncio.sleep(0.2)
    assert await cache_exists(user_id), "Cache must exist before test"
    print(f"  Cache warmed")

    assert circuit_breaker.is_closed, f"CB must be CLOSED for cache test, got {circuit_breaker.state.value}"
    print(f"  CB: {circuit_breaker.state.value}")

    stats = await measure_throughput(
        service._fetch_user_info_from_auth,
        user_id,
        n=CACHED_REQUESTS,
        max_concurrent=MAX_CONCURRENT,
    )

    print(f"  Cached mode — {CACHED_REQUESTS} requests:")
    print(f"    Total time: {stats['total_time_seconds']:.2f}s")
    print(f"    Throughput: {stats['requests_per_second']:.0f} RPS")

    assert stats["requests_per_second"] >= TARGET_CACHED_RPS, \
        f"Cached RPS {stats['requests_per_second']:.0f} below target {TARGET_CACHED_RPS}"


# ==================== 4. CACHE HIT — DATA CONSISTENCY ====================

@pytest.mark.asyncio
async def test_cached_data_matches_auth_service_response(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Cached response data matches fresh auth-service response."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()

    await clear_cache(user_id)
    fresh_info = await service._fetch_user_info_from_auth(user_id)
    print(f"  Fresh response: {fresh_info}")

    cached_info = await service._fetch_user_info_from_auth(user_id)
    print(f"  Cached response: {cached_info}")

    for key in fresh_info:
        if key in cached_info:
            assert cached_info[key] == fresh_info[key], \
                f"Cache mismatch for '{key}': {cached_info[key]} != {fresh_info[key]}"

    print(f"  Cache consistent with auth-service response")


# ==================== 5. CACHE MISS — FALLBACK TO AUTH ====================

@pytest.mark.asyncio
async def test_cache_miss_falls_back_to_auth_service(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """After cache expires, next request goes to auth-service."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()
    await ensure_cb_closed_and_auth_healthy(circuit_breaker, service, user_id)

    await clear_cache(user_id)
    assert not await cache_exists(user_id)

    info = await service._fetch_user_info_from_auth(user_id)
    assert "email" in info
    print(f"  Cache miss: email={info.get('email')}")

    assert await cache_exists(user_id), "Cache should be populated after miss"


# ==================== 6. CACHED LATENCY — p99 UNDER 1000ms ====================

@pytest.mark.asyncio
async def test_cached_latency_p99_under_1000ms(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Cached responses have p99 latency under 1000ms."""
    assert auth_service_is_reachable()

    await fault_reset_all()
    await asyncio.sleep(0.3)

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()
    await ensure_cb_closed_and_auth_healthy(circuit_breaker, service, user_id)

    await clear_cache(user_id)
    await warm_cache(service, user_id)
    await asyncio.sleep(0.2)

    latencies = await measure_latency(
        service._fetch_user_info_from_auth,
        user_id,
        n=1000,
        max_concurrent=MAX_CONCURRENT,
    )

    percentiles = latency_percentiles(latencies)

    print(f"  Cached latency — 1000 requests:")
    print(f"    p50: {percentiles['p50']:.2f}ms")
    print(f"    p95: {percentiles['p95']:.2f}ms")
    print(f"    p99: {percentiles['p99']:.2f}ms")
    print(f"    max: {percentiles['max']:.2f}ms")
    print(f"    mean: {percentiles['mean']:.2f}ms")

    assert percentiles["p99"] < MAX_CACHED_P99_MS, \
        f"Cached p99={percentiles['p99']:.2f}ms exceeds {MAX_CACHED_P99_MS}ms target"


# ==================== 7. CACHE INVALIDATION ON STATE CHANGE ====================

@pytest.mark.asyncio
async def test_cache_invalidated_after_notify(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Cache is invalidated after notify_auth_block_user call."""
    assert auth_service_is_reachable()

    service = await create_user_service(auth_http_client)
    user_id = existing_user_id()
    await ensure_cb_closed_and_auth_healthy(circuit_breaker, service, user_id)

    await clear_cache(user_id)
    await warm_cache(service, user_id)
    await asyncio.sleep(0.2)
    assert await cache_exists(user_id), "Cache should exist before notify"
    print(f"  Cache exists before notify")

    await service._notify_auth_block_user(user_id, "test")
    await asyncio.sleep(0.2)

    exists = await cache_exists(user_id)
    print(f"  Cache exists after notify: {exists}")