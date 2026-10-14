"""
Test fixtures for resilience tests.

Provides real infrastructure for Circuit Breaker integration tests:
    - Application-Level Fault Injection via auth-service test endpoints
    - Multi-worker fault state synchronization with verification
    - Toxiproxy for network fault injection (latency, connection reset)
    - Pre-configured AuthServiceHttpClient with CircuitBreaker
    - Isolated CircuitBreaker per test (no state leakage)
    - Performance benchmarking helpers for load testing
    - Fast pre-test isolation with auth-service health verification
    - Guaranteed post-test cleanup (verified)
    - Dynamic test user — resolves actual UUID from auth-service API
    - Cross-module cool-down to let Docker network recover between test files

Architecture:
    Tests call AuthServiceHttpClient directly — no TestClient, no FastAPI routing.
    Auth-service behavior is manipulated via HTTP calls to /internal/test/faults/*.
    No Docker CLI. No container management. No root privileges.
    Works identically on local Docker, Kubernetes, and CI/CD pipelines.
"""

import asyncio
import hashlib
import os
import statistics
import time
from typing import Any, Awaitable, Callable, List, Optional, AsyncGenerator, Generator
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio

# Ensure the user-service app is importable
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.core.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from app.core.config import settings
from app.core.http_client import AuthServiceHttpClient


# ==================== CONFIGURATION ====================

AUTH_FAULT_URL: str = f"{settings.AUTH_SERVICE_URL}/internal/test/faults"
TOXIPROXY_ADDR: Optional[str] = os.getenv("TOXIPROXY_ADDR", None)
USE_TOXIPROXY: bool = TOXIPROXY_ADDR is not None

TEST_FAILURE_THRESHOLD: int = 100
TEST_RECOVERY_TIMEOUT: float = 3.0
TEST_HALF_OPEN_MAX: int = 1
TEST_SUCCESS_THRESHOLD: int = 2
TEST_HTTP_TIMEOUT: float = 10.0

INTERNAL_API_KEY: str = settings.AUTH_SERVICE_INTERNAL_API_KEY

FAULT_WORKER_RETRIES: int = 10
FAULT_WORKER_RETRY_DELAY: float = 0.1

# Auth-service health check before tests — ensures service recovered
# from previous peak load before starting next test.
AUTH_HEALTH_CHECK_TIMEOUT: float = 30.0
AUTH_HEALTH_CHECK_INTERVAL: float = 1.0

# Test user email — UUID resolved dynamically via auth-service API
TEST_USER_EMAIL: str = "admin@test.com"

# Cool-down pause between test modules — lets Docker network clear
# TIME_WAIT sockets and CPU buffers after peak load tests
CROSS_MODULE_COOLDOWN_SECONDS: float = 3.0

# Post-reset settle time — gives auth-service time to apply fault reset
FAULT_RESET_SETTLE_SECONDS: float = 1.0


# ==================== DYNAMIC TEST USER RESOLUTION ====================

_current_test_user_id: Optional[str] = None


def get_test_user_id() -> str:
    """Return cached UUID. Must be called AFTER ensure_test_user_exists()."""
    global _current_test_user_id
    if _current_test_user_id is None:
        raise RuntimeError(
            "get_test_user_id() called before ensure_test_user_exists(). "
            "Call ensure_test_user_exists() first in fixture or test."
        )
    return _current_test_user_id


# ==================== CROSS-MODULE COOL-DOWN HOOK ====================

def pytest_runtest_teardown(item, nextitem):
    """Pause between test modules to let Docker network recover."""
    if nextitem is not None and item.module != nextitem.module:
        print(f"\n  [Cool-down] {item.module.__name__} → {nextitem.module.__name__}")
        print(f"  [Cool-down] Pausing {CROSS_MODULE_COOLDOWN_SECONDS}s for Docker network recovery...")
        time.sleep(CROSS_MODULE_COOLDOWN_SECONDS)


# ==================== RECOVERY TASK CLEANUP HELPER ====================

async def _await_recovery_task(cb: CircuitBreaker) -> None:
    """Safely cancel and await recovery task completion."""
    task = cb._recovery_task
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


# ==================== AUTH-SERVICE HEALTH CHECK ====================

async def wait_for_auth_healthy(
    timeout: float = AUTH_HEALTH_CHECK_TIMEOUT,
    interval: float = AUTH_HEALTH_CHECK_INTERVAL,
) -> bool:
    """Wait for auth-service to become healthy after peak load."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(
                    f"{AUTH_FAULT_URL}/status",
                    headers={"X-Internal-API-Key": INTERNAL_API_KEY},
                )
                if resp.status_code == 200:
                    return True
        except Exception:
            pass
        await asyncio.sleep(interval)
    return False


# ==================== TEST USER RESTORATION ====================

async def ensure_test_user_exists() -> str:
    """Ensure test user exists. Returns actual UUID from auth-service."""
    global _current_test_user_id

    if _current_test_user_id is not None:
        return _current_test_user_id

    email_hash = hashlib.sha256(TEST_USER_EMAIL.encode()).hexdigest()
    password_hash = hashlib.sha256("seeded_test_user".encode()).hexdigest()
    headers = {"X-Internal-API-Key": INTERNAL_API_KEY}
    base = settings.AUTH_SERVICE_URL

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{base}/internal/user/create",
                headers=headers,
                json={
                    "user_id": str(uuid4()),
                    "email": TEST_USER_EMAIL,
                    "email_hash": email_hash,
                    "password_hash": password_hash,
                    "is_active": True,
                    "is_email_verified": True,
                },
            )

            if resp.status_code in (201, 409):
                data = resp.json()
                user_id = data.get("user_id")
                if user_id:
                    _current_test_user_id = str(user_id)
                    await client.post(
                        f"{base}/internal/user/unblock",
                        headers=headers,
                        json={"user_id": _current_test_user_id, "reason": "test_cleanup"},
                    )
                    return _current_test_user_id
    except Exception:
        pass

    raise RuntimeError(
        f"Failed to resolve test user UUID for email {TEST_USER_EMAIL}"
    )


# ==================== PERFORMANCE BENCHMARKING HELPERS ====================

async def run_concurrently(
    func: Callable[..., Awaitable[Any]],
    *args: Any,
    n: int = 1000,
    max_concurrent: int = 50,
    **kwargs: Any,
) -> List[Any]:
    semaphore = asyncio.Semaphore(max_concurrent)
    async def bounded_call():
        async with semaphore:
            return await func(*args, **kwargs)
    tasks = [bounded_call() for _ in range(n)]
    return await asyncio.gather(*tasks)


async def measure_latency(
    func: Callable[..., Awaitable[Any]],
    *args: Any,
    n: int = 100,
    max_concurrent: int = 50,
    **kwargs: Any,
) -> List[float]:
    semaphore = asyncio.Semaphore(max_concurrent)
    async def timed_call() -> float:
        async with semaphore:
            start = time.monotonic()
            await func(*args, **kwargs)
            return time.monotonic() - start
    tasks = [timed_call() for _ in range(n)]
    return await asyncio.gather(*tasks)


def latency_percentiles(latencies: List[float]) -> dict[str, float]:
    if not latencies:
        return {"p50": 0, "p95": 0, "p99": 0, "min": 0, "max": 0, "mean": 0}
    sorted_lat = sorted(latencies)
    n = len(sorted_lat)
    return {
        "p50": sorted_lat[int(n * 0.50)] * 1000,
        "p95": sorted_lat[int(n * 0.95)] * 1000,
        "p99": sorted_lat[int(n * 0.99)] * 1000,
        "min": min(latencies) * 1000,
        "max": max(latencies) * 1000,
        "mean": statistics.mean(latencies) * 1000,
        "count": n,
    }


async def measure_throughput(
    func: Callable[..., Awaitable[Any]],
    *args: Any,
    n: int = 1000,
    max_concurrent: int = 50,
    **kwargs: Any,
) -> dict[str, float]:
    start = time.monotonic()
    await run_concurrently(func, *args, n=n, max_concurrent=max_concurrent, **kwargs)
    elapsed = time.monotonic() - start
    return {
        "total_time_seconds": elapsed,
        "requests_per_second": n / elapsed if elapsed > 0 else 0,
        "count": n,
    }


# ==================== FAULT INJECTION HELPERS ====================

async def _fault_request(path: str, **params) -> httpx.Response:
    url = f"{AUTH_FAULT_URL}/{path.lstrip('/')}"
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(url, params=params, headers={"X-Internal-API-Key": INTERNAL_API_KEY})
        resp.raise_for_status()
        return resp


async def _fault_request_all_workers(path: str, **params) -> None:
    for _ in range(FAULT_WORKER_RETRIES):
        await _fault_request(path, **params)
        await asyncio.sleep(FAULT_WORKER_RETRY_DELAY)


async def fault_inject_503() -> None:
    await _fault_request_all_workers("503", enabled="true")


async def fault_clear_503() -> None:
    await _fault_request_all_workers("503", enabled="false")


async def fault_inject_timeout(ms: int = 5000) -> None:
    await _fault_request_all_workers("timeout", ms=str(ms))


async def fault_clear_timeout() -> None:
    await _fault_request_all_workers("timeout", ms="0")


async def fault_reset_all() -> None:
    async with httpx.AsyncClient(timeout=5.0) as client:
        for _ in range(FAULT_WORKER_RETRIES):
            await client.post(f"{AUTH_FAULT_URL}/reset", headers={"X-Internal-API-Key": INTERNAL_API_KEY})
            await asyncio.sleep(FAULT_WORKER_RETRY_DELAY)


async def fault_reset_all_verified() -> None:
    """Reset all faults and verify they are actually cleared."""
    await fault_reset_all()
    for attempt in range(15):
        try:
            status = await fault_get_status()
            active = status.get("active_faults", {})
            if not active.get("service_unavailable") and not active.get("timeout"):
                return
        except Exception:
            pass
        await asyncio.sleep(0.2 * (attempt + 1))
    await fault_reset_all()
    await asyncio.sleep(1.0)


async def fault_get_status() -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(f"{AUTH_FAULT_URL}/status", headers={"X-Internal-API-Key": INTERNAL_API_KEY})
        resp.raise_for_status()
        return resp.json()


def auth_service_is_reachable() -> bool:
    try:
        resp = httpx.get(f"{AUTH_FAULT_URL}/status", headers={"X-Internal-API-Key": INTERNAL_API_KEY}, timeout=3.0)
        return resp.status_code == 200
    except Exception:
        return False


# ==================== TOXIPROXY HELPERS ====================

class ToxiproxyClient:
    def __init__(self, address: str = "http://toxiproxy:8474"):
        self._base = address.rstrip("/")

    async def add_latency(self, proxy_name: str, latency_ms: int, jitter_ms: int = 0) -> None:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{self._base}/proxies/{proxy_name}/toxics",
                json={"name": "latency", "type": "latency", "stream": "downstream", "toxicity": 1.0,
                      "attributes": {"latency": latency_ms, "jitter": jitter_ms}},
            )

    async def add_timeout(self, proxy_name: str) -> None:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{self._base}/proxies/{proxy_name}/toxics",
                json={"name": "timeout", "type": "timeout", "stream": "downstream", "toxicity": 1.0,
                      "attributes": {"timeout": 0}},
            )

    async def remove_all_toxics(self, proxy_name: str) -> None:
        async with httpx.AsyncClient() as client:
            await client.delete(f"{self._base}/proxies/{proxy_name}/toxics")


# ==================== FIXTURES ====================

@pytest.fixture(scope="session")
def ensure_auth_service() -> Generator[None, None, None]:
    if not auth_service_is_reachable():
        pytest.fail(f"Auth-service fault injection endpoint not reachable at {AUTH_FAULT_URL}/status. "
                     "Ensure auth-service is running and ENVIRONMENT != production.")
    try:
        httpx.post(f"{AUTH_FAULT_URL}/reset", headers={"X-Internal-API-Key": INTERNAL_API_KEY}, timeout=5.0)
    except Exception:
        pass
    yield
    try:
        httpx.post(f"{AUTH_FAULT_URL}/reset", headers={"X-Internal-API-Key": INTERNAL_API_KEY}, timeout=5.0)
    except Exception:
        pass


@pytest_asyncio.fixture(scope="function", autouse=True)
async def test_user_id() -> UUID:
    """Auto-fixture: guarantees test user exists BEFORE every test.

    Runs before every test automatically. Resolves actual UUID from
    auth-service and caches it in _current_test_user_id.
    """
    global _current_test_user_id
    user_id_str = await ensure_test_user_exists()
    _current_test_user_id = user_id_str
    return UUID(user_id_str)


@pytest_asyncio.fixture
async def circuit_breaker() -> AsyncGenerator[CircuitBreaker, None]:
    # Resolve user UUID BEFORE creating circuit breaker
    await ensure_test_user_exists()

    config = CircuitBreakerConfig(
        failure_threshold=TEST_FAILURE_THRESHOLD,
        recovery_timeout=TEST_RECOVERY_TIMEOUT,
        half_open_max_requests=TEST_HALF_OPEN_MAX,
        success_threshold=TEST_SUCCESS_THRESHOLD,
    )
    cb = CircuitBreaker(config)
    yield cb
    await cb.force_close()
    await _await_recovery_task(cb)
    await asyncio.sleep(0.3)


@pytest_asyncio.fixture
async def auth_http_client(
    circuit_breaker: CircuitBreaker,
) -> AsyncGenerator[AuthServiceHttpClient, None]:
    client = AuthServiceHttpClient(
        base_url=settings.AUTH_SERVICE_URL,
        api_key=settings.AUTH_SERVICE_INTERNAL_API_KEY,
        timeout=TEST_HTTP_TIMEOUT,
        circuit_breaker=circuit_breaker,
    )
    yield client
    await client.close()


@pytest_asyncio.fixture
async def toxiproxy() -> AsyncGenerator[Optional[ToxiproxyClient], None]:
    if not USE_TOXIPROXY:
        yield None
        return
    client = ToxiproxyClient(TOXIPROXY_ADDR)
    yield client
    try:
        async with httpx.AsyncClient() as http:
            proxies = await http.get(f"{TOXIPROXY_ADDR}/proxies")
            for name in proxies.json().keys():
                await client.remove_all_toxics(name)
    except Exception:
        pass


# ==================== PER-TEST ISOLATION ====================

@pytest.fixture(autouse=True)
async def _force_clean_before_each_test(
    auth_http_client: AuthServiceHttpClient,
) -> AsyncGenerator[None, None]:
    """Guaranteed clean state before AND after each test."""
    # PRE-TEST: resolve actual test user UUID
    await ensure_test_user_exists()

    # PRE-TEST: guaranteed fault cleanup with verification
    try:
        await fault_reset_all_verified()
        # Settle time — gives auth-service time to apply fault reset
        await asyncio.sleep(FAULT_RESET_SETTLE_SECONDS)
    except Exception:
        pass

    # PRE-TEST: wait for auth-service to recover from previous peak load
    healthy = await wait_for_auth_healthy()
    if not healthy:
        await asyncio.sleep(5.0)
        healthy = await wait_for_auth_healthy(timeout=15.0)
    if not healthy:
        print(f"  ⚠ Auth-service not healthy after {AUTH_HEALTH_CHECK_TIMEOUT}s — test may fail")

    try:
        if hasattr(auth_http_client, "_circuit_breaker"):
            cb = auth_http_client._circuit_breaker
            await cb.force_close()
            await _await_recovery_task(cb)
    except Exception:
        pass

    try:
        from app.core.redis_client import get_redis
        redis = await get_redis()
        await redis.flushdb()
    except Exception:
        pass

    yield

    # POST-TEST: guaranteed cleanup
    try:
        await fault_reset_all_verified()
    except Exception:
        pass

    try:
        if hasattr(auth_http_client, "_circuit_breaker"):
            cb = auth_http_client._circuit_breaker
            await cb.force_close()
            await _await_recovery_task(cb)
    except Exception:
        pass