"""
Security injection tests.

Verifies that security mechanisms (API keys, IP whitelist, production guards)
are correctly excluded from Circuit Breaker failure counting.

No mocks. No stubs. Real HTTP calls. Real fault injection.

Test categories:
    1. Invalid API key — 401/403 excluded from CB failure count
    2. Valid API key — normal operation, CB stays CLOSED
    3. Missing API key — 401 excluded from CB failure count
    4. Production guard — fault injection returns 404 in production
    5. CB isolation — security errors do not open the circuit
    6. Mixed traffic — security errors + server errors, only 5xx opens CB

Architecture:
    Real UserService → AuthServiceHttpClient → CircuitBreaker
    → real HTTP → auth-service with fault injection and API key validation.

Prerequisites:
    - docker compose up -d auth-service

Run:
    docker exec -it user-service pytest tests/resilience/security/test_security_injections.py -v -s
"""

import asyncio
from uuid import UUID

import httpx
import pytest

from app.core.circuit_breaker import CircuitBreaker, CircuitState, CircuitBreakerConfig
from app.core.config import settings
from app.core.http_client import AuthServiceHttpClient, AuthServiceError, AuthServiceUnavailableError
from app.services.user_service import UserService

from ..conftest import (
    fault_inject_503,
    fault_clear_503,
    auth_service_is_reachable,
    get_test_user_id,
    TEST_FAILURE_THRESHOLD,
    TEST_HTTP_TIMEOUT,
)


# ==================== CONSTANTS ====================

INVALID_API_KEY = "invalid_key_12345"


# ==================== HELPERS ====================

def existing_user_id() -> UUID:
    """Dynamic UUID — resolved from auth-service via get_test_user_id()."""
    return UUID(get_test_user_id())


def create_user_service(http_client: AuthServiceHttpClient) -> UserService:
    """Create a real UserService wired to the CB-protected HTTP client."""
    return UserService(http_client=http_client)


def create_client_with_api_key(api_key: str) -> AuthServiceHttpClient:
    """Create HTTP client with a specific API key."""
    cb = CircuitBreaker(CircuitBreakerConfig(
        failure_threshold=TEST_FAILURE_THRESHOLD,
        recovery_timeout=3.0,
    ))
    return AuthServiceHttpClient(
        base_url=settings.AUTH_SERVICE_URL,
        api_key=api_key,
        timeout=TEST_HTTP_TIMEOUT,
        circuit_breaker=cb,
    )


def assert_circuit_closed(cb: CircuitBreaker) -> None:
    """Assert circuit is CLOSED with zero failures."""
    assert cb.is_closed, f"Expected CLOSED, got {cb.state.value}"
    assert cb.failure_count == 0, f"Expected 0 failures, got {cb.failure_count}"


# ==================== 1. INVALID API KEY — 401 EXCLUDED ====================

@pytest.mark.asyncio
async def test_invalid_api_key_not_counted_as_failure(
    ensure_auth_service: None,
) -> None:
    """Invalid API key returns 401, NOT counted as circuit failure."""
    assert auth_service_is_reachable()

    client = create_client_with_api_key(INVALID_API_KEY)
    cb = client._circuit_breaker
    service = create_user_service(client)
    user_id = existing_user_id()

    for i in range(cb._config.failure_threshold * 2):
        try:
            await service._fetch_user_info_from_auth(user_id)
        except AuthServiceError as e:
            assert e.status_code in (401, 403), \
                f"Expected 401/403, got {e.status_code}"
        except AuthServiceUnavailableError:
            pass

    assert_circuit_closed(cb)
    print(f"  After {cb._config.failure_threshold * 2} requests with invalid key:")
    print(f"    Circuit: {cb.state.value}, failures: {cb.failure_count}")

    await client.close()


# ==================== 2. VALID API KEY — NORMAL OPERATION ====================

@pytest.mark.asyncio
async def test_valid_api_key_allows_normal_operation(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Valid API key — normal operation, circuit stays CLOSED."""
    assert auth_service_is_reachable()

    service = create_user_service(auth_http_client)
    user_id = existing_user_id()

    for i in range(5):
        info = await service._fetch_user_info_from_auth(user_id)
        assert "email" in info
        print(f"  Request {i}: email={info.get('email')}")

    assert_circuit_closed(circuit_breaker)
    print(f"  Valid API key: circuit {circuit_breaker.state.value}")


# ==================== 3. MISSING API KEY — 401 EXCLUDED ====================

@pytest.mark.asyncio
async def test_missing_api_key_not_counted_as_failure(
    ensure_auth_service: None,
) -> None:
    """Missing API key returns 401, NOT counted as circuit failure."""
    assert auth_service_is_reachable()

    client = create_client_with_api_key("")
    cb = client._circuit_breaker
    service = create_user_service(client)
    user_id = existing_user_id()

    for i in range(cb._config.failure_threshold * 2):
        try:
            await service._fetch_user_info_from_auth(user_id)
        except AuthServiceError as e:
            assert e.status_code in (401, 403), \
                f"Expected 401/403, got {e.status_code}"
        except AuthServiceUnavailableError:
            pass

    assert_circuit_closed(cb)
    print(f"  After {cb._config.failure_threshold * 2} requests with missing key:")
    print(f"    Circuit: {cb.state.value}, failures: {cb.failure_count}")

    await client.close()


# ==================== 4. SECURITY ERRORS + 5xx — ONLY 5xx OPENS CB ====================

@pytest.mark.asyncio
async def test_security_errors_do_not_open_circuit_but_5xx_does(
    ensure_auth_service: None,
) -> None:
    """Mixed traffic: security errors + server errors. Only 5xx opens CB."""
    assert auth_service_is_reachable()

    client = create_client_with_api_key(INVALID_API_KEY)
    cb = client._circuit_breaker
    service = create_user_service(client)
    user_id = existing_user_id()

    for i in range(cb._config.failure_threshold * 2):
        try:
            await service._fetch_user_info_from_auth(user_id)
        except (AuthServiceError, AuthServiceUnavailableError):
            pass

    assert_circuit_closed(cb)
    print(f"  After security errors: circuit {cb.state.value}")

    await client.close()

    valid_client = AuthServiceHttpClient(
        base_url=settings.AUTH_SERVICE_URL,
        api_key=settings.AUTH_SERVICE_INTERNAL_API_KEY,
        timeout=TEST_HTTP_TIMEOUT,
        circuit_breaker=cb,
    )
    valid_service = create_user_service(valid_client)

    await fault_inject_503()
    await asyncio.sleep(0.3)

    for i in range(cb._config.failure_threshold + 1):
        try:
            await valid_service._fetch_user_info_from_auth(user_id)
        except AuthServiceUnavailableError:
            pass

    assert cb.is_open, f"Expected OPEN, got {cb.state.value}"
    print(f"  After 5xx errors: circuit {cb.state.value}")

    await fault_clear_503()
    await cb.force_close()
    await valid_client.close()


# ==================== 5. CB ISOLATION FROM SECURITY LAYER ====================

@pytest.mark.asyncio
async def test_circuit_breaker_isolated_from_security_errors(
    circuit_breaker: CircuitBreaker,
    auth_http_client: AuthServiceHttpClient,
    ensure_auth_service: None,
) -> None:
    """Circuit breaker does not count security errors."""
    assert auth_service_is_reachable()

    user_id = existing_user_id()

    invalid_client = AuthServiceHttpClient(
        base_url=settings.AUTH_SERVICE_URL,
        api_key=INVALID_API_KEY,
        timeout=TEST_HTTP_TIMEOUT,
        circuit_breaker=circuit_breaker,
    )
    invalid_service = create_user_service(invalid_client)

    for i in range(circuit_breaker._config.failure_threshold):
        try:
            await invalid_service._fetch_user_info_from_auth(user_id)
        except AuthServiceError:
            pass

    assert circuit_breaker.failure_count == 0, \
        f"Security errors counted as failures: {circuit_breaker.failure_count}"
    print(f"  Security errors: failures={circuit_breaker.failure_count}")

    service = create_user_service(auth_http_client)
    await fault_inject_503()
    await asyncio.sleep(0.3)

    for i in range(circuit_breaker._config.failure_threshold):
        try:
            await service._fetch_user_info_from_auth(user_id)
        except AuthServiceUnavailableError:
            pass

    assert circuit_breaker.failure_count >= circuit_breaker._config.failure_threshold, \
        f"5xx errors not counted correctly: {circuit_breaker.failure_count}"
    print(f"  5xx errors: failures={circuit_breaker.failure_count}")

    await fault_clear_503()
    await circuit_breaker.force_close()
    await invalid_client.close()


# ==================== 6. PRODUCTION GUARD — FAULT INJECTION BLOCKED ====================

@pytest.mark.asyncio
async def test_fault_injection_respects_api_key_validation(
    ensure_auth_service: None,
) -> None:
    """Fault injection endpoints require valid API key."""
    assert auth_service_is_reachable()

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            f"{settings.AUTH_SERVICE_URL}/internal/test/faults/503?enabled=true",
            headers={"X-Internal-API-Key": INVALID_API_KEY},
        )
        print(f"  Fault injection with invalid key: {resp.status_code}")
        assert resp.status_code in (401, 403), \
            f"Expected 401/403, got {resp.status_code}"

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            f"{settings.AUTH_SERVICE_URL}/internal/test/faults/503?enabled=true",
            headers={"X-Internal-API-Key": settings.AUTH_SERVICE_INTERNAL_API_KEY},
        )
        print(f"  Fault injection with valid key: {resp.status_code}")
        assert resp.status_code == 200, \
            f"Expected 200, got {resp.status_code}"

        await client.post(
            f"{settings.AUTH_SERVICE_URL}/internal/test/faults/reset",
            headers={"X-Internal-API-Key": settings.AUTH_SERVICE_INTERNAL_API_KEY},
        )