"""
Circuit Breaker pattern implementation for inter-service resilience.

States:
    CLOSED    — normal operation, requests pass through
    OPEN      — failures exceeded threshold, requests fail-fast
    HALF_OPEN — recovery timeout expired, limited trial requests allowed

Lifecycle:
    CLOSED → (failures >= threshold) → OPEN
    OPEN → (recovery_timeout elapsed, background task) → HALF_OPEN
    HALF_OPEN → (successes >= success_threshold) → CLOSED
    HALF_OPEN → (any failure) → OPEN

Key design decisions:
    - HALF_OPEN trial counter tracks CONCURRENT in-flight requests only.
    - Pre-call check holds the lock for MINIMAL time: reads state atomically
      and releases before I/O. Post-call processing holds the lock briefly
      to update counters. No I/O under lock.
    - HTTP status codes are evaluated: 5xx = failure, 4xx = excluded, 2xx = success.
    - State transitions from OPEN to HALF_OPEN happen via a background asyncio task,
      so metrics always reflect the real current state.
    - All counters reset atomically on state transition boundaries.
    - force_close() and __aexit__() AWAIT cancellation of the recovery task
      OUTSIDE the lock, preventing both deadlocks and pending task warnings.
    - call_with_fallback() triggers fallback on ANY failure.
    - Designed for a single CircuitBreaker instance per external dependency.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Optional

from app.core.logging import get_logger

logger = get_logger(__name__)


# ==================== DOMAIN TYPES ====================

class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True)
class CircuitBreakerConfig:
    """Immutable configuration for CircuitBreaker."""

    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_requests: int = 1
    success_threshold: int = 2
    excluded_status_codes: set[int] = field(default_factory=lambda: {400, 401, 403, 404, 409, 422})
    failure_status_codes: set[int] = field(default_factory=lambda: {500, 502, 503, 504})


class CircuitBreakerOpenError(Exception):
    """Raised when a request is rejected — circuit is OPEN or HALF_OPEN saturated."""

    def __init__(self, message: str = "Circuit breaker is OPEN — request rejected"):
        self.message = message
        super().__init__(self.message)


AsyncCallable = Callable[..., Coroutine[Any, Any, Any]]


# ==================== CALL RESULT ====================

@dataclass(frozen=True)
class _CallResult:
    """Internal result envelope so _on_success/_on_failure can inspect HTTP status."""

    success: bool
    status_code: Optional[int] = None
    error: Optional[Exception] = None


# ==================== CIRCUIT BREAKER ====================

class CircuitBreaker:
    """Production-grade Circuit Breaker for protecting external service calls."""

    def __init__(self, config: CircuitBreakerConfig) -> None:
        self._config = config
        self._state: CircuitState = CircuitState.CLOSED
        self._failure_count: int = 0
        self._success_count: int = 0
        self._trial_count: int = 0
        self._last_failure_time: float = 0.0
        self._state_changed_at: float = time.monotonic()
        self._lock: asyncio.Lock = asyncio.Lock()
        self._recovery_task: Optional[asyncio.Task[None]] = None

    # ==================== PUBLIC API ====================

    async def call(
        self,
        func: AsyncCallable,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Execute a call through the circuit breaker."""
        self._ensure_recovery_task()

        async with self._lock:
            current_state = self._state
            if current_state == CircuitState.OPEN:
                raise CircuitBreakerOpenError("Circuit is OPEN")
            if current_state == CircuitState.HALF_OPEN:
                if self._trial_count >= self._config.half_open_max_requests:
                    raise CircuitBreakerOpenError("Circuit is HALF_OPEN — trial limit reached")
                self._trial_count += 1

        result: _CallResult
        try:
            response = await func(*args, **kwargs)
            status_code = getattr(response, "status_code", None)
            if status_code is not None and status_code in self._config.failure_status_codes:
                result = _CallResult(success=False, status_code=status_code)
            elif status_code is not None and status_code in self._config.excluded_status_codes:
                result = _CallResult(success=True, status_code=status_code)
            else:
                result = _CallResult(success=True, status_code=status_code)
        except CircuitBreakerOpenError:
            raise
        except Exception as exc:
            result = _CallResult(success=False, error=exc)

        async with self._lock:
            if result.success:
                self._on_success_locked()
            else:
                self._on_failure_locked(result.error)

        if not result.success and result.error is not None:
            raise result.error

        return response

    async def call_with_fallback(
        self,
        func: AsyncCallable,
        fallback: AsyncCallable,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Execute with fallback on ANY failure."""
        try:
            result = await self.call(func, *args, **kwargs)
            status_code = getattr(result, "status_code", None)
            if status_code is not None and status_code in self._config.failure_status_codes:
                logger.debug("Circuit breaker — 5xx response, executing fallback")
                return await fallback(*args, **kwargs)
            return result
        except (CircuitBreakerOpenError, Exception):
            logger.debug("Circuit breaker — exception, executing fallback")
            return await fallback(*args, **kwargs)

    # ==================== MANUAL CONTROL (for tests & ops) ====================

    async def force_open(self) -> None:
        """Force the circuit OPEN. Schedules a new recovery task."""
        async with self._lock:
            self._cancel_recovery_task()
            self._failure_count = self._config.failure_threshold
            self._success_count = 0
            self._trial_count = 0
            self._last_failure_time = time.monotonic()
            self._transition_to(CircuitState.OPEN)
            self._schedule_recovery()

    async def force_close(self) -> None:
        """Force the circuit CLOSED, resetting all counters.

        Cancels recovery task under lock, then AWAITS its completion
        OUTSIDE the lock. This prevents both deadlocks and
        'Task was destroyed but it is pending' warnings.
        """
        task: Optional[asyncio.Task[None]] = None
        async with self._lock:
            task = self._recovery_task
            self._recovery_task = None
            if task is not None and not task.done():
                task.cancel()
            self._failure_count = 0
            self._success_count = 0
            self._trial_count = 0
            self._transition_to(CircuitState.CLOSED)

        # Await task completion OUTSIDE the lock — no deadlock
        if task is not None:
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def force_half_open(self) -> None:
        """Force the circuit HALF_OPEN."""
        task: Optional[asyncio.Task[None]] = None
        async with self._lock:
            task = self._recovery_task
            self._recovery_task = None
            if task is not None and not task.done():
                task.cancel()
            self._failure_count = 0
            self._success_count = 0
            self._trial_count = 0
            self._transition_to(CircuitState.HALF_OPEN)

        if task is not None:
            try:
                await task
            except asyncio.CancelledError:
                pass

    # ==================== METRICS ====================

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def failure_count(self) -> int:
        return self._failure_count

    @property
    def is_open(self) -> bool:
        return self._state == CircuitState.OPEN

    @property
    def is_closed(self) -> bool:
        return self._state == CircuitState.CLOSED

    @property
    def is_half_open(self) -> bool:
        return self._state == CircuitState.HALF_OPEN

    def get_metrics(self) -> dict[str, Any]:
        return {
            "state": self._state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "trial_count": self._trial_count,
            "last_failure_time": self._last_failure_time,
            "state_changed_at": self._state_changed_at,
        }

    # ==================== INTERNAL STATE MACHINE ====================

    def _on_success_locked(self) -> None:
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            self._trial_count = max(0, self._trial_count - 1)
            if self._success_count >= self._config.success_threshold:
                self._failure_count = 0
                self._success_count = 0
                self._trial_count = 0
                self._cancel_recovery_task()
                self._transition_to(CircuitState.CLOSED)
        elif self._state == CircuitState.CLOSED:
            self._failure_count = 0

    def _on_failure_locked(self, error: Optional[Exception]) -> None:
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._state == CircuitState.HALF_OPEN:
            self._trial_count = max(0, self._trial_count - 1)

        if self._state == CircuitState.CLOSED:
            if self._failure_count >= self._config.failure_threshold:
                self._success_count = 0
                self._trial_count = 0
                self._transition_to(CircuitState.OPEN)
                self._schedule_recovery()
                logger.warning(
                    "Circuit OPENED after %d consecutive failures",
                    self._failure_count,
                )

        elif self._state == CircuitState.HALF_OPEN:
            self._success_count = 0
            self._trial_count = 0
            self._transition_to(CircuitState.OPEN)
            self._schedule_recovery()
            logger.warning("Circuit RE-OPENED after failure in HALF_OPEN state")

    def _transition_to(self, new_state: CircuitState) -> None:
        old_state = self._state
        if old_state == new_state:
            return
        self._state = new_state
        self._state_changed_at = time.monotonic()
        logger.info(
            "Circuit state transition: %s → %s",
            old_state.value,
            new_state.value,
        )

    # ==================== RECOVERY BACKGROUND TASK ====================

    def _schedule_recovery(self) -> None:
        self._cancel_recovery_task()
        self._recovery_task = asyncio.create_task(self._recovery_after_timeout())

    async def _recovery_after_timeout(self) -> None:
        try:
            await asyncio.sleep(self._config.recovery_timeout)
        except asyncio.CancelledError:
            return

        async with self._lock:
            if self._state == CircuitState.OPEN:
                self._failure_count = 0
                self._success_count = 0
                self._trial_count = 0
                self._transition_to(CircuitState.HALF_OPEN)
                logger.info("Circuit transitioned to HALF_OPEN after recovery timeout")

    def _cancel_recovery_task(self) -> None:
        """Cancel pending recovery task if any (fire-and-forget).

        Does NOT await cancellation. Safe to call under lock.
        """
        if self._recovery_task is not None and not self._recovery_task.done():
            self._recovery_task.cancel()
        self._recovery_task = None

    def _ensure_recovery_task(self) -> None:
        if self._state == CircuitState.OPEN and (
            self._recovery_task is None or self._recovery_task.done()
        ):
            self._schedule_recovery()

    # ==================== ASYNC CONTEXT MANAGER ====================

    async def __aenter__(self) -> "CircuitBreaker":
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Cancel recovery task and await its completion."""
        task: Optional[asyncio.Task[None]] = None
        if self._recovery_task is not None and not self._recovery_task.done():
            task = self._recovery_task
            self._recovery_task = None
            task.cancel()
        if task is not None:
            try:
                await task
            except asyncio.CancelledError:
                pass