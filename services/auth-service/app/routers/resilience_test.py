"""
Resilience testing endpoints for fault injection.

Provides HTTP-level fault injection for integration testing of
Circuit Breaker and other resilience patterns in downstream services.

Endpoints:
    POST /internal/test/faults/503?enabled=true|false
        — Force 503 Service Unavailable responses on all endpoints.
    POST /internal/test/faults/timeout?ms=5000
        — Add artificial delay to all responses (ms: 0-30000).
    POST /internal/test/faults/reset
        — Clear all active faults, restore normal operation.
    GET  /internal/test/faults/status
        — Return current fault injection state.

Security:
    - Only available when ENVIRONMENT != "production".
    - Requires valid X-Internal-API-Key header.
    - All state is in-memory only — restart clears all faults.

Architecture:
    Fault injection is implemented as ASGI middleware that intercepts
    responses. When a fault is active, the middleware modifies the
    response before it reaches the client. This keeps individual
    routers clean and unaware of testing concerns.
    Management endpoints (/internal/test/faults/*) are EXEMPT from
    fault injection — otherwise you couldn't turn faults off.
"""

from __future__ import annotations

import asyncio
import time
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.dependencies import verify_internal_api_key
from app.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(
    prefix="/internal/test/faults",
    tags=["resilience-testing"],
    include_in_schema=False,  # Hidden from OpenAPI docs
)

# Path prefix for fault management endpoints — these are exempt from injection
_MANAGEMENT_PATH_PREFIX = "/internal/test/faults"


# ==================== FAULT TYPES ====================

class FaultType(str, Enum):
    """Types of injectable faults."""

    SERVICE_UNAVAILABLE = "service_unavailable"
    TIMEOUT = "timeout"


# ==================== FAULT STATE (IN-MEMORY) ====================

class FaultState:
    """Thread-safe in-memory fault injection state.

    Singleton — shared across all requests in the process.
    Reset on process restart.
    """

    def __init__(self) -> None:
        self._active_faults: dict[FaultType, bool] = {
            FaultType.SERVICE_UNAVAILABLE: False,
            FaultType.TIMEOUT: False,
        }
        self._timeout_ms: int = 0
        self._injected_count: int = 0
        self._fault_since: Optional[float] = None

    def enable(self, fault: FaultType, **kwargs: int) -> None:
        """Enable a fault type."""
        self._active_faults[fault] = True
        if fault == FaultType.TIMEOUT:
            self._timeout_ms = kwargs.get("ms", 5000)
        self._fault_since = self._fault_since or time.monotonic()
        logger.warning(f"Fault injection ENABLED: {fault.value}")

    def disable(self, fault: FaultType) -> None:
        """Disable a fault type."""
        self._active_faults[fault] = False
        if fault == FaultType.TIMEOUT:
            self._timeout_ms = 0
        logger.warning(f"Fault injection DISABLED: {fault.value}")

    def reset(self) -> None:
        """Reset all faults to normal."""
        for fault in FaultType:
            self._active_faults[fault] = False
        self._timeout_ms = 0
        self._fault_since = None
        logger.warning("All fault injections RESET")

    def is_active(self, fault: FaultType) -> bool:
        """Check if a fault is currently active."""
        return self._active_faults.get(fault, False)

    @property
    def timeout_ms(self) -> int:
        """Current timeout injection duration in ms."""
        return self._timeout_ms if self._active_faults.get(FaultType.TIMEOUT, False) else 0

    def record_injection(self) -> None:
        """Increment the injection counter."""
        self._injected_count += 1

    def snapshot(self) -> dict:
        """Return current fault state for the status endpoint."""
        return {
            "active_faults": {
                f.value: self._active_faults[f] for f in FaultType
            },
            "timeout_ms": self._timeout_ms,
            "injected_count": self._injected_count,
            "fault_since": self._fault_since,
            "uptime_seconds": round(time.monotonic() - (self._fault_since or time.monotonic()), 1)
            if self._fault_since else 0,
        }


# Singleton — lives for the lifetime of the process
_fault_state = FaultState()


# ==================== DEPENDENCY ====================

def _require_non_production() -> None:
    """Raise 404 if running in production."""
    if settings.ENVIRONMENT == "production":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
        )


# ==================== SCHEMAS ====================

class FaultStatusResponse(BaseModel):
    """Response schema for GET /status."""

    active_faults: dict = Field(..., description="Map of fault type → enabled")
    timeout_ms: int = Field(..., description="Current timeout injection (ms)")
    injected_count: int = Field(..., description="Total number of injected faults")
    fault_since: Optional[float] = Field(None, description="Timestamp when first fault was enabled")
    uptime_seconds: float = Field(..., description="Seconds since first fault was enabled")


class FaultToggleResponse(BaseModel):
    """Response schema for fault enable/disable/reset."""

    success: bool = Field(True)
    message: str
    active_faults: dict


# ==================== ENDPOINTS ====================

@router.post("/503")
async def toggle_503(
    enabled: bool = Query(..., description="true = inject 503, false = stop"),
    _: None = Depends(verify_internal_api_key),
) -> JSONResponse:
    """Enable or disable 503 Service Unavailable injection.

    When enabled, ALL subsequent requests to ANY auth-service endpoint
    will return 503 Service Unavailable.
    """
    _require_non_production()

    if enabled:
        _fault_state.enable(FaultType.SERVICE_UNAVAILABLE)
    else:
        _fault_state.disable(FaultType.SERVICE_UNAVAILABLE)

    return JSONResponse(
        content=FaultToggleResponse(
            success=True,
            message=f"503 fault {'ENABLED' if enabled else 'DISABLED'}",
            active_faults={
                f.value: _fault_state.is_active(f) for f in FaultType
            },
        ).model_dump(),
    )


@router.post("/timeout")
async def toggle_timeout(
    ms: int = Query(..., ge=0, le=30000, description="Timeout in milliseconds (0 = disable)"),
    _: None = Depends(verify_internal_api_key),
) -> JSONResponse:
    """Enable or disable artificial response delay.

    When ms > 0, ALL subsequent requests will be delayed by ms milliseconds
    before returning their normal response.
    When ms = 0, timeout injection is disabled.
    """
    _require_non_production()

    if ms > 0:
        _fault_state.enable(FaultType.TIMEOUT, ms=ms)
    else:
        _fault_state.disable(FaultType.TIMEOUT)

    return JSONResponse(
        content=FaultToggleResponse(
            success=True,
            message=f"Timeout fault {'ENABLED' if ms > 0 else 'DISABLED'} ({ms}ms)",
            active_faults={
                f.value: _fault_state.is_active(f) for f in FaultType
            },
        ).model_dump(),
    )


@router.post("/reset")
async def reset_faults(
    _: None = Depends(verify_internal_api_key),
) -> JSONResponse:
    """Reset all active faults. Restores normal operation."""
    _require_non_production()

    _fault_state.reset()

    return JSONResponse(
        content=FaultToggleResponse(
            success=True,
            message="All faults RESET",
            active_faults={
                f.value: False for f in FaultType
            },
        ).model_dump(),
    )


@router.get("/status", response_model=FaultStatusResponse)
async def get_fault_status(
    _: None = Depends(verify_internal_api_key),
) -> JSONResponse:
    """Return current fault injection state."""
    _require_non_production()

    return JSONResponse(content=_fault_state.snapshot())


# ==================== ASGI MIDDLEWARE ====================

async def fault_injection_middleware(request: Request, call_next):
    """ASGI middleware that injects faults based on _fault_state.

    Must be registered in app/main.py:
        app.middleware("http")(fault_injection_middleware)

    Behavior:
        - Management endpoints (/internal/test/faults/*) are NEVER affected.
        - If 503 fault is active → return 503 immediately.
        - If timeout fault is active → sleep for timeout_ms, then proceed normally.
        - If no faults → pass through unchanged.
    """
    # NEVER inject faults on management endpoints — you must be able to turn faults off
    if request.url.path.startswith(_MANAGEMENT_PATH_PREFIX):
        return await call_next(request)

    # Check 503 injection (fast-fail)
    if _fault_state.is_active(FaultType.SERVICE_UNAVAILABLE):
        _fault_state.record_injection()
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "detail": "Fault injection: 503 Service Unavailable",
                "fault": FaultType.SERVICE_UNAVAILABLE.value,
            },
        )

    # Check timeout injection
    if _fault_state.is_active(FaultType.TIMEOUT):
        timeout_ms = _fault_state.timeout_ms
        _fault_state.record_injection()
        await asyncio.sleep(timeout_ms / 1000.0)
        # Fall through to normal response after delay

    # Normal processing
    response = await call_next(request)
    return response