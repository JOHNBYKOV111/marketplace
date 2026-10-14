"""
User Service application entry point.

Configures FastAPI app, middleware, routers, and exception handlers.
Uses orjson for high-performance JSON serialization.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from app.core.config import settings


# ==================== LIFESPAN ====================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifecycle management."""
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"Environment: {settings.ENVIRONMENT}")

    print("Database ready")

    try:
        from app.core.redis_client import init_redis
        await init_redis()
        print("Redis connected")
    except Exception as e:
        print(f"Redis connection failed: {e}")
        if settings.ENVIRONMENT == "production":
            raise

    yield

    print("Shutting down...")

    try:
        from app.core.redis_client import close_redis
        await close_redis()
        print("Redis connection closed")
    except Exception as e:
        print(f"Redis close error: {e}")


# ==================== CREATE APP ====================

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="User Management Service",
    docs_url="/api/docs" if settings.is_development else None,
    redoc_url="/api/redoc" if settings.is_development else None,
    openapi_url="/api/openapi.json" if settings.is_development else None,
    debug=settings.is_development,
    lifespan=lifespan,
    default_response_class=ORJSONResponse,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
    max_age=3600,
)

# ==================== ROUTERS ====================

from app.routers.admin import router as admin_router
from app.routers.user import router as user_router

app.include_router(admin_router)
app.include_router(user_router)


@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "status": "running",
    }


@app.get("/health", include_in_schema=False)
async def health_check():
    return {"status": "ok", "service": settings.APP_NAME}