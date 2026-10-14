"""
Точка входа в приложение Auth Service.

Настраивает FastAPI приложение, middleware, роутеры и обработчики ошибок.

Совместимость с тестами MFA:
- MFA роутер подключается без префикса (эндпоинты начинаются с /mfa/...)
- Все зависимости (Redis, GatewayUser) доступны через app.dependency_overrides в тестах
- CORS middleware не блокирует тестовые запросы

Совместимость с тестами OAuth:
- OAuth роутер подключается без префикса (эндпоинты начинаются с /oauth/...)
- Зависимости get_oauth_service, get_auth_service_for_oauth доступны через app.dependency_overrides
- redis_client подменяется в тестах через хирургическую подмену в модуле роутера

Совместимость с тестами Password:
- Password роутер подключается без префикса (эндпоинты начинаются с /password/...)
- Зависимости get_password_service_for_password_router, get_auth_service_for_password_router,
  get_rate_limit_service_for_password_router доступны через app.dependency_overrides
- Email-уведомления подменяются в тестах через хирургическую подмену в модуле роутера

Связанные модули:
- app.routers.mfa - MFA роутер (подключается здесь)
- app.routers.oauth - OAuth роутер (подключается здесь)
- app.routers.password - Password роутер (подключается здесь)
- app.core.dependencies - зависимости (используются в тестах через dependency_overrides)
"""

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from fastapi import FastAPI, Request, status, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import close_db_connections
from app.core.debug import setup_logging as setup_debug_logging
from app.core.debug import AsgiLoggingMiddleware, LoggingRoute
from app.core.middleware.auth import AuthMiddleware
from app.core.dependencies import get_current_admin
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    ValidationError,
    AppException,
    DatabaseError,
    ExternalServiceError,
    register_exception_handlers,
)
from app.routers import (
    admin_router,
    auth_router,
    health_router,
    user_router,
    security_router,
    internal_router,
    jwks_router,
)


# ==================== НАСТРОЙКА ЛОГИРОВАНИЯ ====================

# Настройка дебаг-логирования до создания приложения
setup_debug_logging(level=settings.LOG_LEVEL)


# ==================== LIFESPAN ====================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Управление жизненным циклом приложения.

    Выполняет инициализацию при старте и очистку при завершении.
    """
    # Startup
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"Environment: {settings.ENVIRONMENT}")

    # Инициализация Redis
    try:
        from app.core.redis_client import init_redis
        await init_redis()
        print("Redis connected")
    except Exception as e:
        print(f"Redis connection failed: {e}")
        if settings.ENVIRONMENT == "production":
            raise

    # Инициализация Kafka
    try:
        from app.core.kafka_client import init_kafka
        await init_kafka()
        print("Kafka connected")
    except Exception as e:
        print(f"Kafka connection failed: {e}")
        if settings.ENVIRONMENT == "production":
            raise

    # Инициализация Vault
    try:
        from app.core.vault_client import init_vault
        await init_vault()
        print("Vault connected")
    except Exception as e:
        print(f"Vault connection failed: {e}")
        if settings.ENVIRONMENT == "production":
            raise

    # Инициализация базы данных с дефолтными пользователями
    try:
        from app.core.init_db import init_database_with_users
        await init_database_with_users()
        print("Database initialized with default users")
    except Exception as e:
        print(f"Database initialization failed: {e}")
        if settings.ENVIRONMENT == "production":
            raise

    # База данных уже инициализирована через Alembic миграции
    print("Database ready")

    yield

    # Shutdown
    print("Shutting down...")

    # Закрытие Redis
    try:
        from app.core.redis_client import close_redis
        await close_redis()
        print("Redis connection closed")
    except Exception as e:
        print(f"Redis close error: {e}")

    # Закрытие Kafka
    try:
        from app.core.kafka_client import close_kafka
        await close_kafka()
        print("Kafka connection closed")
    except Exception as e:
        print(f"Kafka close error: {e}")

    # Закрытие Vault
    try:
        from app.core.vault_client import close_vault
        await close_vault()
        print("Vault connection closed")
    except Exception as e:
        print(f"Vault close error: {e}")

    # Закрытие БД
    await close_db_connections()
    print("Database connections closed")


# ==================== СОЗДАНИЕ ПРИЛОЖЕНИЯ ====================

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Authentication & Authorization Service",
    docs_url="/api/docs" if settings.is_development else None,
    redoc_url="/api/redoc" if settings.is_development else None,
    openapi_url="/api/openapi.json" if settings.is_development else None,
    debug=settings.is_development,
    lifespan=lifespan,
)


# ==================== РЕГИСТРАЦИЯ ОБРАБОТЧИКОВ ИСКЛЮЧЕНИЙ ====================

# Регистрируем все кастомные хендлеры из app.core.exceptions
register_exception_handlers(app)


# ==================== MIDDLEWARE ====================

# Fault injection middleware — MUST be first to intercept all requests
# Only active in non-production environments
if settings.ENVIRONMENT != "production":
    from app.routers.resilience_test import fault_injection_middleware
    app.middleware("http")(fault_injection_middleware)

# AsgiLoggingMiddleware для логирования запросов
app.add_middleware(AsgiLoggingMiddleware)

# AuthMiddleware для проверки авторизации и ролей
app.add_middleware(AuthMiddleware)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOWED_METHODS,
    allow_headers=settings.CORS_ALLOWED_HEADERS,
    max_age=settings.CORS_MAX_AGE,
)

# Глобальный оверрайд роутера для корневых эндпоинтов
app.router.route_class = LoggingRoute


# ==================== ПОДКЛЮЧЕНИЕ РОУТЕРОВ ====================

# Health check (публичный)
app.include_router(health_router, prefix="/api/v1", tags=["Health"])

# Auth routes (публичные)
app.include_router(auth_router, prefix="/api/v1", tags=["Authentication"])

# User routes (защищенные)
app.include_router(user_router, prefix="/api/v1", tags=["Users"])

# Security routes (защищенные)
app.include_router(security_router, prefix="/api/v1", tags=["Security"])

# Admin routes (защищенные)
app.include_router(
    admin_router,
    prefix="/api/v1",
    tags=["Admin"],
    dependencies=[Depends(get_current_admin)],
)

# Internal API routes (для межсервисного взаимодействия)
app.include_router(
    internal_router,
    prefix="/internal",
    tags=["Internal"],
)

# Resilience testing routes (только в не-production окружениях)
if settings.ENVIRONMENT != "production":
    from app.routers.resilience_test import router as resilience_test_router
    app.include_router(resilience_test_router, tags=["Resilience-Testing"])

# JWKS routes (публичный + админские)
app.include_router(jwks_router, tags=["JWKS"])

# MFA routes (защищенные, аутентификация через Gateway заголовки)
from app.routers.mfa import router as mfa_router
app.include_router(mfa_router, tags=["MFA"])

# OAuth routes (публичные, аутентификация через внешних провайдеров)
from app.routers.oauth import router as oauth_router
app.include_router(oauth_router, tags=["OAuth"])

# Password routes (защищенные, аутентификация через Gateway заголовки)
from app.routers.password import router as password_router
app.include_router(password_router, tags=["Password"])


# ==================== КОРНЕВОЙ ЭНДПОИНТ ====================

@app.get("/", include_in_schema=False)
async def root():
    """Корневой эндпоинт для проверки работоспособности."""
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "status": "running",
    }


@app.get("/health", include_in_schema=False)
async def health_check():
    """Health check эндпоинт."""
    return {"status": "ok", "service": settings.APP_NAME}