"""
Глобальный конфиг для всех интеграционных тестов.

Содержит:
- Настройку логирования
- Подключение к тестовой БД
- Глобальные фикстуры (БД, клиенты, создание данных)
- Генерацию trace_id
- Автоматическую очистку БД и Redis после каждого теста
- Инициализацию Redis на всю сессию тестов
- Вспомогательные функции для Auth тестов (создание токенов)

Локальные фикстуры вынесены в подпапки:
- api/conftest.py — фикстуры авторизации и клиенты с токенами
- repositories/conftest.py — фикстуры репозиториев
- middlewares_and_core/conftest.py — фикстуры моков
- services/conftest.py — фикстуры внешних сервисов
"""

import asyncio
import os
import sys
import re
import logging
import inspect
from typing import AsyncGenerator, Dict, Optional
from unittest.mock import MagicMock
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from alembic.config import Config
from alembic import command

from app.core.config import settings

# ============================================================
# КРИТИЧЕСКИ ВАЖНО: Переопределяем БД ДО импорта app
# Заставляем FastAPI использовать тестовую БД, а не основную
# ============================================================
settings.DATABASE_URL = settings.TEST_DATABASE_URL
os.environ["DATABASE_URL"] = settings.TEST_DATABASE_URL

# ============================================================
# КРИТИЧЕСКИ ВАЖНО: Отключаем Kafka в тестовом окружении
# ============================================================
settings.KAFKA_ENABLED = False
os.environ["KAFKA_ENABLED"] = "false"

from app.core.database import get_db
from app.models import Base
from app.main import app
from app.models.audit_log import AuditLog
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.models.user_security_settings import UserSecuritySettings


# ==================== НАСТРОЙКА ЛОГИРОВАНИЯ ====================

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.debug import setup_logging, generate_trace_id, set_trace_id, reset_trace_id
from app.core.debug.logging_config import JsonFormatter


def pytest_configure(config):
    setup_logging(level="DEBUG")

    root_logger = logging.getLogger()
    app_formatter = None

    for handler in root_logger.handlers:
        if handler.formatter:
            app_formatter = handler.formatter
            break

    logging_plugin = config.pluginmanager.get_plugin("logging-plugin")

    if logging_plugin and hasattr(logging_plugin, "log_cli_handler") and app_formatter:
        logging_plugin.log_cli_handler.setFormatter(app_formatter)


setup_logging(level="DEBUG")


# ==================== ТЕСТОВАЯ БАЗА ДАННЫХ ====================

TEST_DATABASE_URL = settings.TEST_DATABASE_URL

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    poolclass=NullPool,
)


# ==================== ИНИЦИАЛИЗАЦИЯ ТЕСТОВОЙ БАЗЫ ДАННЫХ ====================

@pytest.fixture(scope="session", autouse=True)
async def init_test_database():
    """
    Выполняется 1 раз при старте pytest.
    Гарантирует стерильность тестовой БД.
    Создаёт схему заново и накатывает миграции.
    """
    from pathlib import Path

    async with test_engine.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
        await conn.execute(text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'))

    alembic_cfg = Config(Path(__file__).parent.parent / "alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", settings.TEST_DATABASE_URL)

    def run_migrations():
        command.upgrade(alembic_cfg, "head")

    await asyncio.to_thread(run_migrations)

    yield


# ==================== ИНИЦИАЛИЗАЦИЯ REDIS НА ВСЮ СЕССИЮ ====================

@pytest.fixture(scope="session", autouse=True)
async def manage_test_redis():
    """
    Инициализация реального Redis на всю сессию тестов.
    Имитирует жизненный цикл Redis из реального lifespan приложения.
    Подключение открывается один раз и переиспользуется всеми тестами.
    """
    from app.core.redis_client import init_redis, close_redis, redis_client

    try:
        await init_redis()
        yield
    finally:
        await close_redis()


# ==================== ФИКСТУРЫ БАЗЫ ДАННЫХ ====================

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Каждый тест получает свою транзакцию с автоматическим откатом.
    """
    async with test_engine.connect() as connection:
        async with connection.begin() as transaction:
            async with AsyncSession(
                bind=connection,
                join_transaction_mode="create_savepoint",
                expire_on_commit=False,
            ) as session:
                await session.execute(text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'))
                yield session


@pytest.fixture(autouse=True)
async def global_database_cleaner(db_session: AsyncSession):
    """
    Глобальная фикстура очистки БД и Redis после каждого теста.
    Гарантирует 100% стерильность окружения между тестами.
    """
    yield

    # Очистка PostgreSQL
    truncate_query = text("""
        DO $$
        DECLARE
            statements CURSOR FOR
                SELECT tablename FROM pg_tables
                WHERE schemaname = 'public' AND tablename != 'alembic_version';
        BEGIN
            FOR stmt IN statements LOOP
                EXECUTE 'TRUNCATE TABLE ' || quote_ident(stmt.tablename) || ' RESTART IDENTITY CASCADE;';
            END LOOP;
        END $$;
    """)

    try:
        await db_session.execute(truncate_query)
        await db_session.commit()
    except Exception:
        await db_session.rollback()
        await db_session.execute(truncate_query)
        await db_session.commit()

    # Очистка Redis (счётчики rate-limit, токены сброса, OAuth state)
    from app.core.redis_client import redis_client
    if redis_client.is_initialized:
        try:
            await redis_client.flushdb()
        except Exception:
            pass


# ==================== ФИКСТУРЫ КЛИЕНТА ====================

@pytest_asyncio.fixture
async def get_url(app=app):
    def _get_url(route_name: str, **kwargs) -> str:
        return app.url_path_for(route_name, **kwargs)
    return _get_url


@pytest_asyncio.fixture
async def client(db_session: AsyncSession, get_url) -> AsyncGenerator[AsyncClient, None]:
    """
    Фикстура клиента с переопределением get_db на тестовую сессию.
    """
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    if not app.routes:
        app.router.setup()

    prefix_regex = re.compile(r"^/?api/v[0-9]+/")

    route_mapping = {}
    for route in app.routes:
        if hasattr(route, "path"):
            real_path = route.path
            logical_key = prefix_regex.sub("", real_path).lstrip("/")
            route_mapping[logical_key] = real_path

    sorted_logical_keys = sorted(route_mapping.keys(), key=len, reverse=True)

    class DynamicPrefixTransport(ASGITransport):
        async def handle_async_request(self, request, *args, **kwargs):
            requested_path = request.url.path.strip("/")

            for logical_key in sorted_logical_keys:
                real_path = route_mapping[logical_key]

                pattern_str = "^" + re.sub(r"\{[^}]+\}", r"([^/]+)", logical_key.strip("/")) + "/?$"
                match = re.match(pattern_str, requested_path)

                if match:
                    base_logical = logical_key.split("/{")[0].strip("/")
                    real_base = real_path.split("/{")[0].strip("/")
                    prefix = real_base.replace(base_logical, "").strip("/")

                    final_path = f"/{prefix}/{requested_path}".replace("//", "/")

                    request.url = request.url.copy_with(path=final_path)
                    break

            return await super().handle_async_request(request, *args, **kwargs)

    async with AsyncClient(
        transport=DynamicPrefixTransport(app=app),
        base_url="http://test"
    ) as client:
        yield client

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def sync_client(db_session: AsyncSession) -> TestClient:
    """
    Синхронный клиент с реальными репозиториями.
    """
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


# ==================== ФИКСТУРЫ ДЛЯ СОЗДАНИЯ ТЕСТОВЫХ ДАННЫХ ====================

@pytest_asyncio.fixture
async def create_test_user(db_session: AsyncSession):
    """
    Создание тестового пользователя с физическим коммитом в БД.
    Использует PasswordService для совместимости хешей с роутерами.
    Commit гарантирует что пользователь виден всем сессиям.
    Очистка происходит через global_database_cleaner (TRUNCATE).
    """
    from app.services.password_service import PasswordService

    async def _create_user(
        email: str = None,
        password: str = None,
        password_hash: str = None,
        is_active: bool = True,
        is_email_verified: bool = False,
        is_superuser: bool = False,
        id: Optional[UUID] = None,
    ) -> User:
        if not email:
            email = f"test_{uuid4().hex[:8]}@example.com"

        if password and not password_hash:
            ps = PasswordService()
            password_hash = await ps.hash_password(password)
        elif not password_hash:
            password_hash = "hashed_password"

        user = User(
            id=id if id else uuid4(),
            email=email,
            email_hash=User.create_email_hash(email),
            password_hash=password_hash,
            is_active=is_active,
            is_email_verified=is_email_verified,
            is_superuser=is_superuser,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        return user

    return _create_user


@pytest_asyncio.fixture
async def create_test_security_settings(db_session: AsyncSession):
    from app.models.user_security_settings import UserSecuritySettings

    async def _create_security_settings(
        user_id: UUID,
        totp_enabled: bool = False,
        totp_secret: Optional[str] = None,
        totp_backup_codes: Optional[list] = None,
    ) -> UserSecuritySettings:
        settings = UserSecuritySettings(
            user_id=user_id,
            totp_enabled=totp_enabled,
            totp_secret=totp_secret or f"totp_secret_{uuid4().hex[:16]}",
            totp_backup_codes=totp_backup_codes or [],
        )
        db_session.add(settings)
        await db_session.commit()
        await db_session.refresh(settings)
        return settings

    return _create_security_settings


@pytest_asyncio.fixture
async def create_test_audit_log(db_session: AsyncSession):
    async def _create_audit_log(
        user_id,
        action: str,
        success: bool = True,
        details: Dict = None,
        ip_address: str = "127.0.0.1",
    ) -> AuditLog:
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            success=success,
            details=details or {},
            ip_address=ip_address,
        )
        db_session.add(audit_log)
        await db_session.commit()
        await db_session.refresh(audit_log)
        return audit_log

    return _create_audit_log


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФИКСТУРЫ ДЛЯ AUTH ТЕСТОВ ====================

@pytest_asyncio.fixture
async def create_refresh_token(db_session: AsyncSession):
    """
    Создает refresh токен для пользователя.
    Используется в Auth тестах для /refresh, /logout, /logout-all.
    """
    from app.repositories.refresh_token_repository import RefreshTokenRepository

    async def _create_refresh_token(
        user_id: UUID,
        token: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        client_ip: str = "127.0.0.1",
        user_agent: str = "pytest",
    ) -> str:
        refresh_repo = RefreshTokenRepository(db_session)
        token = token or f"test_refresh_{uuid4().hex[:16]}"
        expires_at = expires_at or (datetime.now(timezone.utc) + timedelta(days=30))

        await refresh_repo.create_token(
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        await db_session.commit()
        return token

    return _create_refresh_token


@pytest_asyncio.fixture
async def create_verification_token(db_session: AsyncSession):
    """
    Создает токен верификации email для пользователя.
    Используется в Auth тестах для /verify-email.
    """
    from app.repositories.user_repository import UserRepository
    from app.services.token_service import TokenService

    async def _create_verification_token(
        user_id: UUID,
        expires_at: Optional[datetime] = None,
    ) -> str:
        from app.repositories.refresh_token_repository import RefreshTokenRepository

        refresh_repo = RefreshTokenRepository(db_session)
        token_service = TokenService(
            refresh_repo=refresh_repo,
            secret_key=settings.JWT_SECRET_KEY
        )

        token = await token_service.create_email_verification_token(user_id)

        repo = UserRepository(db_session)
        expires_at = expires_at or (datetime.now(timezone.utc) + timedelta(hours=24))
        await repo.update_verification_token(user_id, token, expires_at)
        await db_session.commit()
        return token

    return _create_verification_token


@pytest_asyncio.fixture
async def unverified_user(create_test_user):
    """Пользователь с неподтвержденным email."""
    return await create_test_user(
        email=f"unverified_{uuid4().hex[:8]}@example.com",
        password="SecurePass123!",
        is_active=True,
        is_email_verified=False,
        is_superuser=False,
    )


# ==================== ГЕНЕРАЦИЯ TRACE_ID ====================

@pytest.fixture(autouse=True)
def auto_test_trace_id():
    trace_id = generate_trace_id()
    token = set_trace_id(trace_id)
    yield
    reset_trace_id(token)