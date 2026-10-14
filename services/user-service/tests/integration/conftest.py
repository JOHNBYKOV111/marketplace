"""
Local conftest for integration tests.

Provides fixtures for:
- AsyncClient with test app and database override
- Database session with rollback-based isolation
- Authentication headers (admin, user)
- Clean database between tests
- Connection pool management to prevent connection exhaustion
"""

import asyncio
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.database import get_db
from app.main import app
from app.models.base import Base


@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async fixtures."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_engine():
    """Create async test database engine for the session."""
    engine = create_async_engine(
        settings.TEST_DATABASE_URL,
        echo=False,
        poolclass=NullPool,
    )
    return engine


@pytest.fixture(scope="session", autouse=True)
async def setup_database(test_engine):
    """Create all tables once per test session."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a new database session with guaranteed cleanup.

    Uses a fresh connection per test. Session is rolled back
    and closed after each test to prevent connection leaks.
    """
    async_session = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with test_engine.connect() as connection:
        session = async_session(bind=connection)
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()
            await connection.close()


@pytest_asyncio.fixture(autouse=True)
async def clean_tables(db_session: AsyncSession):
    """Clean all tables after each test."""
    yield
    for table in reversed(Base.metadata.sorted_tables):
        await db_session.execute(table.delete())
    await db_session.commit()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create AsyncClient with test app and database override."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        try:
            yield client
        finally:
            app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def cleanup_engine_connections(test_engine):
    """Dispose engine connection pool after all tests complete."""
    yield
    await test_engine.dispose()


@pytest.fixture
def admin_headers():
    """Headers with admin user credentials."""
    return {
        "X-User-Id": "11111111-1111-1111-1111-111111111111",
        "X-User-Roles": "admin",
    }


@pytest.fixture
def user_headers():
    """Headers with regular user credentials."""
    return {
        "X-User-Id": "22222222-2222-2222-2222-222222222222",
        "X-User-Roles": "user",
    }