"""Database connection module."""
import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker, AsyncEngine

from app.core.config import settings

def _get_database_url() -> str:
    """
    Динамически определяет URL базы данных.
    Если запущены тесты и передан TEST_DATABASE_URL, использует его.
    """
    # Проверяем, запущены ли тесты (pytest устанавливает PYTEST_CURRENT_TEST)
    if "PYTEST_CURRENT_TEST" in os.environ and getattr(settings, "TEST_DATABASE_URL", None):
        return settings.TEST_DATABASE_URL
    return settings.DATABASE_URL

def create_engine_configured() -> AsyncEngine:
    """
    Создает оптимизированный асинхронный движок с расширенным пулом
    для выдерживания пиковых нагрузок (1000+ RPS).
    """
    return create_async_engine(
        _get_database_url(),
        echo=False,
        pool_size=50,         # Размер пула (увеличен под воркеры и peak load)
        max_overflow=50,     # Дополнительные коннекты при всплесках трафика
        pool_timeout=30,      # Время ожидания свободного коннекта
        pool_recycle=1800,    # Перезапуск соединений каждые 30 минут
        pool_pre_ping=True,   # Проверка «живости» сокета перед выдачей приложению
        connect_args={
            "command_timeout": 30,
            "server_settings": {
                "statement_timeout": "30s",
                "idle_in_transaction_session_timeout": "60s",
            },
        },
    )

# Глобальный синглтон движка — создается один раз при старте
engine = create_engine_configured()

AsyncSessionLocal = async_sessionmaker(
    engine, 
    class_=AsyncSession, 
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Асинхронная фабрика сессий для FastAPI Dependency Injection."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def close_db_connections() -> None:
    """Закрывает все соединения пула при завершении работы приложения."""
    await engine.dispose()
