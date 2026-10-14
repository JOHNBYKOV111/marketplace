"""
Настройка базы данных для auth-service.

Предоставляет:
- Подключение к PostgreSQL
- Асинхронную сессию SQLAlchemy
- Управление транзакциями
- Healthcheck
- Логирование SQL запросов через событийную модель
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.debug import setup_db_logging


# ==================== СОЗДАНИЕ ДВИЖКА ====================

def create_engine(
    database_url: Optional[str] = None,
    echo: bool = False,
    pool_size: int = 50,
    max_overflow: int = 50,
    pool_timeout: int = 30,
    pool_recycle: int = 3600,
    pool_pre_ping: bool = True,
) -> AsyncEngine:
    """
    Создает асинхронный движок SQLAlchemy.

    Args:
        database_url: URL для подключения к БД
        echo: Включить логирование SQL запросов (используйте False)
        pool_size: Размер пула соединений (увеличен для peak load)
        max_overflow: Максимальное количество дополнительных соединений
        pool_timeout: Таймаут получения соединения из пула
        pool_recycle: Время жизни соединения в секундах
        pool_pre_ping: Проверять соединение перед использованием

    Returns:
        AsyncEngine: Настроенный асинхронный движок
    """
    database_url = database_url or settings.DATABASE_URL

    return create_async_engine(
        database_url,
        echo=False,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        pool_recycle=pool_recycle,
        pool_pre_ping=pool_pre_ping,
        poolclass=NullPool if settings.DB_POOL_DISABLED else None,
        connect_args={
            "command_timeout": 30,
            "server_settings": {
                "statement_timeout": "30s",
                "idle_in_transaction_session_timeout": "60s",
            },
        },
    )


# ==================== ГЛОБАЛЬНЫЙ ДВИЖОК ====================

engine = create_engine()

# Подключение дебаг-логирования для SQLAlchemy
setup_db_logging(engine, slow_query_threshold_ms=200.0)


# ==================== ФАБРИКА СЕССИЙ ====================

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ==================== ПОЛУЧЕНИЕ СЕССИИ ДЛЯ DEPENDENCY ====================

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Получение сессии для Dependency Injection в FastAPI.

    Используется как dependency:
        async def some_endpoint(session: AsyncSession = Depends(get_db)):
            ...

    Yields:
        AsyncSession: Асинхронная сессия
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ==================== КОНТЕКСТНЫЙ МЕНЕДЖЕР ДЛЯ СЕССИИ ====================

@asynccontextmanager
async def get_session_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Контекстный менеджер для работы с сессией.

    Используется в сервисах для явного управления сессией.

    Yields:
        AsyncSession: Асинхронная сессия
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ==================== КОНТЕКСТНЫЙ МЕНЕДЖЕР ДЛЯ ТРАНЗАКЦИЙ ====================

@asynccontextmanager
async def transaction(session: AsyncSession) -> AsyncGenerator[None, None]:
    """
    Контекстный менеджер для управления транзакциями.

    Args:
        session: Асинхронная сессия

    Yields:
        None: Контекст для выполнения операций

    Raises:
        Exception: При ошибке выполняется rollback
    """
    try:
        yield
        await session.commit()
    except Exception:
        await session.rollback()
        raise


# ==================== ПОЛУЧЕНИЕ ПРЯМОГО СОЕДИНЕНИЯ ====================

async def get_connection() -> AsyncGenerator[AsyncConnection, None]:
    """
    Получение прямого соединения с БД.

    Используется для выполнения сырых SQL запросов.

    Yields:
        AsyncConnection: Асинхронное соединение
    """
    async with engine.connect() as connection:
        yield connection


# ==================== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ ====================

async def init_database(database_url: Optional[str] = None) -> None:
    """
    Инициализация базы данных при старте приложения.
    Создает таблицы и расширения.

    Args:
        database_url: URL для подключения к БД (опционально)
    """
    from app.models import Base

    if database_url:
        temp_engine = create_engine(
            database_url,
            echo=False,
            pool_pre_ping=True,
        )
        async with temp_engine.begin() as conn:
            # СНАЧАЛА расширение, ПОТОМ таблицы!
            # Иначе create_all падает при пустой базе
            await conn.execute(text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'))
            await conn.run_sync(Base.metadata.create_all)
        await temp_engine.dispose()
    else:
        async with engine.begin() as conn:
            await conn.execute(text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'))
            await conn.run_sync(Base.metadata.create_all)


# ==================== HEALTHCHECK ====================

async def healthcheck() -> bool:
    """
    Проверяет доступность базы данных.

    Returns:
        bool: True если БД доступна
    """
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def get_db_version() -> Optional[str]:
    """
    Получает версию PostgreSQL.

    Returns:
        Optional[str]: Версия PostgreSQL или None в случае ошибки
    """
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT version()"))
            row = result.fetchone()
            return row[0] if row else None
    except Exception:
        return None


# ==================== ЗАКРЫТИЕ РЕСУРСОВ ====================

async def close_db_connections() -> None:
    """Закрывает все соединения с базой данных."""
    await engine.dispose()
    if _test_engine_singleton is not None:
        await _test_engine_singleton.dispose()


# ==================== HEALTH CHECKS MANAGER ====================

class DatabaseManager:
    """
    Менеджер базы данных для управления подключениями и состоянием.
    
    Предоставляет методы для проверки состояния пула соединений
    и получения статуса подключения.
    """
    
    def __init__(self, engine: AsyncEngine = engine):
        self._engine = engine
        self._is_initialized = True
    
    @property
    def is_initialized(self) -> bool:
        return self._is_initialized
    
    async def ping(self) -> bool:
        return await healthcheck()
    
    async def get_pool_status(self) -> dict:
        try:
            pool = self._engine.pool
            stats = pool.status() if hasattr(pool, "status") else {}
            return {
                "size": stats.get("size", 0),
                "used": stats.get("checked_out", 0),
                "available": stats.get("available", 0),
                "overflow": stats.get("overflow", 0),
                "is_initialized": self._is_initialized,
            }
        except Exception as e:
            return {
                "size": 0,
                "used": 0,
                "available": 0,
                "overflow": 0,
                "is_initialized": self._is_initialized,
                "error": str(e),
            }
    
    async def get_connection_info(self) -> dict:
        try:
            async with self._engine.connect() as conn:
                result = await conn.execute(text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
                ))
                total_connections = result.scalar() or 0
                
                result = await conn.execute(text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state = 'active'"
                ))
                active_connections = result.scalar() or 0
                
                result = await conn.execute(text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state = 'idle'"
                ))
                idle_connections = result.scalar() or 0
            
            return {
                "total": total_connections,
                "active": active_connections,
                "idle": idle_connections,
            }
        except Exception as e:
            return {"error": str(e)}
    
    async def get_version(self) -> Optional[str]:
        return await get_db_version()


db_manager = DatabaseManager(engine)


# ==================== ОПТИМИЗИРОВАННАЯ ЛОГИКА ДЛЯ ТЕСТОВ ====================

# Синглтон тестового движка и фабрики — не пересоздаём пул на каждый запрос
_test_engine_singleton: Optional[AsyncEngine] = None
_test_sessionmaker_singleton: Optional[async_sessionmaker] = None


def _get_test_sessionmaker() -> async_sessionmaker:
    """Возвращает синглтон фабрики тестовых сессий."""
    global _test_engine_singleton, _test_sessionmaker_singleton
    if _test_sessionmaker_singleton is None:
        _test_engine_singleton = create_engine(
            settings.TEST_DATABASE_URL,
            echo=False,
            pool_pre_ping=True,
        )
        _test_sessionmaker_singleton = async_sessionmaker(
            _test_engine_singleton,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
    return _test_sessionmaker_singleton


async def get_test_db() -> AsyncGenerator[AsyncSession, None]:
    """Высокопроизводительное получение тестовой сессии через синглтон пула."""
    if settings.TEST_DATABASE_URL:
        session_factory = _get_test_sessionmaker()
        async with session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    else:
        async with AsyncSessionLocal() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()


async def reset_database() -> None:
    """Очищает все таблицы в тестовой БД одним быстрым запросом."""
    if not settings.TEST_DATABASE_URL:
        return

    session_factory = _get_test_sessionmaker()
    
    async with _test_engine_singleton.begin() as conn:
        result = await conn.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        ))
        tables = [row[0] for row in result.fetchall()]
        if tables:
            # Один быстрый запрос вместо цикла
            tables_str = ", ".join(f'"{t}"' for t in tables)
            await conn.execute(text(f'TRUNCATE TABLE {tables_str} CASCADE'))


async def get_transaction_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()