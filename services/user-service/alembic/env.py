"""
Alembic environment configuration.
"""

import asyncio
from logging.config import fileConfig
from os.path import abspath, dirname
from pathlib import Path
import sys

# Гарантируем, что папка /app находится в sys.path
sys.path.insert(0, abspath(dirname(dirname(__file__))))

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

# 1. Сначала импортируем Base
from app.models.base import Base

# 2. Принудительно импортируем ВСЕ файлы моделей, чтобы они зарегистрировались в Base.metadata
from app.models.user import User
from app.models.role import Role, Permission, RolePermission, UserRole
from app.models.user_security_settings import UserSecuritySettings

from app.core.config import settings

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# 3. Только ПОСЛЕ этого передаем заполненные метаданные в Alembic
target_metadata = Base.metadata


def get_url() -> str:
    """
    Возвращает URL для подключения к БД.
    
    Приоритет:
    1. URL из конфига Alembic (может быть переопределён через -x или set_main_option)
    2. URL из настроек приложения (settings.DATABASE_URL)
    """
    url = config.get_main_option("sqlalchemy.url")
    if url:
        return url
    return settings.DATABASE_URL


def run_migrations_offline() -> None:
    """Запуск миграций в offline-режиме."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    """Выполняет миграции с переданным соединением."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Запуск миграций в асинхронном режиме."""
    database_url = get_url()
    connectable = create_async_engine(
        database_url,
        echo=False,
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Запуск миграций в online-режиме."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()