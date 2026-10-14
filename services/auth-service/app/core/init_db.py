"""
Инициализация базы данных при старте приложения.

Обеспечивает:
- Создание дефолтного администратора (только в development/test окружениях)
- Создание тестового обычного пользователя (в development и test окружениях)
- Безопасное создание (проверка на существование)
- Логирование процесса инициализации
- Поддержку изолированных тестов через flush/rollback
"""

import os
from typing import Optional
from uuid import uuid4
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.logging import get_logger
from app.core.security import hash_password_bcrypt
from app.models.user import User
from app.repositories.user_repository import UserRepository

logger = get_logger(__name__)


# ==================== КОНСТАНТЫ ====================

DEFAULT_ADMIN_EMAIL = "admin@test.com"
DEFAULT_ADMIN_PASSWORD = "SecurePass123!"
DEFAULT_USER_EMAIL = "user@test.com"
DEFAULT_USER_PASSWORD = "SecurePass123!"


# ==================== ФУНКЦИИ ДЛЯ РАБОТЫ С ПОЛЬЗОВАТЕЛЯМИ ====================

async def get_or_create_user(
    session: AsyncSession,
    email: str,
    password: str,
    is_superuser: bool = False,
    is_active: bool = True,
    is_email_verified: bool = True,
    commit: bool = True,
) -> User:
    """
    Получение или создание пользователя.
    
    Args:
        session: Сессия БД
        email: Email пользователя
        password: Пароль
        is_superuser: Флаг суперпользователя
        is_active: Активен ли пользователь
        is_email_verified: Верифицирован ли email
        commit: Выполнять commit (True для инита, False для тестов)
    
    Returns:
        User: Объект пользователя
    """
    repo = UserRepository(session)
    email_hash = User.create_email_hash(email)
    
    # Проверяем существование пользователя
    existing = await repo.get_by_email_hash(email_hash)
    if existing:
        logger.debug(f"User already exists: {email}")
        return existing
    
    # Создаём пользователя
    user_id = uuid4()
    user = User(
        id=user_id,
        email=email,
        email_hash=email_hash,
        password_hash=hash_password_bcrypt(password),
        is_active=is_active,
        is_email_verified=is_email_verified,
        is_superuser=is_superuser,
    )
    
    session.add(user)
    
    if commit:
        await session.commit()
        await session.refresh(user)
        logger.info(f"User created: {email} (superuser={is_superuser})")
    else:
        await session.flush()
        logger.debug(f"User flushed (not committed): {email}")
    
    return user


async def create_default_admin(session: AsyncSession) -> Optional[User]:
    """
    Создание дефолтного администратора.
    
    Args:
        session: Сессия БД
    
    Returns:
        Optional[User]: Созданный администратор или None
    """
    # Создаём только в development и test окружениях
    if settings.ENVIRONMENT not in ["development", "test"]:
        logger.info("Skipping default admin creation in production environment")
        return None
    
    email = os.getenv("DEFAULT_ADMIN_EMAIL", DEFAULT_ADMIN_EMAIL)
    password = os.getenv("DEFAULT_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
    
    if not email or not password:
        logger.warning("Default admin credentials not configured")
        return None
    
    try:
        user = await get_or_create_user(
            session=session,
            email=email,
            password=password,
            is_superuser=True,
            is_active=True,
            is_email_verified=True,
            commit=True,
        )
        logger.info(f"Default admin created/verified: {email}")
        return user
    except Exception as e:
        logger.error(f"Failed to create default admin: {e}")
        return None


async def create_default_user(session: AsyncSession) -> Optional[User]:
    """
    Создание дефолтного обычного пользователя (для development и test).
    
    Args:
        session: Сессия БД
    
    Returns:
        Optional[User]: Созданный пользователь или None
    """
    # Создаём только в development и test окружениях
    if settings.ENVIRONMENT not in ["development", "test"]:
        return None
    
    email = os.getenv("DEFAULT_USER_EMAIL", DEFAULT_USER_EMAIL)
    password = os.getenv("DEFAULT_USER_PASSWORD", DEFAULT_USER_PASSWORD)
    
    if not email or not password:
        logger.warning("Default user credentials not configured")
        return None
    
    try:
        user = await get_or_create_user(
            session=session,
            email=email,
            password=password,
            is_superuser=False,
            is_active=True,
            is_email_verified=True,
            commit=True,
        )
        logger.info(f"Default user created/verified: {email}")
        return user
    except Exception as e:
        logger.error(f"Failed to create default user: {e}")
        return None


async def create_audit_log_for_test(session: AsyncSession, user_id: uuid4) -> None:
    """
    Создание тестовой записи в аудит-логах (для test окружения).
    
    Args:
        session: Сессия БД
        user_id: ID пользователя
    """
    from app.models.audit_log import AuditLog
    
    if settings.ENVIRONMENT != "test":
        return
    
    # Проверяем, есть ли уже логи
    from sqlalchemy import select
    stmt = select(AuditLog).limit(1)
    result = await session.execute(stmt)
    existing = result.scalar_one_or_none()
    
    if existing:
        logger.debug("Audit log already exists, skipping creation")
        return
    
    # Создаём тестовый лог
    log = AuditLog(
        user_id=user_id,
        action="TEST_INIT",
        details={"source": "init_db", "test": True},
        success=True,
        ip_address="127.0.0.1",
        user_agent="pytest/init_db",
    )
    session.add(log)
    await session.commit()
    logger.info("Test audit log created")


# ==================== ОСНОВНАЯ ФУНКЦИЯ ИНИЦИАЛИЗАЦИИ ====================

async def init_database_with_users() -> None:
    """
    Инициализация БД с созданием дефолтных пользователей.
    
    Выполняется при старте приложения в development и test окружениях.
    """
    if settings.ENVIRONMENT not in ["development", "test"]:
        logger.info(f"Skipping user initialization in {settings.ENVIRONMENT} environment")
        return
    
    logger.info(f"Initializing database with default users ({settings.ENVIRONMENT} mode)")
    
    try:
        async with AsyncSessionLocal() as session:
            # Создаём админа
            admin = await create_default_admin(session)
            
            # Создаём обычного пользователя (для development и test)
            user = await create_default_user(session)
            
            # Создаём тестовый аудит-лог (только для test)
            if settings.ENVIRONMENT == "test" and admin:
                await create_audit_log_for_test(session, admin.id)
            
            # Создаём тестовый аудит-лог для обычного пользователя
            if settings.ENVIRONMENT == "test" and user:
                await create_audit_log_for_test(session, user.id)
            
            logger.info("Database initialization completed successfully")
            
    except Exception as e:
        logger.error(f"Failed to initialize database with users: {e}")
        raise


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ ТЕСТОВ ====================

async def ensure_test_users(
    session: AsyncSession,
    commit: bool = False,
) -> tuple[User, User]:
    """
    Гарантированное создание админа и обычного пользователя для тестов.
    
    Используется в тестовых фикстурах для быстрого создания пользователей.
    Для тестов рекомендуется использовать commit=False и управлять транзакцией через фикстуру.
    
    Args:
        session: Сессия БД
        commit: Выполнять commit (False для тестов с rollback)
    
    Returns:
        tuple[User, User]: (админ, обычный пользователь)
    """
    admin = await get_or_create_user(
        session=session,
        email=DEFAULT_ADMIN_EMAIL,
        password=DEFAULT_ADMIN_PASSWORD,
        is_superuser=True,
        is_active=True,
        is_email_verified=True,
        commit=commit,
    )
    
    user = await get_or_create_user(
        session=session,
        email=DEFAULT_USER_EMAIL,
        password=DEFAULT_USER_PASSWORD,
        is_superuser=False,
        is_active=True,
        is_email_verified=True,
        commit=commit,
    )
    
    return admin, user


async def ensure_audit_logs(session: AsyncSession, user_id: uuid4) -> None:
    """
    Гарантированное создание тестовых аудит-логов.
    
    Args:
        session: Сессия БД
        user_id: ID пользователя
    """
    await create_audit_log_for_test(session, user_id)