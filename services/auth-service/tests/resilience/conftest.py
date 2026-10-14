"""
Общие фикстуры и утилиты для resilience-тестов.

Содержит:
- HTTP клиент с таймаутами для нагрузочных/отказоустойчивых тестов
- Фикстуры для инъекции отказов (Redis, Kafka, БД)
- Фикстуры тестовых данных (пользователи)
- Утилиты для сбора статистики производительности
- Функции замера ресурсов (память)
- Вычисление перцентилей (p50, p90, p99)
- Вспомогательные функции (seed_test_user)
- Глобальный патч настроек для всех тестов
- Фикстуры для подмены зависимостей через app.dependency_overrides
- Общие фикстуры для intermittent failure pattern
- Фикстуры для работы с реальным Redis
- Общие MFA-хелперы и фикстуры
- Хелперы для нагрузочного тестирования (run_batch_requests, run_mixed_batch_requests)

Используется всеми тестовыми файлами в tests/resilience/.
"""

import asyncio
import os
import time
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import status
from httpx import AsyncClient

from app.main import app
from app.core.config import settings
from app.core.database import get_db
from app.core.redis_client import redis_client
from app.models.user import User
from app.repositories.user_repository import UserRepository


# ==================== ГЛОБАЛЬНЫЙ ПАТЧ НАСТРОЕК ====================
# Сервис auth_service использует ACCESS_TOKEN_EXPIRE_MINUTES и REFRESH_TOKEN_EXPIRE_DAYS
# без префикса JWT_, а в settings переменные называются с префиксом.
# Pydantic v2 блокирует setattr, поэтому пишем напрямую в __dict__.
# Патч применяется для ВСЕХ тестов в папке tests/resilience/.

settings.__dict__["ACCESS_TOKEN_EXPIRE_MINUTES"] = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
settings.__dict__["REFRESH_TOKEN_EXPIRE_DAYS"] = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS


# ==================== HTTP КЛИЕНТ ====================

@pytest.fixture
async def client():
    """
    Фикстура HTTP клиента с увеличенными таймаутами.

    Таймаут 30 секунд — достаточен для нагрузочных тестов
    и тестов с сетевыми задержками.

    Используется во всех resilience-тестах.
    """
    async with AsyncClient(
        app=app,
        base_url="http://test",
        timeout=30.0,
    ) as client:
        yield client


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

async def seed_test_user(email="admin@test.com", password="SecurePass123!"):
    """
    Создаёт тестового пользователя в БД если он не существует.

    Используется в нагрузочных тестах, где нужен реальный пользователь
    для логина и получения токенов.

    Args:
        email: Email пользователя
        password: Пароль пользователя

    Returns:
        User: Созданный или существующий пользователь

    Используется в:
    - test_high_load.py
    - test_extreme_load.py
    """
    from app.core.security import hash_password_bcrypt

    async for session in get_db():
        repo = UserRepository(session)

        email_hash = User.create_email_hash(email)
        existing = await repo.get_by_email_hash(email_hash)

        if existing:
            return existing

        user = User(
            id=uuid4(),
            email=email,
            email_hash=email_hash,
            password_hash=hash_password_bcrypt(password),
            is_active=True,
            is_email_verified=True,
            is_superuser=False,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


# ==================== ТЕСТОВЫЕ ДАННЫЕ ====================

@pytest.fixture
def test_user_data():
    """
    Фикстура с данными тестового пользователя для тестов целостности данных.

    Возвращает словарь с уникальными email, password и email_hash.

    Используется в:
    - test_data_integrity.py
    """
    return {
        "email": f"integrity_test_{uuid4().hex[:8]}@example.com",
        "password": "SecurePass123!",
        "email_hash": User.create_email_hash(f"integrity_test_{uuid4().hex[:8]}@example.com"),
    }


@pytest.fixture
def user_id():
    """Фикстура с уникальным ID пользователя."""
    return uuid4()


@pytest.fixture
def user_uuid():
    """Фикстура с уникальным UUID пользователя."""
    return uuid4()


# ==================== MFA ХЕЛПЕРЫ И ФИКСТУРЫ ====================

@pytest.fixture
def mfa_headers():
    """
    Фикстура с заголовками для MFA-запросов.
    
    Возвращает словарь с уникальным user_id и стандартными заголовками.
    Каждый тест получает новый уникальный user_id.

    Используется в:
    - test_redis_resilience.py
    """
    return {
        "X-User-Id": str(uuid4()),
        "X-User-Roles": "user",
        "X-User-Email": "test@example.com",
    }


async def verify_totp(client, headers, code="123456"):
    """
    Хелпер для вызова TOTP верификации.
    
    Args:
        client: HTTP-клиент
        headers: заголовки запроса
        code: TOTP-код (по умолчанию "123456")
    
    Returns:
        Response: ответ FastAPI

    Используется в:
    - test_redis_resilience.py
    """
    return await client.post(
        "/mfa/totp/verify",
        headers=headers,
        json={"code": code},
    )


# ==================== НАГРУЗОЧНЫЕ ХЕЛПЕРЫ ====================

async def run_batch_requests(client, endpoint, count, batch_size=100):
    """
    Выполняет пакетные запросы к одному эндпоинту и возвращает статистику.
    
    Args:
        client: HTTP-клиент
        endpoint: URL эндпоинта
        count: общее количество запросов
        batch_size: размер пакета
    
    Returns:
        dict: {"success": int, "error": int}

    Используется в:
    - test_resource_leaks.py
    - test_high_load.py
    - test_extreme_load.py
    """
    success = 0
    error = 0

    for batch_start in range(0, count, batch_size):
        current_batch = min(batch_size, count - batch_start)
        tasks = [client.get(endpoint) for _ in range(current_batch)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for resp in responses:
            if isinstance(resp, Exception):
                error += 1
            elif hasattr(resp, 'status_code') and resp.status_code == status.HTTP_200_OK:
                success += 1
            else:
                error += 1

    return {"success": success, "error": error}


async def run_mixed_batch_requests(client, endpoints, count, batch_size=100):
    """
    Выполняет пакетные запросы к разным эндпоинтам и возвращает статистику.
    
    Args:
        client: HTTP-клиент
        endpoints: список URL эндпоинтов (циклически)
        count: общее количество запросов
        batch_size: размер пакета
    
    Returns:
        dict: {"success": int, "error": int}

    Используется в:
    - test_resource_leaks.py
    - test_high_load.py
    """
    success = 0
    error = 0

    for batch_start in range(0, count, batch_size):
        current_batch = min(batch_size, count - batch_start)
        tasks = []
        for i in range(current_batch):
            endpoint = endpoints[i % len(endpoints)]
            tasks.append(client.get(endpoint))
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for resp in responses:
            if isinstance(resp, Exception):
                error += 1
            elif hasattr(resp, 'status_code') and resp.status_code == status.HTTP_200_OK:
                success += 1
            else:
                error += 1

    return {"success": success, "error": error}


# ==================== FAULT INJECTION ====================

@pytest.fixture
def call_counter():
    """
    Фикстура-счётчик вызовов для intermittent failure pattern.

    Возвращает словарь со счётчиком, который мутируется в тестах.
    Каждый тест получает чистый счётчик (0).

    Используется в:
    - test_postgresql_resilience.py
    - test_network_resilience.py
    """
    return {"count": 0}


@pytest.fixture
def fault_injection():
    """
    Фикстура для инъекции отказов в зависимости.

    Возвращает словарь с флагами, позволяющими точечно
    включать/выключать отказы без перезапуска контейнеров.

    Используется в:
    - test_circuit_breaker.py
    - test_graceful_degradation.py
    """
    return {
        "redis_failures": 0,
        "redis_should_fail": False,
        "kafka_should_fail": False,
        "db_should_fail": False,
    }


@pytest.fixture
def redis_fault():
    """
    Фикстура для управления состоянием Redis.

    Позволяет переключать Redis между доступным/недоступным состоянием.

    Используется в:
    - test_redis_resilience.py
    """
    return {
        "available": True,
        "failure_count": 0,
    }


@pytest.fixture
def db_fault():
    """
    Фикстура для управления состоянием БД.

    Позволяет переключать БД между доступным/недоступным состоянием.

    Используется в:
    - test_postgresql_resilience.py
    """
    return {
        "available": True,
        "failure_count": 0,
    }


@pytest.fixture
def kafka_fault():
    """
    Фикстура для управления состоянием Kafka.

    Позволяет переключать Kafka между доступным/недоступным состоянием.

    Используется в:
    - test_kafka_resilience.py
    """
    return {
        "available": True,
        "sent_events": [],
        "failed_events": [],
    }


@pytest.fixture
def network_fault():
    """
    Фикстура для симуляции сетевых проблем.

    Позволяет задавать задержки и типы сетевых ошибок.

    Используется в:
    - test_network_resilience.py
    """
    return {
        "latency_ms": 0,
        "packet_loss": False,
        "connection_reset": False,
    }


# ==================== REDIS ФИКСТУРЫ ====================

@pytest.fixture
async def real_redis():
    """
    Фикстура с реальным Redis-клиентом.
    
    Предоставляет доступ к реальному Redis для подготовки тестовых данных
    и проверки состояния после выполнения операций.

    Используется в:
    - test_redis_resilience.py
    - test_resource_leaks.py
    """
    return redis_client


@pytest.fixture
async def redis_disabled():
    """
    Фикстура для временного отключения Redis через симуляцию сетевой ошибки.
    
    Патчит основные методы RedisClient чтобы они выбрасывали TimeoutError.
    Это заставляет приложение зайти в ветку обработки аварий (fail open),
    не трогая приватные атрибуты класса.
    
    Production-стандарт: patch.object методов на уровне инстанса,
    гарантированное восстановление через контекстный менеджер.

    Используется в:
    - test_redis_resilience.py
    - test_resource_leaks.py
    """
    import redis.exceptions as redis_exc

    timeout_error = redis_exc.TimeoutError("Redis connection timed out (simulated)")

    with patch.object(redis_client, "get", side_effect=timeout_error), \
         patch.object(redis_client, "set", side_effect=timeout_error), \
         patch.object(redis_client, "get_json", side_effect=timeout_error), \
         patch.object(redis_client, "set_json", side_effect=timeout_error), \
         patch.object(redis_client, "ping", side_effect=timeout_error), \
         patch.object(redis_client, "incr", side_effect=timeout_error), \
         patch.object(redis_client, "delete", side_effect=timeout_error), \
         patch.object(redis_client, "exists", side_effect=timeout_error), \
         patch.object(redis_client, "rate_limit_atomic", side_effect=timeout_error), \
         patch.object(redis_client, "get_idempotency_result", side_effect=timeout_error), \
         patch.object(redis_client, "set_idempotency_result", side_effect=timeout_error):
        yield


@pytest.fixture
async def clean_redis_key(real_redis):
    """
    Фикстура для автоматической очистки Redis-ключей после теста.
    
    Возвращает корутину register_key(key), которую тест вызывает
    для регистрации ключа на удаление. Все зарегистрированные ключи
    будут удалены при завершении теста.

    Используется в:
    - test_redis_resilience.py
    """
    keys_to_clean = []

    async def register_key(key):
        keys_to_clean.append(key)

    yield register_key

    for key in keys_to_clean:
        try:
            await real_redis.delete(key)
        except Exception:
            pass  # Redis может быть уже отключён


# ==================== OAuth ТЕСТОВЫЕ ДАННЫЕ ====================

@pytest.fixture
def oauth_state_data():
    """
    Фикстура с данными OAuth state в Redis.

    Используется в:
    - test_network_resilience.py (test_oauth_exchange_code_timeout,
      test_dns_failure_handled_for_external_services)
    """
    return {
        "provider": "google",
        "redirect_uri": "https://example.com/callback",
        "code_verifier": "test_verifier",
        "is_linked": False,
        "user_id": None,
    }


# ==================== DEPENDENCY OVERRIDE ФИКСТУРЫ ====================

@pytest.fixture
async def override_get_oauth_service():
    """
    Фикстура для подмены get_oauth_service через app.dependency_overrides.

    Гарантирует восстановление оригинальной зависимости после теста.

    Использование в тесте:
        def test_something(client, override_get_oauth_service):
            get_oauth_service = override_get_oauth_service
            mock_oauth = AsyncMock()
            app.dependency_overrides[get_oauth_service] = lambda: mock_oauth
            # ... тест ...
        # после выхода из теста зависимость автоматически восстановлена

    Используется в:
    - test_network_resilience.py
    """
    from app.routers.oauth import get_oauth_service

    original = app.dependency_overrides.get(get_oauth_service)
    yield get_oauth_service
    if original:
        app.dependency_overrides[get_oauth_service] = original
    else:
        app.dependency_overrides.pop(get_oauth_service, None)


@pytest.fixture
async def override_get_health_service():
    """
    Фикстура для подмены get_health_service через app.dependency_overrides.

    Гарантирует восстановление оригинальной зависимости после теста.

    Использование в тесте:
        def test_something(client, override_get_health_service):
            get_health_service = override_get_health_service
            mock_health = AsyncMock()
            app.dependency_overrides[get_health_service] = lambda: mock_health
            # ... тест ...
        # после выхода из теста зависимость автоматически восстановлена

    Используется в:
    - test_postgresql_resilience.py
    """
    from app.routers.health import get_health_service

    original = app.dependency_overrides.get(get_health_service)
    yield get_health_service
    if original:
        app.dependency_overrides[get_health_service] = original
    else:
        app.dependency_overrides.pop(get_health_service, None)


# ==================== СТАТИСТИКА ПРОИЗВОДИТЕЛЬНОСТИ ====================

@pytest.fixture
def perf_stats():
    """
    Фикстура для сбора статистики производительности.

    Возвращает словарь, в который тесты записывают:
    - response_times: список времён ответа в секундах
    - errors: список ошибок
    - status_codes: счётчик статус-кодов

    Используется в:
    - test_high_load.py
    - test_extreme_load.py
    - test_resource_leaks.py
    """
    return {
        "response_times": [],
        "errors": [],
        "status_codes": {},
    }


@pytest.fixture
def performance_stats():
    """
    Алиас для perf_stats — сбор статистики производительности.

    Используется в:
    - test_extreme_load.py (для обратной совместимости)
    """
    return {
        "response_times": [],
        "errors": [],
        "status_codes": {},
    }


@pytest.fixture
def resource_stats():
    """
    Фикстура для сбора статистики использования ресурсов.

    Собирает:
    - memory_start_mb / memory_end_mb: потребление памяти
    - memory_samples: промежуточные замеры
    - db_connections_start / db_connections_end: соединения с БД

    Используется в:
    - test_resource_leaks.py
    """
    return {
        "memory_start_mb": 0,
        "memory_end_mb": 0,
        "memory_samples": [],
        "db_connections_start": 0,
        "db_connections_end": 0,
    }


# ==================== УТИЛИТЫ ====================

def calc_percentiles(times, percentiles=None):
    """
    Вычисление перцентилей из списка времён ответа.

    Args:
        times: список времён ответа в секундах
        percentiles: список перцентилей (по умолчанию [50, 90, 95, 99])

    Returns:
        dict: словарь {p50: значение, p90: значение, p95: значение, p99: значение}

    Используется в:
    - test_high_load.py
    - test_extreme_load.py
    - test_resource_leaks.py
    """
    if percentiles is None:
        percentiles = [50, 90, 95, 99]

    if not times:
        return {f"p{p}": 0 for p in percentiles}

    sorted_times = sorted(times)
    result = {}

    for p in percentiles:
        idx = min(int(len(sorted_times) * p / 100), len(sorted_times) - 1)
        result[f"p{p}"] = sorted_times[idx]

    return result


def calculate_percentiles(times, percentiles=None):
    """
    Алиас для calc_percentiles — вычисление перцентилей.

    Используется в:
    - test_extreme_load.py (для обратной совместимости)
    """
    return calc_percentiles(times, percentiles)


def get_process_memory_mb():
    """
    Получение текущего потребления памяти процесса в МБ.

    Требует psutil. Если не установлен — возвращает 0.

    Returns:
        float: потребление памяти в мегабайтах

    Используется в:
    - test_resource_leaks.py
    """
    try:
        import psutil
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024
    except ImportError:
        return 0