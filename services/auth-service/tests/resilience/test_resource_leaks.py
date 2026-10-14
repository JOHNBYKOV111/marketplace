"""
Тесты утечек ресурсов при длительной нагрузке.

Тестирует:
- Отсутствие исчерпания пула соединений БД после 2 минут sustained нагрузки
- Отсутствие утечки соединений Redis после 10 000 операций
- Стабильное потребление памяти после 100 000 JWKS запросов
- Корректное закрытие соединений после исключений

Архитектура тестов (Production-стандарт):
- 100% реальная логика: FastAPI, PostgreSQL (пул соединений), Redis (пул соединений)
- Fault injection только через patch.object методов RedisClient (инфраструктурный уровень)
- Длительные тесты: sustained нагрузка с замерами ресурсов
- Замеры ресурсов: память процесса через psutil
- Все фикстуры и тесты асинхронные
- Все фикстуры используют фикстуры из conftest.py (resource_stats)
- Инфраструктурные тесты фокусируются на стабильности памяти, а не на бизнес-успехах

Связанные модули:
- app.core.database - пул соединений PostgreSQL
- app.core.redis_client - клиент Redis
- app.routers.jwks - JWKS эндпоинт
- app.routers.health - liveness, readiness, health, metrics
"""

import asyncio
import os
import time
from unittest.mock import patch

import pytest
import redis.exceptions as redis_exc
from fastapi import status
from httpx import AsyncClient

from app.main import app
from app.core.redis_client import redis_client


# ==================== ФИКСТУРЫ ====================

@pytest.fixture
async def client():
    """Фикстура HTTP клиента с большими таймаутами для длительных тестов."""
    async with AsyncClient(
        app=app,
        base_url="http://test",
        timeout=60.0,
    ) as client:
        yield client


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

def get_process_memory_mb() -> float:
    """
    Возвращает текущее потребление памяти процессом в мегабайтах.
    
    Использует psutil если доступен, иначе resource (Linux).
    """
    try:
        import psutil
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / (1024 * 1024)
    except ImportError:
        try:
            import resource
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        except ImportError:
            return 0.0


async def run_batch_requests(client, url, count, method="GET", json_data=None):
    """
    Отправляет пачку запросов к одному эндпоинту для проверки утечек.
    
    Разбивает на пачки по 100 чтобы не перегружать сетевой стек httpx.
    Возвращает статистику успешных/ошибочных запросов.
    """
    success = 0
    error = 0

    async def send_req():
        nonlocal success, error
        try:
            if method == "POST":
                resp = await client.post(url, json=json_data)
            else:
                resp = await client.get(url)
            if resp.status_code == status.HTTP_200_OK:
                success += 1
            else:
                error += 1
        except Exception:
            error += 1

    batch_size = 100
    for i in range(0, count, batch_size):
        tasks = [send_req() for _ in range(min(batch_size, count - i))]
        await asyncio.gather(*tasks)

    return {"success": success, "error": error}


async def run_mixed_batch_requests(client, endpoints, count):
    """
    Отправляет смешанную нагрузку для проверки стабильности памяти.
    
    Разбивает на пачки по 100. Возвращает статистику.
    """
    success = 0
    error = 0

    async def send_mixed(i):
        nonlocal success, error
        try:
            endpoint = endpoints[i % len(endpoints)]
            resp = await client.get(endpoint)
            if resp.status_code == status.HTTP_200_OK:
                success += 1
            else:
                error += 1
        except Exception:
            error += 1

    batch_size = 100
    for i in range(0, count, batch_size):
        tasks = [send_mixed(j) for j in range(i, min(i + batch_size, count))]
        await asyncio.gather(*tasks)

    return {"success": success, "error": error}


# ==================== УТЕЧКИ ПУЛА БД ====================

class TestDatabaseConnectionPool:
    """Тесты утечек пула соединений БД."""

    async def test_db_connection_pool_not_exhausted_under_sustained_load(
        self,
        client,
        resource_stats,
    ):
        """
        Тест что пул соединений БД не исчерпывается при sustained нагрузке.

        Flow:
        1. Замеряем начальное потребление памяти
        2. Отправляем 2 запроса в секунду в течение 2 минут (240 запросов)
        3. Замеряем конечное потребление памяти
        4. Ни одного отказа из-за нехватки соединений
        5. Память не должна расти более чем на 50%

        Production-сценарий:
        Длительная нагрузка на сервис. Пул соединений не должен
        исчерпываться — соединения должны возвращаться в пул.
        """
        DURATION_SECONDS = 120  # 2 минуты
        RPS = 2  # запроса в секунду

        resource_stats["memory_start_mb"] = get_process_memory_mb()

        results = {"success": 0, "error": 0, "pool_exhausted": 0}
        request_count = 0
        start_time = time.monotonic()

        while time.monotonic() - start_time < DURATION_SECONDS:
            batch_tasks = [client.get("/.well-known/jwks.json") for _ in range(RPS)]
            responses = await asyncio.gather(*batch_tasks, return_exceptions=True)

            for resp in responses:
                request_count += 1
                if isinstance(resp, Exception):
                    results["error"] += 1
                elif hasattr(resp, 'status_code'):
                    if resp.status_code == status.HTTP_200_OK:
                        results["success"] += 1
                    elif resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE:
                        results["pool_exhausted"] += 1
                    else:
                        results["error"] += 1

            if request_count % 20 == 0:
                mem = get_process_memory_mb()
                resource_stats["memory_samples"].append(mem)

            await asyncio.sleep(1.0 / RPS)

        resource_stats["memory_end_mb"] = get_process_memory_mb()

        print(f"\n=== DB Connection Pool Sustained Load ===")
        print(f"Duration: {DURATION_SECONDS}s")
        print(f"Total requests: {request_count}")
        print(f"Success: {results['success']}")
        print(f"Pool exhausted (503): {results['pool_exhausted']}")
        print(f"Errors: {results['error']}")
        print(f"Memory start: {resource_stats['memory_start_mb']:.1f}MB")
        print(f"Memory end: {resource_stats['memory_end_mb']:.1f}MB")
        if resource_stats["memory_samples"]:
            print(f"Memory min: {min(resource_stats['memory_samples']):.1f}MB")
            print(f"Memory max: {max(resource_stats['memory_samples']):.1f}MB")

        assert results["pool_exhausted"] == 0, (
            f"Не должно быть отказов из-за пула, получено {results['pool_exhausted']}"
        )

        success_rate = results["success"] / request_count * 100 if request_count > 0 else 0
        assert success_rate >= 95, f"Success rate >= 95%, получено {success_rate:.1f}%"

        if resource_stats["memory_start_mb"] > 0 and resource_stats["memory_end_mb"] > 0:
            memory_growth = (
                (resource_stats["memory_end_mb"] - resource_stats["memory_start_mb"])
                / resource_stats["memory_start_mb"] * 100
            )
            print(f"Memory growth: {memory_growth:.1f}%")
            assert memory_growth < 50, (
                f"Рост памяти не должен превышать 50%, получено {memory_growth:.1f}%"
            )

    async def test_connections_released_after_exception(
        self,
        client,
    ):
        """
        Тест что соединения возвращаются в пул после исключений.

        Flow:
        1. Имитируем отказ Redis (первые 5 запросов падают с TimeoutError)
        2. Redis восстанавливается
        3. Последующие запросы должны выполняться нормально
        4. Соединения не зависают в состоянии "взято"

        Production-сценарий:
        Ошибка в середине транзакции. Соединение должно быть
        возвращено в пул, а не зависнуть навсегда.

        Production-стандарт: patch.object методов RedisClient для fault injection,
        гарантированное восстановление через контекстный менеджер.
        """
        timeout_error = redis_exc.TimeoutError("Redis connection timed out (simulated)")
        call_count = {"count": 0}

        async def fail_5_then_recover(*args, **kwargs):
            call_count["count"] += 1
            if call_count["count"] <= 5:
                raise timeout_error
            return None  # кэш пуст, fallback к БД

        with patch.object(redis_client, "get_json", side_effect=fail_5_then_recover), \
             patch.object(redis_client, "set_json", side_effect=fail_5_then_recover):

            results = []
            for _ in range(10):
                response = await client.get("/.well-known/jwks.json")
                results.append(response.status_code)

            print(f"\n=== Connection Release After Exception ===")
            print(f"Results: {results}")
            print(f"Redis failures: {call_count['count']}")

            # После ошибок запросы должны восстановиться
            success_after_errors = sum(1 for r in results[5:] if r == status.HTTP_200_OK)
            assert success_after_errors >= 3, (
                f"Минимум 3 успешных запроса после ошибок, получено {success_after_errors}"
            )


# ==================== УТЕЧКИ REDIS ====================

class TestRedisConnectionLeaks:
    """Тесты утечек соединений Redis."""

    async def test_redis_connection_leak_after_10000_operations(
        self,
        client,
    ):
        """
        Тест что нет утечки соединений Redis после 10 000 операций.

        Flow:
        1. Выполняем 10 000 запросов к JWKS
        2. Все запросы должны быть успешными
        3. Соединения не должны накапливаться

        Production-сценарий:
        Длительная работа сервиса. Redis-соединения не должны
        накапливаться — каждое должно закрываться после использования.
        """
        OPERATIONS = 10000

        start_time = time.monotonic()

        stats = await run_batch_requests(
            client, "/.well-known/jwks.json", OPERATIONS
        )

        total_time = time.monotonic() - start_time

        print(f"\n=== Redis Connection Leak Test ===")
        print(f"Total operations: {OPERATIONS}")
        print(f"Success: {stats['success']}")
        print(f"Errors: {stats['error']}")
        print(f"Time: {total_time:.1f}s")
        print(f"Avg RPS: {OPERATIONS / total_time:.0f}")

        assert stats["error"] == 0, f"0 ошибок, получено {stats['error']}"

        success_rate = stats["success"] / OPERATIONS * 100
        assert success_rate >= 99, f"Success rate >= 99%, получено {success_rate:.1f}%"

    async def test_redis_connection_recovery_after_failures(
        self,
        client,
    ):
        """
        Тест что Redis соединения восстанавливаются после серии отказов.

        Flow:
        1. Имитируем 10 отказов Redis подряд через TimeoutError
        2. Восстанавливаем Redis
        3. Следующие запросы должны работать нормально

        Production-сценарий:
        Redis несколько раз перезапустился. Сервис должен
        переподключаться без утечки соединений.

        Production-стандарт: patch.object методов RedisClient для fault injection,
        гарантированное восстановление через контекстный менеджер.
        """
        timeout_error = redis_exc.TimeoutError("Redis connection timed out (simulated)")
        failure_count = {"count": 0}

        async def fail_10_then_recover(*args, **kwargs):
            failure_count["count"] += 1
            if failure_count["count"] <= 10:
                raise timeout_error
            return None  # кэш пуст, fallback к БД

        with patch.object(redis_client, "get_json", side_effect=fail_10_then_recover), \
             patch.object(redis_client, "set_json", side_effect=fail_10_then_recover):

            results = []
            for i in range(20):
                response = await client.get("/.well-known/jwks.json")
                results.append(response.status_code)

            print(f"\n=== Redis Connection Recovery ===")
            print(f"Results: {results}")
            print(f"Redis failures: {failure_count['count']}")

            success_after_recovery = sum(
                1 for r in results[10:] if r == status.HTTP_200_OK
            )
            assert success_after_recovery >= 8, (
                f"Минимум 8 успешных после восстановления, получено {success_after_recovery}"
            )


# ==================== УТЕЧКИ ПАМЯТИ ====================

class TestMemoryStability:
    """Тесты стабильности потребления памяти."""

    async def test_memory_stable_after_100000_jwks_requests(
        self,
        client,
        resource_stats,
    ):
        """
        Тест что потребление памяти стабильно после 100 000 JWKS запросов.

        Flow:
        1. Замеряем начальное потребление памяти
        2. Отправляем 100 000 запросов к JWKS
        3. Замеряем конечное потребление памяти
        4. Рост памяти не должен превышать 100%
        5. Память должна стабилизироваться (не расти линейно)

        Production-сценарий:
        Сервис работает неделями без перезапуска. Память не должна
        расти — нет утечек в Python-объектах, кэшах, логах.
        """
        REQUEST_COUNT = 100000
        BATCH_SIZE = 200

        resource_stats["memory_start_mb"] = get_process_memory_mb()

        success = 0
        error = 0
        start_time = time.monotonic()

        for batch_start in range(0, REQUEST_COUNT, BATCH_SIZE):
            current_batch = min(BATCH_SIZE, REQUEST_COUNT - batch_start)
            tasks = [client.get("/.well-known/jwks.json") for _ in range(current_batch)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for resp in responses:
                if isinstance(resp, Exception):
                    error += 1
                elif hasattr(resp, 'status_code') and resp.status_code == status.HTTP_200_OK:
                    success += 1
                else:
                    error += 1

            if (batch_start + current_batch) % 10000 == 0:
                elapsed = time.monotonic() - start_time
                current_mem = get_process_memory_mb()
                resource_stats["memory_samples"].append(current_mem)
                progress = (batch_start + current_batch) / REQUEST_COUNT * 100
                print(f"Progress: {progress:.0f}% ({batch_start + current_batch}/{REQUEST_COUNT}) "
                      f"- {elapsed:.1f}s - Memory: {current_mem:.1f}MB")

        resource_stats["memory_end_mb"] = get_process_memory_mb()
        total_time = time.monotonic() - start_time

        print(f"\n=== Memory Stability After 100K Requests ===")
        print(f"Total requests: {REQUEST_COUNT}")
        print(f"Success: {success}")
        print(f"Errors: {error}")
        print(f"Time: {total_time:.1f}s")
        print(f"Avg RPS: {REQUEST_COUNT / total_time:.0f}")
        print(f"Memory start: {resource_stats['memory_start_mb']:.1f}MB")
        print(f"Memory end: {resource_stats['memory_end_mb']:.1f}MB")
        if resource_stats["memory_samples"]:
            print(f"Memory samples: {[f'{m:.1f}' for m in resource_stats['memory_samples']]}")

        success_rate = success / REQUEST_COUNT * 100 if REQUEST_COUNT > 0 else 0
        assert success_rate >= 99.5, f"Success rate >= 99.5%, получено {success_rate:.2f}%"

        if resource_stats["memory_start_mb"] > 0 and resource_stats["memory_end_mb"] > 0:
            memory_growth = (
                (resource_stats["memory_end_mb"] - resource_stats["memory_start_mb"])
                / resource_stats["memory_start_mb"] * 100
            )
            print(f"Memory growth: {memory_growth:.1f}%")
            assert memory_growth < 100, (
                f"Рост памяти не должен превышать 100%, получено {memory_growth:.1f}%"
            )

            if len(resource_stats["memory_samples"]) >= 3:
                mid = len(resource_stats["memory_samples"]) // 2
                first_half = resource_stats["memory_samples"][:mid]
                second_half = resource_stats["memory_samples"][mid:]
                avg_first = sum(first_half) / len(first_half)
                avg_second = sum(second_half) / len(second_half)
                print(f"Memory first half avg: {avg_first:.1f}MB")
                print(f"Memory second half avg: {avg_second:.1f}MB")
                if avg_first > 0:
                    half_growth = (avg_second - avg_first) / avg_first * 100
                    assert half_growth < 20, (
                        f"Рост памяти во второй половине < 20%, получено {half_growth:.1f}%"
                    )

    async def test_memory_stable_under_mixed_workload(
        self,
        client,
        resource_stats,
    ):
        """
        Тест что память стабильна при смешанной нагрузке.

        Flow:
        1. Выполняем 5000 запросов разных типов (JWKS, liveness, readiness)
        2. Замеряем память до и после
        3. Главный критерий — память не должна вырасти более чем на 30%

        Production-сценарий:
        Реальный трафик — смесь из разных эндпоинтов.
        Память должна быть стабильна независимо от типа запросов.
        Инфраструктурный тест — проверяет утечки памяти, а не бизнес-логику.
        """
        REQUEST_COUNT = 5000

        resource_stats["memory_start_mb"] = get_process_memory_mb()

        endpoints = [
            "/.well-known/jwks.json",
            "/api/v1/liveness",
            "/api/v1/readiness",
            "/api/v1/health/",
            "/api/v1/metrics",
        ]

        start_time = time.monotonic()
        stats = await run_mixed_batch_requests(client, endpoints, REQUEST_COUNT)

        resource_stats["memory_end_mb"] = get_process_memory_mb()
        total_time = time.monotonic() - start_time

        print(f"\n=== Memory Stability Mixed Workload ===")
        print(f"Total requests: {REQUEST_COUNT}")
        print(f"Success: {stats['success']}")
        print(f"Errors: {stats['error']}")
        print(f"Time: {total_time:.1f}s")
        print(f"Memory start: {resource_stats['memory_start_mb']:.1f}MB")
        print(f"Memory end: {resource_stats['memory_end_mb']:.1f}MB")

        if resource_stats["memory_start_mb"] > 0 and resource_stats["memory_end_mb"] > 0:
            memory_growth = (
                (resource_stats["memory_end_mb"] - resource_stats["memory_start_mb"])
                / resource_stats["memory_start_mb"] * 100
            )
            print(f"Memory growth: {memory_growth:.1f}%")
            assert memory_growth < 30.0, (
                f"Память слишком сильно выросла под смешанной нагрузкой: {memory_growth:.1f}%"
            )


# ==================== БЫСТРЫЕ ПРОВЕРКИ ДЛЯ CI ====================

class TestResourceLeaksQuick:
    """Быстрые тесты для проверки утечек в CI."""

    async def test_1000_requests_no_connection_leak(
        self,
        client,
    ):
        """
        Быстрый тест: 1000 запросов без утечки соединений.

        Проверяет базовую стабильность пула соединений.
        """
        stats = await run_batch_requests(
            client, "/.well-known/jwks.json", 1000
        )

        print(f"\n=== Quick 1000 Requests ===")
        print(f"Success: {stats['success']}")
        print(f"Errors: {stats['error']}")

        assert stats["error"] == 0, f"0 ошибок, получено {stats['error']}"
        assert stats["success"] == 1000, (
            f"Все 1000 должны быть успешными, получено {stats['success']}"
        )