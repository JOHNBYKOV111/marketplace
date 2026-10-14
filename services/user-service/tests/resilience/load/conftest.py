"""
Circuit-specific test fixtures.

Imports all common fixtures from the parent resilience conftest.
Circuit tests use default thresholds — they verify state transitions
under controlled fault injection, not stress conditions.

Optimized hierarchy:
    - First test initialization: 10s sleep executed exactly ONCE 
      to cover PostgreSQL cold start and migration.
    - Subsequent tests: 1s cool-down sleep to clear TIME_WAIT sockets.
"""

import asyncio
import pytest_asyncio

# Re-export everything from the parent conftest
from ..conftest import *

# Circuit-specific: standard thresholds for state transition tests
TEST_FAILURE_THRESHOLD: int = 100
TEST_RECOVERY_TIMEOUT: float = 3.0

# Глобальный флаг в памяти модуля — выживает между тестами
_IS_COLD_START: bool = True


@pytest_asyncio.fixture(scope="function", autouse=True)
async def _circuit_smart_warmup():
    """
    УМНЫЙ ПОТЕСТОВЫЙ ПРОГРЕВ И ОЧИСТКА СЕТИ.
    
    Использует scope="function", что полностью совместимо с pytest-asyncio,
    но благодаря флагу _IS_COLD_START делает 10-секундную паузу только ОДИН раз
    при старте самого первого теста в модуле. На всех остальных тестах
    он просто делает быструю 1-секундную паузу для сброса TIME_WAIT сокетов.
    """
    global _IS_COLD_START
    
    if _IS_COLD_START:
        print("\n  [Cold Start] Обнаружен холодный старт СУБД. Ждем 10с для наката миграций...")
        await asyncio.sleep(10.0)
        _IS_COLD_START = False  # Переключаем флаг, больше этот блок не выполнится
    else:
        # Для всех последующих тестов даем сети остыть ровно 1 секунду
        await asyncio.sleep(1.0)
        
    yield
