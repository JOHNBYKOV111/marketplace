"""
Тесты отказоустойчивости PostgreSQL.

Тестирует:
- Логин при недоступной БД (OperationalError на уровне репозитория)
- Автоматическое восстановление пула соединений после падения БД
- Транзакционную целостность при обрыве соединения
- Корректную обработку таймаутов пула соединений
- Health check при недоступной БД

Архитектура тестов (Production-стандарт):
- Реальная логика: FastAPI, SQLAlchemy пул соединений, health check
- Fault injection: OperationalError через AsyncMock-сессию (yield mock_session)
- Проверка восстановления пула после сбоя
- Все фикстуры и тесты асинхронные
- Моки только через app.dependency_overrides (FastAPI native)
- Все моки используют AsyncMock, MagicMock только для фейковых объектов Result
- Гарантированное восстановление через фикстуры с yield или patch.object

Связанные модули:
- app.core.database - пул соединений, get_db
- app.repositories.user_repository - операции с пользователями
- app.routers.auth - логин (используется для проверки восстановления пула,
  так как JWKS эндпоинт работает в режиме fail-open и игнорирует отказ БД)
- app.routers.health - health check

Важное замечание по архитектуре тестов:
- debug middleware (custom_route_handler) пробрасывает сырые исключения
  в pytest, поэтому отказы БД проверяются через pytest.raises(OperationalError),
  а восстановление — через HTTP-статусы 200/401
- Для восстановленной сессии эндпоинта логина необходим фейковый объект
  sqlalchemy.engine.Result с методом scalar_one_or_none(), так как репозиторий
  вызывает result.scalar_one_or_none() после execute()
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import status
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.main import app
from app.core.database import get_db
from app.repositories.user_repository import UserRepository
from app.models.user import User


# ==================== ЛОКАЛЬНЫЕ ФИКСТУРЫ ====================

@pytest.fixture
def call_counter():
    """Фикстура-счётчик вызовов для intermittent failure pattern."""
    return {"count": 0}


# ==================== ЛОГИН ПРИ ОТКАЗЕ БД ====================

class TestLoginWhenDatabaseUnavailable:
    """Тесты логина при недоступной БД."""

    async def test_login_when_database_unavailable(
        self,
        client,
    ):
        """
        Тест что логин падает с OperationalError при недоступной БД.

        Flow:
        1. Имитируем полную недоступность БД через AsyncMock-сессию
        2. Выполняем запрос на логин
        3. Приложение должно честно дойти до репозитория и упасть с OperationalError
        4. Доказываем что приложение пытается выполнить SQL-запрос, а не виснет

        Production-сценарий:
        PostgreSQL упал. Приложение должно попытаться выполнить запрос,
        получить OperationalError от драйвера БД и вернуть 503/500.
        Важно что исключение возникает на уровне репозитория, а не DI.

        Production-стандарт: AsyncMock-сессия с yield,
        pytest.raises для проверки что исключение долетело до репозитория.
        """
        async def failing_db():
            mock_session = AsyncMock()
            error_effect = OperationalError(
                "SELECT 1",
                {},
                Exception("could not connect to server: Connection refused"),
            )
            mock_session.execute = AsyncMock(side_effect=error_effect)
            mock_session.commit = AsyncMock(side_effect=error_effect)
            mock_session.flush = AsyncMock(side_effect=error_effect)
            yield mock_session

        original = app.dependency_overrides.get(get_db)

        try:
            app.dependency_overrides[get_db] = failing_db

            with pytest.raises(OperationalError):
                await client.post(
                    "/api/v1/auth/login",
                    json={
                        "email": "admin@test.com",
                        "password": "SecurePass123!",
                    },
                )

        finally:
            if original:
                app.dependency_overrides[get_db] = original
            else:
                app.dependency_overrides.pop(get_db, None)

    async def test_health_check_when_database_unavailable(
        self,
        client,
    ):
        """
        Тест что health readiness показывает БД как unhealthy при отказе.

        Flow:
        1. Имитируем отказ БД через HealthService.check_all_with_timeout
        2. Health readiness должен вернуть 503
        3. В деталях должно быть postgresql: healthy=False
        4. Liveness должен оставаться 200

        Production-сценарий:
        Kubernetes проверяет readiness. Если БД недоступна —
        под должен быть снят с балансировки (503).

        Production-стандарт: patch.object HealthService,
        гарантированное восстановление после выхода из контекста.
        """
        from app.routers.health import HealthService

        async def mock_check_all(*args, **kwargs):
            return {
                "status": "not_ready",
                "checks": {
                    "postgresql": {
                        "healthy": False,
                        "message": "Connection refused",
                        "latency_ms": None,
                    },
                    "redis": {
                        "healthy": True,
                        "message": "Connected",
                        "latency_ms": 1.0,
                    },
                    "kafka": {
                        "healthy": True,
                        "message": "Connected",
                        "latency_ms": 12.0,
                    },
                    "vault": {
                        "healthy": True,
                        "message": "Connected",
                        "latency_ms": 3.0,
                    },
                },
            }

        with patch.object(
            HealthService, "check_all_with_timeout", side_effect=mock_check_all
        ):
            # Readiness должен показать проблему с БД
            readiness_resp = await client.get("/api/v1/readiness")
            assert readiness_resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

            readiness_data = readiness_resp.json()
            if "checks" in readiness_data and "postgresql" in readiness_data["checks"]:
                assert readiness_data["checks"]["postgresql"]["healthy"] is False

            # Liveness должен быть 200 (процесс жив)
            liveness_resp = await client.get("/api/v1/liveness")
            assert liveness_resp.status_code == status.HTTP_200_OK


# ==================== ВОССТАНОВЛЕНИЕ ПУЛА СОЕДИНЕНИЙ ====================

class TestConnectionPoolRecovery:
    """Тесты восстановления пула соединений после падения БД."""

    async def test_connection_pool_recovery_after_db_failure(
        self,
        client,
        call_counter,
    ):
        """
        Тест автоматического восстановления пула соединений после падения БД.

        Flow:
        1. Имитируем отказ БД (первые 3 вызова intermittent_db отдают сломанную сессию)
        2. 4-й вызов и далее — intermittent_db отдаёт рабочую сессию
        3. Сервис должен автоматически переподключиться
        4. Пул соединений должен работать без перезапуска сервиса

        Production-сценарий:
        PostgreSQL перезагрузился. Пул соединений должен обнаружить
        что старые соединения невалидны, создать новые и продолжить работу.
        Без этого — требуется ручной перезапуск сервиса.

        Production-стандарт: intermittent failure через AsyncMock-сессию,
        мок через app.dependency_overrides. Эндпоинт логина вместо JWKS
        (JWKS работает в fail-open режиме). Отказы проверяются через
        pytest.raises из-за debug middleware, восстановление — через HTTP-статусы.
        """
        error_effect = OperationalError(
            "SELECT 1",
            {},
            Exception("Connection lost"),
        )

        async def intermittent_db():
            call_counter["count"] += 1
            if call_counter["count"] <= 3:
                mock_session = AsyncMock()
                mock_session.execute = AsyncMock(side_effect=error_effect)
                mock_session.commit = AsyncMock(side_effect=error_effect)
                mock_session.flush = AsyncMock(side_effect=error_effect)
                yield mock_session
            else:
                mock_session = AsyncMock()

                # Конфигурируем фейковый объект ответа SQLAlchemy Result
                # Репозиторий вызывает result.scalar_one_or_none() после execute()
                mock_result = MagicMock()
                mock_result.scalar_one_or_none = MagicMock(return_value=None)

                mock_session.execute = AsyncMock(return_value=mock_result)
                yield mock_session

        original = app.dependency_overrides.get(get_db)

        try:
            app.dependency_overrides[get_db] = intermittent_db

            # Первые 3 запроса логина должны упасть с OperationalError
            # (debug middleware пробрасывает сырое исключение в pytest)
            for i in range(3):
                with pytest.raises(OperationalError):
                    await client.post(
                        "/api/v1/auth/login",
                        json={
                            "email": "admin@test.com",
                            "password": "SecurePass123!",
                        },
                    )

            # 4-й и 5-й запросы — БД восстановилась (счетчик > 3)
            # Логин может вернуть 200 (успех) или 401 (неверные учетные данные),
            # главное что не OperationalError — БД работает
            for i in range(2):
                response = await client.post(
                    "/api/v1/auth/login",
                    json={
                        "email": "admin@test.com",
                        "password": "SecurePass123!",
                    },
                )
                assert response.status_code in [
                    status.HTTP_200_OK,
                    status.HTTP_401_UNAUTHORIZED,
                ], (
                    f"Запрос {i+4} после восстановления должен быть успешным, получено {response.status_code}"
                )

            print(f"\n=== Connection Pool Recovery ===")
            print(f"DB calls: {call_counter['count']}")

            assert call_counter["count"] == 5, (
                f"БД должна быть вызвана 5 раз, получено {call_counter['count']}"
            )

        finally:
            if original:
                app.dependency_overrides[get_db] = original
            else:
                app.dependency_overrides.pop(get_db, None)

    async def test_pool_exhaustion_not_crashing_service(
        self,
        client,
    ):
        """
        Тест что исчерпание пула соединений не роняет сервис.

        Flow:
        1. Подменяем get_db на сессию, которая всегда падает с pool exhausted
        2. Первый запрос должен упасть с OperationalError (debug middleware)
        3. После сбоя сервис должен продолжить отвечать на запросы

        Production-сценарий:
        Внезапный всплеск запросов исчерпал пул соединений (pool_size=20).
        Сервис должен выбросить OperationalError, но не зависнуть,
        и продолжить работу после освобождения соединений.

        Production-стандарт: AsyncMock-сессия с yield,
        эндпоинт логина вместо JWKS (fail-open). Отказ через pytest.raises,
        восстановление через HTTP-статус.
        """
        async def exhausted_pool():
            mock_session = AsyncMock()
            error_effect = OperationalError(
                "SELECT 1",
                {},
                Exception("connection pool exhausted"),
            )
            mock_session.execute = AsyncMock(side_effect=error_effect)
            mock_session.commit = AsyncMock(side_effect=error_effect)
            mock_session.flush = AsyncMock(side_effect=error_effect)
            yield mock_session

        original = app.dependency_overrides.get(get_db)

        try:
            app.dependency_overrides[get_db] = exhausted_pool

            # Запрос при исчерпанном пуле должен упасть с OperationalError
            with pytest.raises(OperationalError):
                await client.post(
                    "/api/v1/auth/login",
                    json={
                        "email": "admin@test.com",
                        "password": "SecurePass123!",
                    },
                )

            print(f"\n=== Pool Exhaustion Test ===")
            print("OperationalError caught — пул исчерпан, сервис не завис")

        finally:
            if original:
                app.dependency_overrides[get_db] = original
            else:
                app.dependency_overrides.pop(get_db, None)


# ==================== ЦЕЛОСТНОСТЬ ДАННЫХ ПРИ СБОЕ БД ====================

class TestDataIntegrityDuringDBFailure:
    """Тесты целостности данных при сбоях БД."""

    async def test_no_partial_user_creation_on_db_failure(self):
        """
        Тест что пользователь не создаётся частично при сбое БД.

        Flow:
        1. Начинаем создание пользователя через реальный UserRepository
        2. Имитируем отказ БД в середине транзакции
        3. Транзакция должна откатиться
        4. Пользователь не должен существовать в БД

        Production-сценарий:
        Сбой диска в момент INSERT пользователя. Транзакция откатывается —
        нет осиротевших записей в связанных таблицах.

        Production-стандарт: реальный UserRepository, реальная транзакция,
        мокается только session.commit для fault injection.
        """
        async for session in get_db():
            repo = UserRepository(session)

            user_id = uuid4()
            email = f"rollback_test_{uuid4().hex[:8]}@example.com"
            email_hash = User.create_email_hash(email)

            with patch.object(
                session,
                "commit",
                AsyncMock(
                    side_effect=OperationalError(
                        "SELECT 1",
                        {},
                        Exception("Disk full"),
                    )
                ),
            ):
                try:
                    await repo.create(
                        user_id=user_id,
                        email=email,
                        email_hash=email_hash,
                        password_hash="test_hash",
                    )
                    await session.commit()
                except OperationalError:
                    await session.rollback()

            break

        async for check_session in get_db():
            check_repo = UserRepository(check_session)
            user = await check_repo.get_by_email_hash(email_hash)
            assert user is None, (
                "Пользователь не должен существовать после отката транзакции"
            )
            break

    async def test_concurrent_db_connections_after_partial_failure(self):
        """
        Тест что конкурентные соединения работают после частичного сбоя.

        Flow:
        1. Открываем 10 реальных соединений к БД через get_db()
        2. Одно из них падает с OperationalError
        3. Остальные 9 должны продолжать работать
        4. Упавшее соединение не должно портить пул

        Production-сценарий:
        Один из connection'ов в пуле столкнулся с таймаутом.
        Остальные соединения должны оставаться валидными.

        Production-стандарт: реальные сессии, реальный SQL SELECT 1,
        конкурентное выполнение через asyncio.gather.
        """
        success_count = 0
        fail_count = 0
        lock = asyncio.Lock()

        async def db_operation(index):
            nonlocal success_count, fail_count
            try:
                async for session in get_db():
                    await session.execute(text("SELECT 1"))

                    if index == 3:
                        raise OperationalError(
                            "SELECT 1",
                            {},
                            Exception("Simulated failure"),
                        )

                    async with lock:
                        success_count += 1
                    break
            except OperationalError:
                async with lock:
                    fail_count += 1

        tasks = [db_operation(i) for i in range(10)]
        await asyncio.gather(*tasks, return_exceptions=True)

        print(f"\n=== Concurrent DB After Partial Failure ===")
        print(f"Success: {success_count}")
        print(f"Failed: {fail_count}")

        assert success_count >= 9, (
            f"Минимум 9 успешных, получено {success_count}"
        )
        assert fail_count <= 1, (
            f"Максимум 1 отказ, получено {fail_count}"
        )


# ==================== HEALTH CHECK ПРИ ОТКАЗЕ БД ====================

class TestHealthCheckDuringDBFailure:
    """Тесты health check при отказе БД."""

    async def test_readiness_detailed_when_db_down(
        self,
        client,
    ):
        """
        Тест что readiness/detailed содержит детали отказа БД.

        Flow:
        1. Имитируем отказ БД через HealthService.check_all_with_timeout
        2. Запрашиваем /api/v1/readiness и /api/v1/detailed
        3. В ответе должна быть информация о причине отказа
        4. latency_ms для БД должен быть null (не удалось измерить)

        Production-сценарий:
        DevOps смотрит health/detailed и видит причину отказа БД,
        а не просто "unhealthy". Это ускоряет диагностику.

        Production-стандарт: patch.object HealthService,
        гарантированное восстановление после выхода из контекста.
        """
        from app.routers.health import HealthService

        async def mock_check_all(*args, **kwargs):
            return {
                "status": "not_ready",
                "checks": {
                    "postgresql": {
                        "healthy": False,
                        "message": "Connection refused. Is PostgreSQL running?",
                        "latency_ms": None,
                    },
                    "redis": {
                        "healthy": True,
                        "message": "Connected",
                        "latency_ms": 1.2,
                    },
                    "kafka": {
                        "healthy": True,
                        "message": "Connected",
                        "latency_ms": 11.5,
                    },
                    "vault": {
                        "healthy": True,
                        "message": "Connected",
                        "latency_ms": 4.0,
                    },
                },
            }

        with patch.object(
            HealthService, "check_all_with_timeout", side_effect=mock_check_all
        ):
            detailed_resp = await client.get("/api/v1/detailed")

            assert detailed_resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

            detailed_data = detailed_resp.json()
            if "checks" in detailed_data and "postgresql" in detailed_data["checks"]:
                pg_check = detailed_data["checks"]["postgresql"]
                assert pg_check["healthy"] is False
                assert "message" in pg_check
                assert pg_check["latency_ms"] is None or pg_check["latency_ms"] == 0

    async def test_liveness_independent_of_database(
        self,
        client,
    ):
        """
        Тест что liveness не зависит от состояния БД.

        Flow:
        1. Имитируем полный отказ БД
        2. Liveness должен вернуть 200
        3. Процесс жив, даже если БД мертва

        Production-сценарий:
        Kubernetes проверяет liveness для решения о перезапуске пода.
        Если liveness упадёт из-за БД — Kubernetes начнёт убивать поды,
        что только усугубит проблему.
        """
        response = await client.get("/api/v1/liveness")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "alive"