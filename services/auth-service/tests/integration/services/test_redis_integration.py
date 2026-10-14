"""
Интеграционные тесты для Redis клиента.

Тестирует:
- Инициализацию и закрытие соединения
- Базовые операции (get, set, delete, exists, expire, ttl)
- JSON операции (get_json, set_json через set)
- Инкремент счётчиков (incr, incr_by)
- Операции с множествами (sadd, srem, smembers, sismember)
- Rate limit atomic (Lua скрипт)
- OTP операции (save_otp, verify_otp)
- Refresh token операции
- Blacklist JWT
- Idempotency
- Scan и delete_by_pattern
- Pipeline
- Health check (ping, info)
- Graceful shutdown
- Edge cases и обработка ошибок
"""

import json
import asyncio
from unittest.mock import patch

import pytest
import redis.asyncio as redis

from app.core.redis_client import RedisClient, close_redis, init_redis, redis_client
from app.core.config import settings


# ==================== ФИКСТУРЫ ====================

@pytest.fixture(scope="function")
async def redis_client_real():
    """Реальный Redis клиент для интеграционных тестов."""
    client = RedisClient()
    await client.initialize(settings.REDIS_URL)
    yield client
    await client.close()


# ==================== ТЕСТЫ ====================

class TestRedisClientInitialization:
    """Тесты для инициализации Redis клиента."""

    @pytest.fixture(scope="function")
    async def client(self):
        """Реальный Redis клиент."""
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.close()

    async def test_initialize_success(self, client):
        """Тест успешной инициализации клиента."""
        assert client._initialized is True
        assert client._client is not None
        assert client.is_initialized is True

        result = await client.ping()
        assert result is True

    async def test_initialize_already_initialized(self, client):
        """Тест повторной инициализации не должна ломать клиент."""
        await client.initialize(settings.REDIS_URL)
        assert client._initialized is True
        assert client._client is not None

    async def test_close(self, client):
        """Тест закрытия соединения."""
        assert client._initialized is True
        await client.close()
        assert client._initialized is False
        assert client._client is None

    async def test_ping_success(self, client):
        """Тест успешного ping."""
        result = await client.ping()
        assert result is True

    async def test_ping_after_close(self, client):
        """Тест ping после закрытия."""
        await client.close()
        result = await client.ping()
        assert result is False


class TestBasicOperations:
    """Тесты для базовых Redis операций."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.delete_by_pattern("test:*")
        await client.close()

    async def test_set_and_get_string(self, client):
        key = "test:string"
        value = "test_value"

        result = await client.set(key, value)
        assert result is True

        retrieved = await client.get(key)
        assert retrieved == value

    async def test_set_with_ttl(self, client):
        key = "test:ttl"
        value = "test_value"

        await client.set(key, value, ttl=60)
        ttl = await client.ttl(key)
        assert ttl > 0 and ttl <= 60

    async def test_set_with_nx(self, client):
        key = "test:nx"
        value1 = "first_value"
        value2 = "second_value"

        result1 = await client.set(key, value1, nx=True)
        assert result1 is True

        result2 = await client.set(key, value2, nx=True)
        assert result2 is False

        retrieved = await client.get(key)
        assert retrieved == value1

    async def test_get_json(self, client):
        key = "test:json"
        dict_value = {"name": "test", "age": 30, "items": [1, 2, 3]}

        await client.set(key, dict_value)
        retrieved = await client.get_json(key)

        assert retrieved == dict_value

    async def test_delete(self, client):
        key = "test:delete"
        await client.set(key, "value")

        deleted = await client.delete(key)
        assert deleted == 1

        exists = await client.exists(key)
        assert exists is False

    async def test_delete_multiple_keys(self, client):
        key1, key2, key3 = "test:del1", "test:del2", "test:del3"
        await client.set(key1, "1")
        await client.set(key2, "2")
        await client.set(key3, "3")

        deleted = await client.delete(key1, key2, key3)
        assert deleted == 3

        assert await client.exists(key1) is False

    async def test_exists(self, client):
        key = "test:exists"
        assert await client.exists(key) is False

        await client.set(key, "value")
        assert await client.exists(key) is True

    async def test_expire(self, client):
        key = "test:expire"
        await client.set(key, "value")

        result = await client.expire(key, 60)
        assert result is True

        ttl = await client.ttl(key)
        assert ttl > 0 and ttl <= 60

    async def test_ttl(self, client):
        key = "test:ttl"
        await client.set(key, "value", ttl=60)

        ttl = await client.ttl(key)
        assert ttl > 0 and ttl <= 60

    async def test_ttl_no_expire(self, client):
        key = "test:no_ttl"
        await client.set(key, "value")

        ttl = await client.ttl(key)
        assert ttl == -1


class TestCounterOperations:
    """Тесты для операций со счётчиками."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.delete_by_pattern("test:counter:*")
        await client.close()

    async def test_incr_first_time_with_ttl(self, client):
        key = "test:counter:incr"

        result = await client.incr(key, ttl=60)
        assert result == 1

        ttl = await client.ttl(key)
        assert ttl > 0 and ttl <= 60

    async def test_incr_existing(self, client):
        key = "test:counter:incr_existing"

        result1 = await client.incr(key, ttl=60)
        assert result1 == 1

        result2 = await client.incr(key)
        assert result2 == 2

        value = await client.get(key)
        assert value == "2"

    async def test_incr_by(self, client):
        key = "test:counter:incrby"

        result = await client.incr_by(key, amount=5, ttl=60)
        assert result == 5

        value = await client.get(key)
        assert value == "5"

    async def test_get_counter(self, client):
        key = "test:counter:get"
        await client.incr_by(key, amount=10)

        value = await client.get_counter(key)
        assert value == 10

    async def test_get_counter_not_exists(self, client):
        key = "test:counter:not_exists"

        value = await client.get_counter(key)
        assert value == 0


class TestSetOperations:
    """Тесты для операций с множествами."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.delete_by_pattern("test:set:*")
        await client.close()

    async def test_sadd_and_smembers(self, client):
        key = "test:set:add"
        values = {"value1", "value2", "value3"}

        added = await client.sadd(key, *values)
        assert added == 3

        members = await client.smembers(key)
        assert members == values

    async def test_sadd_duplicate(self, client):
        key = "test:set:dup"
        await client.sadd(key, "value1", "value2")

        added = await client.sadd(key, "value1", "value3")
        assert added == 1

        members = await client.smembers(key)
        assert members == {"value1", "value2", "value3"}

    async def test_srem(self, client):
        key = "test:set:rem"
        await client.sadd(key, "value1", "value2", "value3")

        removed = await client.srem(key, "value1")
        assert removed == 1

        members = await client.smembers(key)
        assert members == {"value2", "value3"}

    async def test_sismember(self, client):
        key = "test:set:ismember"
        await client.sadd(key, "value1", "value2")

        assert await client.sismember(key, "value1") is True
        assert await client.sismember(key, "value3") is False


class TestRateLimitAtomic:
    """Тесты для атомарного rate limit (Lua скрипт)."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.delete_by_pattern("rate:*")
        await client.close()

    async def test_rate_limit_atomic_within_limit(self, client):
        key = "rate:test:allowed"
        limit = 5
        window = 60

        for _ in range(3):
            allowed, count = await client.rate_limit_atomic(key, limit, window)
            assert allowed is True
            assert count <= limit

        count = await client._client.zcard(f"rate:{key}")
        assert count == 3

    async def test_rate_limit_atomic_exceeded(self, client):
        key = "rate:test:exceeded"
        limit = 3
        window = 60

        results = []
        for i in range(5):
            allowed, count = await client.rate_limit_atomic(key, limit, window)
            results.append((allowed, count))

        assert results[0][0] is True
        assert results[1][0] is True
        assert results[2][0] is True
        assert results[3][0] is False
        assert results[4][0] is False
        assert results[3][1] == 3
        assert results[4][1] == 3

    async def test_rate_limit_atomic_reset_after_window(self, client):
        key = "rate:test:reset"
        limit = 2
        window = 3

        for _ in range(2):
            allowed, count = await client.rate_limit_atomic(key, limit, window)
            assert allowed is True

        allowed, count = await client.rate_limit_atomic(key, limit, window)
        assert allowed is False
        assert count == 2

        await asyncio.sleep(window + 1)

        allowed, count = await client.rate_limit_atomic(key, limit, window)
        assert allowed is True
        assert count == 1


class TestOTPOperations:
    """Тесты для OTP операций."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.delete_by_pattern("otp:*")
        await client.close()

    async def test_save_otp(self, client):
        key = "test:save"
        code = "123456"

        result = await client.save_otp(key, code, ttl=300)
        assert result is True

        stored = await client.get(f"otp:{key}")
        assert stored == code

    async def test_save_otp_with_ttl(self, client):
        key = "test:ttl"
        code = "654321"

        await client.save_otp(key, code, ttl=60)
        ttl = await client.ttl(f"otp:{key}")
        assert ttl > 0 and ttl <= 60

    async def test_verify_otp_success(self, client):
        key = "test:verify"
        code = "123456"

        await client.save_otp(key, code)
        assert await client.exists(f"otp:{key}") is True

        result = await client.verify_otp(key, code, delete_on_success=True)
        assert result is True
        assert await client.exists(f"otp:{key}") is False

    async def test_verify_otp_wrong_code(self, client):
        key = "test:wrong"
        code = "123456"
        wrong_code = "000000"

        await client.save_otp(key, code)

        result = await client.verify_otp(key, wrong_code, delete_on_success=True)
        assert result is False
        assert await client.exists(f"otp:{key}") is True

    async def test_verify_otp_expired(self, client):
        key = "test:expired"
        code = "123456"

        await client.save_otp(key, code, ttl=1)
        await asyncio.sleep(2)

        result = await client.verify_otp(key, code)
        assert result is False


class TestRefreshTokenOperations:
    """Тесты для Refresh Token операций."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.delete_by_pattern("refresh:*")
        await client.close()

    async def test_save_refresh_token(self, client):
        token_id = "token_123"
        user_id = "user_456"

        result = await client.save_refresh_token(token_id, user_id, ttl=86400)
        assert result is True

        stored = await client.get(f"refresh:{token_id}")
        assert stored == user_id

    async def test_get_refresh_token_user(self, client):
        token_id = "token_get"
        user_id = "user_get"

        await client.save_refresh_token(token_id, user_id)

        retrieved = await client.get_refresh_token_user(token_id)
        assert retrieved == user_id

    async def test_revoke_refresh_token(self, client):
        token_id = "token_revoke"
        user_id = "user_revoke"

        await client.save_refresh_token(token_id, user_id)
        assert await client.exists(f"refresh:{token_id}") is True

        result = await client.revoke_refresh_token(token_id)
        assert result is True
        assert await client.exists(f"refresh:{token_id}") is False


class TestBlacklistOperations:
    """Тесты для JWT blacklist операций."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.delete_by_pattern("blacklist:*")
        await client.close()

    async def test_blacklist_jwt(self, client):
        jti = "jti_test"

        result = await client.blacklist_jwt(jti, ttl=900)
        assert result is True
        assert await client.exists(f"blacklist:{jti}") is True

    async def test_is_jwt_blacklisted(self, client):
        jti = "jti_check"

        assert await client.is_jwt_blacklisted(jti) is False

        await client.blacklist_jwt(jti)
        assert await client.is_jwt_blacklisted(jti) is True


class TestIdempotencyOperations:
    """Тесты для idempotency операций."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.delete_by_pattern("idempotency:*")
        await client.close()

    async def test_save_idempotency_result(self, client):
        key = "test:save"
        result_data = {"status": "success", "id": 123}

        result = await client.save_idempotency_result(key, result_data, ttl=86400)
        assert result is True

        stored = await client.get_json(f"idempotency:{key}")
        assert stored == result_data

    async def test_get_idempotency_result(self, client):
        key = "test:get"
        result_data = {"status": "success", "id": 456}

        await client.save_idempotency_result(key, result_data)

        retrieved = await client.get_json(f"idempotency:{key}")
        assert retrieved == result_data


class TestScanOperations:
    """Тесты для scan операций."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.delete_by_pattern("scan:*")
        await client.close()

    async def test_scan_keys(self, client):
        for i in range(5):
            await client.set(f"scan:key{i}", f"value{i}")

        keys = await client.scan_keys("scan:*")
        assert len(keys) == 5
        assert all(key.startswith("scan:") for key in keys)

    async def test_delete_by_pattern(self, client):
        for i in range(3):
            await client.set(f"scan:delete{i}", f"value{i}")

        keys = await client.scan_keys("scan:delete*")
        assert len(keys) == 3

        deleted = await client.delete_by_pattern("scan:delete*")
        assert deleted == 3

        keys = await client.scan_keys("scan:delete*")
        assert len(keys) == 0


class TestPipelineAndInfo:
    """Тесты для pipeline и info."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.delete_by_pattern("pipe:*")
        await client.close()

    async def test_pipeline(self, client):
        pipe = client.pipeline()
        pipe.set("pipe:key1", "value1")
        pipe.set("pipe:key2", "value2")
        pipe.get("pipe:key1")
        pipe.get("pipe:key2")

        results = await pipe.execute()

        assert results[0] is True
        assert results[1] is True
        assert results[2] == "value1"
        assert results[3] == "value2"

    async def test_info_success(self, client):
        info = await client.info()
        assert info is not None
        assert "redis_version" in info
        assert "used_memory" in info

    async def test_info_specific_section(self, client):
        info = await client.info("memory")
        assert info is not None
        assert "used_memory" in info


class TestLifecycleFunctions:
    """Тесты для глобальных функций init_redis и close_redis."""

    async def test_init_redis_global(self):
        await init_redis(settings.REDIS_URL)
        assert redis_client._initialized is True
        assert redis_client._client is not None

        result = await redis_client.ping()
        assert result is True

        await close_redis()
        assert redis_client._initialized is False

    @patch("app.core.redis_client.settings")
    async def test_init_redis_without_url(self, mock_settings):
        """Тест запуска без указания URL."""
        mock_settings.REDIS_URL = None

        from app.core.redis_client import redis_client, init_redis

        # Lead-сброс: обманываем состояние клиента, будто он еще не запускался
        old_initialized = redis_client._initialized
        redis_client._initialized = False

        try:
            with pytest.raises(RuntimeError, match="Redis URL not provided"):
                await init_redis()
        finally:
            # Возвращаем исходное состояние, чтобы не сломать соседние тесты
            redis_client._initialized = old_initialized


class TestSingleton:
    """Тесты для синглтона."""

    def test_redis_client_singleton(self):
        from app.core.redis_client import redis_client as client1
        from app.core.redis_client import redis_client as client2

        assert client1 is client2
        assert isinstance(client1, RedisClient)


class TestHealthCheck:
    """Тесты для health check."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.close()

    async def test_ping_real(self, client):
        result = await client.ping()
        assert result is True

    async def test_info_real(self, client):
        info = await client.info()
        assert info is not None
        assert info.get("redis_version") is not None


class TestEdgeCases:
    """Тесты для граничных случаев."""

    @pytest.fixture(scope="function")
    async def client(self):
        client = RedisClient()
        await client.initialize(settings.REDIS_URL)
        yield client
        await client.delete_by_pattern("edge:*")
        await client.close()

    async def test_set_get_empty_string(self, client):
        key = "edge:empty"
        value = ""

        await client.set(key, value)
        retrieved = await client.get(key)
        assert retrieved == value

    async def test_set_get_nonexistent_key(self, client):
        retrieved = await client.get("edge:nonexistent")
        assert retrieved is None

    async def test_delete_nonexistent_key(self, client):
        deleted = await client.delete("edge:nonexistent")
        assert deleted == 0

    async def test_set_get_large_value(self, client):
        key = "edge:large"
        value = "x" * 1024

        await client.set(key, value)
        retrieved = await client.get(key)
        assert retrieved == value

    async def test_json_with_nested_data(self, client):
        key = "edge:json_nested"
        value = {"user": {"name": "test", "profile": {"age": 30, "city": "Moscow"}}}

        await client.set(key, value)
        retrieved = await client.get_json(key)
        assert retrieved == value