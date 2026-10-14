"""
Unit tests for RedisService.

Tests cover:
- get, get_json, set, setex, delete, exists, expire, ttl
- incr, get_rate_limit
- sadd, srem, smembers, sismember
- flushdb, scan_keys, delete_by_pattern
- Edge cases and error handling
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.services.redis_service import RedisService


# ==================== FIXTURES ====================

@pytest.fixture
def mock_redis():
    """Mock redis_client for all Redis operations."""
    with patch("app.services.redis_service.redis_client") as mock:
        yield mock


# ==================== GET OPERATIONS ====================

class TestRedisServiceGet:
    """Tests for get and get_json operations."""

    @pytest.mark.asyncio
    async def test_get_success(self, mock_redis):
        """Test successful get operation."""
        mock_redis.get = AsyncMock(return_value="test_value")

        result = await RedisService.get(key="test:key")

        assert result == "test_value"
        mock_redis.get.assert_called_once_with("test:key")

    @pytest.mark.asyncio
    async def test_get_not_found(self, mock_redis):
        """Test get when key does not exist."""
        mock_redis.get = AsyncMock(return_value=None)

        result = await RedisService.get(key="nonexistent:key")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_empty_string(self, mock_redis):
        """Test get returns empty string."""
        mock_redis.get = AsyncMock(return_value="")

        result = await RedisService.get(key="empty:key")

        assert result == ""

    @pytest.mark.asyncio
    async def test_get_redis_failure(self, mock_redis):
        """Test get returns None on Redis failure."""
        mock_redis.get = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.get(key="test:key")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_json_success(self, mock_redis):
        """Test successful get_json operation."""
        expected = {"user_id": "user123", "role": "admin"}
        mock_redis.get_json = AsyncMock(return_value=expected)

        result = await RedisService.get_json(key="user:user123")

        assert result == expected
        mock_redis.get_json.assert_called_once_with("user:user123")

    @pytest.mark.asyncio
    async def test_get_json_not_found(self, mock_redis):
        """Test get_json when key does not exist."""
        mock_redis.get_json = AsyncMock(return_value=None)

        result = await RedisService.get_json(key="nonexistent:key")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_json_redis_failure(self, mock_redis):
        """Test get_json returns None on Redis failure."""
        mock_redis.get_json = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.get_json(key="test:key")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_json_complex_structure(self, mock_redis):
        """Test get_json with complex nested structure."""
        expected = {
            "users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}],
            "metadata": {"count": 2, "active": True},
        }
        mock_redis.get_json = AsyncMock(return_value=expected)

        result = await RedisService.get_json(key="complex:key")

        assert result == expected
        assert result["users"][1]["name"] == "Bob"


# ==================== SET OPERATIONS ====================

class TestRedisServiceSet:
    """Tests for set and setex operations."""

    @pytest.mark.asyncio
    async def test_set_success(self, mock_redis):
        """Test successful set operation."""
        mock_redis.set = AsyncMock(return_value=True)

        result = await RedisService.set(key="test:key", value="test_value")

        assert result is True
        mock_redis.set.assert_called_once_with(
            "test:key", "test_value", ttl=None, nx=False, xx=False
        )

    @pytest.mark.asyncio
    async def test_set_with_ttl(self, mock_redis):
        """Test set with TTL."""
        mock_redis.set = AsyncMock(return_value=True)

        result = await RedisService.set(key="test:key", value="value", ttl=3600)

        assert result is True
        mock_redis.set.assert_called_once_with(
            "test:key", "value", ttl=3600, nx=False, xx=False
        )

    @pytest.mark.asyncio
    async def test_set_nx_only_if_not_exists(self, mock_redis):
        """Test set with nx=True (only if not exists)."""
        mock_redis.set = AsyncMock(return_value=True)

        result = await RedisService.set(key="test:key", value="value", nx=True)

        assert result is True
        mock_redis.set.assert_called_once_with(
            "test:key", "value", ttl=None, nx=True, xx=False
        )

    @pytest.mark.asyncio
    async def test_set_xx_only_if_exists(self, mock_redis):
        """Test set with xx=True (only if exists)."""
        mock_redis.set = AsyncMock(return_value=True)

        result = await RedisService.set(key="test:key", value="value", xx=True)

        assert result is True
        mock_redis.set.assert_called_once_with(
            "test:key", "value", ttl=None, nx=False, xx=True
        )

    @pytest.mark.asyncio
    async def test_set_returns_false(self, mock_redis):
        """Test set returns False when Redis returns False."""
        mock_redis.set = AsyncMock(return_value=False)

        result = await RedisService.set(key="test:key", value="value")

        assert result is False

    @pytest.mark.asyncio
    async def test_set_redis_failure(self, mock_redis):
        """Test set returns False on Redis failure."""
        mock_redis.set = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.set(key="test:key", value="value")

        assert result is False

    @pytest.mark.asyncio
    async def test_set_complex_value(self, mock_redis):
        """Test set with complex value (dict)."""
        mock_redis.set = AsyncMock(return_value=True)

        complex_value = {"users": [1, 2, 3], "active": True}
        result = await RedisService.set(key="test:key", value=complex_value, ttl=600)

        assert result is True
        mock_redis.set.assert_called_once_with(
            "test:key", complex_value, ttl=600, nx=False, xx=False
        )

    @pytest.mark.asyncio
    async def test_setex_success(self, mock_redis):
        """Test successful setex operation."""
        mock_redis.setex = AsyncMock(return_value=True)

        result = await RedisService.setex(key="test:key", ttl=300, value="value")

        assert result is True
        mock_redis.setex.assert_called_once_with("test:key", 300, "value")

    @pytest.mark.asyncio
    async def test_setex_redis_failure(self, mock_redis):
        """Test setex returns False on Redis failure."""
        mock_redis.setex = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.setex(key="test:key", ttl=300, value="value")

        assert result is False


# ==================== DELETE OPERATIONS ====================

class TestRedisServiceDelete:
    """Tests for delete operation."""

    @pytest.mark.asyncio
    async def test_delete_single_key(self, mock_redis):
        """Test deleting a single key."""
        mock_redis.delete = AsyncMock(return_value=1)

        result = await RedisService.delete("test:key")

        assert result == 1
        mock_redis.delete.assert_called_once_with("test:key")

    @pytest.mark.asyncio
    async def test_delete_multiple_keys(self, mock_redis):
        """Test deleting multiple keys."""
        mock_redis.delete = AsyncMock(return_value=3)

        result = await RedisService.delete("key1", "key2", "key3")

        assert result == 3
        mock_redis.delete.assert_called_once_with("key1", "key2", "key3")

    @pytest.mark.asyncio
    async def test_delete_no_keys(self, mock_redis):
        """Test delete with no keys returns 0."""
        result = await RedisService.delete()

        assert result == 0
        mock_redis.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_key_not_found(self, mock_redis):
        """Test deleting non-existent key."""
        mock_redis.delete = AsyncMock(return_value=0)

        result = await RedisService.delete("nonexistent:key")

        assert result == 0

    @pytest.mark.asyncio
    async def test_delete_redis_failure(self, mock_redis):
        """Test delete returns 0 on Redis failure."""
        mock_redis.delete = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.delete("test:key")

        assert result == 0


# ==================== EXISTS OPERATION ====================

class TestRedisServiceExists:
    """Tests for exists operation."""

    @pytest.mark.asyncio
    async def test_exists_true(self, mock_redis):
        """Test exists returns True when key exists."""
        mock_redis.exists = AsyncMock(return_value=True)

        result = await RedisService.exists(key="test:key")

        assert result is True
        mock_redis.exists.assert_called_once_with("test:key")

    @pytest.mark.asyncio
    async def test_exists_false(self, mock_redis):
        """Test exists returns False when key does not exist."""
        mock_redis.exists = AsyncMock(return_value=False)

        result = await RedisService.exists(key="nonexistent:key")

        assert result is False

    @pytest.mark.asyncio
    async def test_exists_redis_failure(self, mock_redis):
        """Test exists returns False on Redis failure."""
        mock_redis.exists = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.exists(key="test:key")

        assert result is False


# ==================== EXPIRE OPERATION ====================

class TestRedisServiceExpire:
    """Tests for expire operation."""

    @pytest.mark.asyncio
    async def test_expire_success(self, mock_redis):
        """Test successful expire operation."""
        mock_redis.expire = AsyncMock(return_value=True)

        result = await RedisService.expire(key="test:key", ttl=3600)

        assert result is True
        mock_redis.expire.assert_called_once_with("test:key", 3600)

    @pytest.mark.asyncio
    async def test_expire_key_not_found(self, mock_redis):
        """Test expire on non-existent key."""
        mock_redis.expire = AsyncMock(return_value=False)

        result = await RedisService.expire(key="nonexistent:key", ttl=60)

        assert result is False

    @pytest.mark.asyncio
    async def test_expire_redis_failure(self, mock_redis):
        """Test expire returns False on Redis failure."""
        mock_redis.expire = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.expire(key="test:key", ttl=60)

        assert result is False


# ==================== TTL OPERATION ====================

class TestRedisServiceTTL:
    """Tests for ttl operation."""

    @pytest.mark.asyncio
    async def test_ttl_with_ttl_set(self, mock_redis):
        """Test ttl returns remaining seconds."""
        mock_redis.ttl = AsyncMock(return_value=300)

        result = await RedisService.ttl(key="test:key")

        assert result == 300
        mock_redis.ttl.assert_called_once_with("test:key")

    @pytest.mark.asyncio
    async def test_ttl_no_expiry(self, mock_redis):
        """Test ttl returns -1 when key has no expiry."""
        mock_redis.ttl = AsyncMock(return_value=-1)

        result = await RedisService.ttl(key="persistent:key")

        assert result == -1

    @pytest.mark.asyncio
    async def test_ttl_key_not_found(self, mock_redis):
        """Test ttl returns -2 when key does not exist."""
        mock_redis.ttl = AsyncMock(return_value=-2)

        result = await RedisService.ttl(key="nonexistent:key")

        assert result == -2

    @pytest.mark.asyncio
    async def test_ttl_redis_failure(self, mock_redis):
        """Test ttl returns -2 on Redis failure."""
        mock_redis.ttl = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.ttl(key="test:key")

        assert result == -2


# ==================== INCR OPERATION ====================

class TestRedisServiceIncr:
    """Tests for incr operation."""

    @pytest.mark.asyncio
    async def test_incr_first_call(self, mock_redis):
        """Test incr on new key returns 1."""
        mock_redis.incr = AsyncMock(return_value=1)

        result = await RedisService.incr(key="counter:key")

        assert result == 1
        mock_redis.incr.assert_called_once_with("counter:key", ttl=None)

    @pytest.mark.asyncio
    async def test_incr_with_ttl(self, mock_redis):
        """Test incr with TTL set on first call."""
        mock_redis.incr = AsyncMock(return_value=1)

        result = await RedisService.incr(key="counter:key", ttl=60)

        assert result == 1
        mock_redis.incr.assert_called_once_with("counter:key", ttl=60)

    @pytest.mark.asyncio
    async def test_incr_multiple_calls(self, mock_redis):
        """Test incr returns incremented value."""
        mock_redis.incr = AsyncMock(return_value=5)

        result = await RedisService.incr(key="counter:key")

        assert result == 5

    @pytest.mark.asyncio
    async def test_incr_large_value(self, mock_redis):
        """Test incr with large counter value."""
        mock_redis.incr = AsyncMock(return_value=999999)

        result = await RedisService.incr(key="counter:key")

        assert result == 999999

    @pytest.mark.asyncio
    async def test_incr_redis_failure(self, mock_redis):
        """Test incr returns 0 on Redis failure."""
        mock_redis.incr = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.incr(key="counter:key")

        assert result == 0


# ==================== GET RATE LIMIT OPERATION ====================

class TestRedisServiceGetRateLimit:
    """Tests for get_rate_limit operation."""

    @pytest.mark.asyncio
    async def test_get_rate_limit_success(self, mock_redis):
        """Test successful get_rate_limit."""
        mock_redis.get_counter = AsyncMock(return_value=4)

        result = await RedisService.get_rate_limit(key="rate:key")

        assert result == 4
        mock_redis.get_counter.assert_called_once_with("rate:key")

    @pytest.mark.asyncio
    async def test_get_rate_limit_not_exists(self, mock_redis):
        """Test get_rate_limit when key does not exist."""
        mock_redis.get_counter = AsyncMock(return_value=0)

        result = await RedisService.get_rate_limit(key="rate:new_key")

        assert result == 0

    @pytest.mark.asyncio
    async def test_get_rate_limit_redis_failure(self, mock_redis):
        """Test get_rate_limit returns 0 on Redis failure."""
        mock_redis.get_counter = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.get_rate_limit(key="rate:key")

        assert result == 0


# ==================== SET OPERATIONS (SADD, SREM, SMEMBERS, SISMEMBER) ====================

class TestRedisServiceSetOperations:
    """Tests for Redis set operations."""

    @pytest.mark.asyncio
    async def test_sadd_single_value(self, mock_redis):
        """Test adding single value to set."""
        mock_redis.sadd = AsyncMock(return_value=1)

        result = await RedisService.sadd("set:key", "value1")

        assert result == 1
        mock_redis.sadd.assert_called_once_with("set:key", "value1")

    @pytest.mark.asyncio
    async def test_sadd_multiple_values(self, mock_redis):
        """Test adding multiple values to set."""
        mock_redis.sadd = AsyncMock(return_value=3)

        result = await RedisService.sadd("set:key", "v1", "v2", "v3")

        assert result == 3
        mock_redis.sadd.assert_called_once_with("set:key", "v1", "v2", "v3")

    @pytest.mark.asyncio
    async def test_sadd_duplicate_values(self, mock_redis):
        """Test adding duplicate values (only new ones counted)."""
        mock_redis.sadd = AsyncMock(return_value=0)

        result = await RedisService.sadd("set:key", "existing_value")

        assert result == 0

    @pytest.mark.asyncio
    async def test_sadd_redis_failure(self, mock_redis):
        """Test sadd returns 0 on Redis failure."""
        mock_redis.sadd = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.sadd("set:key", "value")

        assert result == 0

    @pytest.mark.asyncio
    async def test_srem_single_value(self, mock_redis):
        """Test removing single value from set."""
        mock_redis.srem = AsyncMock(return_value=1)

        result = await RedisService.srem("set:key", "value1")

        assert result == 1
        mock_redis.srem.assert_called_once_with("set:key", "value1")

    @pytest.mark.asyncio
    async def test_srem_multiple_values(self, mock_redis):
        """Test removing multiple values from set."""
        mock_redis.srem = AsyncMock(return_value=2)

        result = await RedisService.srem("set:key", "v1", "v2")

        assert result == 2
        mock_redis.srem.assert_called_once_with("set:key", "v1", "v2")

    @pytest.mark.asyncio
    async def test_srem_not_member(self, mock_redis):
        """Test removing value not in set."""
        mock_redis.srem = AsyncMock(return_value=0)

        result = await RedisService.srem("set:key", "missing")

        assert result == 0

    @pytest.mark.asyncio
    async def test_srem_redis_failure(self, mock_redis):
        """Test srem returns 0 on Redis failure."""
        mock_redis.srem = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.srem("set:key", "value")

        assert result == 0

    @pytest.mark.asyncio
    async def test_smembers_with_values(self, mock_redis):
        """Test getting all set members."""
        expected = {"v1", "v2", "v3"}
        mock_redis.smembers = AsyncMock(return_value=expected)

        result = await RedisService.smembers(key="set:key")

        assert result == expected
        mock_redis.smembers.assert_called_once_with("set:key")

    @pytest.mark.asyncio
    async def test_smembers_empty_set(self, mock_redis):
        """Test getting members of empty set."""
        mock_redis.smembers = AsyncMock(return_value=set())

        result = await RedisService.smembers(key="empty:set")

        assert result == set()

    @pytest.mark.asyncio
    async def test_smembers_redis_failure(self, mock_redis):
        """Test smembers returns empty set on Redis failure."""
        mock_redis.smembers = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.smembers(key="set:key")

        assert result == set()

    @pytest.mark.asyncio
    async def test_sismember_true(self, mock_redis):
        """Test sismember returns True when value in set."""
        mock_redis.sismember = AsyncMock(return_value=True)

        result = await RedisService.sismember(key="set:key", value="v1")

        assert result is True
        mock_redis.sismember.assert_called_once_with("set:key", "v1")

    @pytest.mark.asyncio
    async def test_sismember_false(self, mock_redis):
        """Test sismember returns False when value not in set."""
        mock_redis.sismember = AsyncMock(return_value=False)

        result = await RedisService.sismember(key="set:key", value="missing")

        assert result is False

    @pytest.mark.asyncio
    async def test_sismember_redis_failure(self, mock_redis):
        """Test sismember returns False on Redis failure."""
        mock_redis.sismember = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.sismember(key="set:key", value="v1")

        assert result is False


# ==================== FLUSHDB OPERATION ====================

class TestRedisServiceFlushDB:
    """Tests for flushdb operation."""

    @pytest.mark.asyncio
    async def test_flushdb_success(self, mock_redis):
        """Test successful flushdb."""
        mock_redis.flushdb = AsyncMock(return_value=True)

        result = await RedisService.flushdb()

        assert result is True
        mock_redis.flushdb.assert_called_once()

    @pytest.mark.asyncio
    async def test_flushdb_failure(self, mock_redis):
        """Test flushdb returns False on failure."""
        mock_redis.flushdb = AsyncMock(return_value=False)

        result = await RedisService.flushdb()

        assert result is False

    @pytest.mark.asyncio
    async def test_flushdb_redis_failure(self, mock_redis):
        """Test flushdb returns False on Redis exception."""
        mock_redis.flushdb = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.flushdb()

        assert result is False


# ==================== SCAN KEYS OPERATION ====================

class TestRedisServiceScanKeys:
    """Tests for scan_keys operation."""

    @pytest.mark.asyncio
    async def test_scan_keys_success(self, mock_redis):
        """Test successful scan_keys."""
        expected = ["key:1", "key:2", "key:3"]
        mock_redis.scan_keys = AsyncMock(return_value=expected)

        result = await RedisService.scan_keys(pattern="key:*")

        assert result == expected
        mock_redis.scan_keys.assert_called_once_with("key:*", count=100)

    @pytest.mark.asyncio
    async def test_scan_keys_with_custom_count(self, mock_redis):
        """Test scan_keys with custom count."""
        mock_redis.scan_keys = AsyncMock(return_value=["k1", "k2"])

        result = await RedisService.scan_keys(pattern="test:*", count=50)

        assert result == ["k1", "k2"]
        mock_redis.scan_keys.assert_called_once_with("test:*", count=50)

    @pytest.mark.asyncio
    async def test_scan_keys_no_matches(self, mock_redis):
        """Test scan_keys with no matching keys."""
        mock_redis.scan_keys = AsyncMock(return_value=[])

        result = await RedisService.scan_keys(pattern="nonexistent:*")

        assert result == []

    @pytest.mark.asyncio
    async def test_scan_keys_redis_failure(self, mock_redis):
        """Test scan_keys returns empty list on Redis failure."""
        mock_redis.scan_keys = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.scan_keys(pattern="test:*")

        assert result == []


# ==================== DELETE BY PATTERN OPERATION ====================

class TestRedisServiceDeleteByPattern:
    """Tests for delete_by_pattern operation."""

    @pytest.mark.asyncio
    async def test_delete_by_pattern_success(self, mock_redis):
        """Test successful delete_by_pattern."""
        mock_redis.delete_by_pattern = AsyncMock(return_value=5)

        result = await RedisService.delete_by_pattern(pattern="temp:*")

        assert result == 5
        mock_redis.delete_by_pattern.assert_called_once_with("temp:*")

    @pytest.mark.asyncio
    async def test_delete_by_pattern_no_matches(self, mock_redis):
        """Test delete_by_pattern with no matching keys."""
        mock_redis.delete_by_pattern = AsyncMock(return_value=0)

        result = await RedisService.delete_by_pattern(pattern="nonexistent:*")

        assert result == 0

    @pytest.mark.asyncio
    async def test_delete_by_pattern_redis_failure(self, mock_redis):
        """Test delete_by_pattern returns 0 on Redis failure."""
        mock_redis.delete_by_pattern = AsyncMock(side_effect=Exception("Connection failed"))

        result = await RedisService.delete_by_pattern(pattern="test:*")

        assert result == 0


# ==================== EDGE CASES ====================

class TestRedisServiceEdgeCases:
    """Tests for edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_set_with_zero_ttl(self, mock_redis):
        """Test set with TTL=0."""
        mock_redis.set = AsyncMock(return_value=True)

        result = await RedisService.set(key="test:key", value="value", ttl=0)

        assert result is True
        mock_redis.set.assert_called_once_with(
            "test:key", "value", ttl=0, nx=False, xx=False
        )

    @pytest.mark.asyncio
    async def test_set_with_negative_ttl(self, mock_redis):
        """Test set with negative TTL."""
        mock_redis.set = AsyncMock(return_value=True)

        result = await RedisService.set(key="test:key", value="value", ttl=-1)

        assert result is True

    @pytest.mark.asyncio
    async def test_setex_with_zero_ttl(self, mock_redis):
        """Test setex with TTL=0."""
        mock_redis.setex = AsyncMock(return_value=True)

        result = await RedisService.setex(key="test:key", ttl=0, value="value")

        assert result is True
        mock_redis.setex.assert_called_once_with("test:key", 0, "value")

    @pytest.mark.asyncio
    async def test_get_with_special_characters_in_key(self, mock_redis):
        """Test get with special characters in key."""
        mock_redis.get = AsyncMock(return_value="value")

        result = await RedisService.get(key="user:email:user@example.com")

        assert result == "value"
        mock_redis.get.assert_called_once_with("user:email:user@example.com")

    @pytest.mark.asyncio
    async def test_set_with_none_value(self, mock_redis):
        """Test set with None value."""
        mock_redis.set = AsyncMock(return_value=True)

        result = await RedisService.set(key="test:key", value=None)

        assert result is True
        mock_redis.set.assert_called_once_with(
            "test:key", None, ttl=None, nx=False, xx=False
        )

    @pytest.mark.asyncio
    async def test_delete_with_empty_keys(self, mock_redis):
        """Test delete with empty string key."""
        result = await RedisService.delete()

        assert result == 0
        mock_redis.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_ttl_very_large(self, mock_redis):
        """Test ttl with very large value."""
        mock_redis.ttl = AsyncMock(return_value=86400 * 365)  # 1 year

        result = await RedisService.ttl(key="long:ttl:key")

        assert result == 86400 * 365