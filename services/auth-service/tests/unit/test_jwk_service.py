"""
Unit tests for JWKService.

Tests cover:
- generate_key_pair (RSA, EC, unsupported algorithm)
- _generate_rsa_key_pair, _generate_ec_key_pair
- _generate_kid format
- _get_ec_curve (ES256, ES384, ES512, invalid)
- save_key (success, duplicate)
- get_key, get_all_keys, get_active_keys, get_keys_for_verification
- activate_key, deactivate_key (success, not found, already active/inactive, last key)
- expire_key
- rotate_keys (success, no old keys, grace period)
- get_jwks (cache hit, cache miss, force refresh)
- get_key_metrics, get_metrics_data
- cleanup_expired_keys
- _get_cached_jwks, _cache_jwks, _invalidate_cache
- health_check, get_primary_key, get_key_by_algorithm
- Edge cases and error handling
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.exceptions import BadRequestException, ConflictException, NotFoundException
from app.models.jwk_key import JWKKey
from app.services.jwk_service import JWKService


class TestJWKServiceGenerateKeyPair:
    """Tests for generate_key_pair method."""

    @pytest.fixture
    def mock_repo(self):
        return AsyncMock()

    @pytest.fixture
    def service(self, mock_repo):
        return JWKService(mock_repo)

    @patch("cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key")
    async def test_generate_rsa_key_pair(self, mock_generate, service):
        """Test RSA key pair generation."""
        mock_private_key = MagicMock()
        mock_public_key = MagicMock()
        mock_private_key.public_key.return_value = mock_public_key
        mock_generate.return_value = mock_private_key

        mock_private_key.private_bytes.return_value = b"-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----"
        mock_public_key.public_bytes.return_value = b"-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----"

        key, private_pem, public_pem = await service.generate_key_pair(algorithm="RS256", key_size=2048)

        assert key.algorithm == "RS256"
        assert key.key_type == "RSA"
        assert key.is_active is False
        assert key.is_verification_enabled is True
        assert key.expires_at is not None
        assert "BEGIN PRIVATE KEY" in private_pem
        assert "BEGIN PUBLIC KEY" in public_pem

    @patch("cryptography.hazmat.primitives.asymmetric.ec.generate_private_key")
    async def test_generate_ec_key_pair(self, mock_generate, service):
        """Test EC key pair generation."""
        mock_private_key = MagicMock()
        mock_public_key = MagicMock()
        mock_private_key.public_key.return_value = mock_public_key
        mock_generate.return_value = mock_private_key

        mock_private_key.private_bytes.return_value = b"-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----"
        mock_public_key.public_bytes.return_value = b"-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----"

        key, private_pem, public_pem = await service.generate_key_pair(algorithm="ES256")

        assert key.algorithm == "ES256"
        assert key.key_type == "EC"
        assert "BEGIN PRIVATE KEY" in private_pem

    async def test_generate_key_pair_unsupported_algorithm(self, service):
        """Test unsupported algorithm raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            await service.generate_key_pair(algorithm="HS256")


class TestJWKServiceGetECCurve:
    """Tests for _get_ec_curve method."""

    @pytest.fixture
    def service(self):
        return JWKService(AsyncMock())

    def test_get_ec_curve_es256(self, service):
        from cryptography.hazmat.primitives.asymmetric import ec
        curve = service._get_ec_curve("ES256")
        assert isinstance(curve, ec.SECP256R1)

    def test_get_ec_curve_es384(self, service):
        curve = service._get_ec_curve("ES384")
        assert curve is not None

    def test_get_ec_curve_es512(self, service):
        curve = service._get_ec_curve("ES512")
        assert curve is not None

    def test_get_ec_curve_invalid(self, service):
        with pytest.raises(ValueError, match="Unsupported EC algorithm"):
            service._get_ec_curve("INVALID")


class TestJWKServiceGenerateKid:
    """Tests for _generate_kid method."""

    @pytest.fixture
    def service(self):
        return JWKService(AsyncMock())

    def test_generate_kid_format(self, service):
        kid = service._generate_kid()
        assert kid.startswith("key_")
        assert len(kid) > 10

    def test_generate_kid_uniqueness(self, service):
        kids = {service._generate_kid() for _ in range(10)}
        assert len(kids) == 10


class TestJWKServiceSaveKey:
    """Tests for save_key method."""

    @pytest.fixture
    def mock_repo(self):
        repo = AsyncMock()
        repo.create = AsyncMock()
        repo.get_by_kid = AsyncMock(return_value=None)
        return repo

    @pytest.fixture
    def service(self, mock_repo):
        return JWKService(mock_repo)

    async def test_save_key_success(self, service, mock_repo):
        """Test successful key saving."""
        key = MagicMock(spec=JWKKey)
        key.kid = "key_123"

        result = await service.save_key(key)

        mock_repo.create.assert_called_once_with(key)
        assert result == mock_repo.create.return_value

    async def test_save_key_duplicate(self, service, mock_repo):
        """Test saving duplicate key raises ConflictException."""
        mock_repo.get_by_kid.return_value = MagicMock(spec=JWKKey)

        key = MagicMock(spec=JWKKey)
        key.kid = "existing_key"

        with pytest.raises(ConflictException):
            await service.save_key(key)


class TestJWKServiceGetKeys:
    """Tests for get_key, get_all_keys, get_active_keys, get_keys_for_verification."""

    @pytest.fixture
    def mock_repo(self):
        repo = AsyncMock()
        repo.get_by_kid = AsyncMock()
        repo.get_all_keys = AsyncMock()
        repo.get_active_keys = AsyncMock()
        repo.get_keys_for_verification = AsyncMock()
        return repo

    @pytest.fixture
    def service(self, mock_repo):
        return JWKService(mock_repo)

    async def test_get_key_found(self, service, mock_repo):
        mock_key = MagicMock(spec=JWKKey)
        mock_repo.get_by_kid.return_value = mock_key
        result = await service.get_key("key_123")
        assert result == mock_key

    async def test_get_key_not_found(self, service, mock_repo):
        mock_repo.get_by_kid.return_value = None
        result = await service.get_key("nonexistent")
        assert result is None

    async def test_get_all_keys(self, service, mock_repo):
        mock_keys = [MagicMock(spec=JWKKey)]
        mock_repo.get_all_keys.return_value = mock_keys
        result = await service.get_all_keys()
        assert result == mock_keys

    async def test_get_active_keys(self, service, mock_repo):
        mock_keys = [MagicMock(spec=JWKKey)]
        mock_repo.get_active_keys.return_value = mock_keys
        result = await service.get_active_keys()
        assert result == mock_keys

    async def test_get_keys_for_verification(self, service, mock_repo):
        mock_keys = [MagicMock(spec=JWKKey)]
        mock_repo.get_keys_for_verification.return_value = mock_keys
        result = await service.get_keys_for_verification()
        assert result == mock_keys


class TestJWKServiceActivateDeactivate:
    """Tests for activate_key and deactivate_key methods."""

    @pytest.fixture
    def mock_repo(self):
        repo = AsyncMock()
        repo.get_by_kid = AsyncMock()
        repo.activate_key = AsyncMock(return_value=True)
        repo.deactivate_key = AsyncMock(return_value=True)
        repo.get_active_keys = AsyncMock()
        return repo

    @pytest.fixture
    def service(self, mock_repo):
        return JWKService(mock_repo)

    async def test_activate_key_success(self, service, mock_repo):
        mock_key = MagicMock(spec=JWKKey)
        mock_key.is_active = False
        mock_repo.get_by_kid.return_value = mock_key

        result = await service.activate_key("key_123", activated_by="admin")

        assert result is True
        mock_repo.activate_key.assert_called_once_with("key_123", "admin")

    async def test_activate_key_not_found(self, service, mock_repo):
        mock_repo.get_by_kid.return_value = None

        with pytest.raises(NotFoundException):
            await service.activate_key("nonexistent")

    async def test_activate_key_already_active(self, service, mock_repo):
        mock_key = MagicMock(spec=JWKKey)
        mock_key.is_active = True
        mock_repo.get_by_kid.return_value = mock_key

        result = await service.activate_key("key_123")

        assert result is True
        mock_repo.activate_key.assert_not_called()

    async def test_deactivate_key_success(self, service, mock_repo):
        mock_key = MagicMock(spec=JWKKey)
        mock_key.is_active = True
        mock_repo.get_by_kid.return_value = mock_key
        mock_repo.get_active_keys.return_value = [mock_key, MagicMock()]

        result = await service.deactivate_key("key_123")

        assert result is True
        mock_repo.deactivate_key.assert_called_once_with("key_123")

    async def test_deactivate_key_not_found(self, service, mock_repo):
        mock_repo.get_by_kid.return_value = None

        with pytest.raises(NotFoundException):
            await service.deactivate_key("nonexistent")

    async def test_deactivate_key_last_active(self, service, mock_repo):
        mock_key = MagicMock(spec=JWKKey)
        mock_key.is_active = True
        mock_repo.get_by_kid.return_value = mock_key
        mock_repo.get_active_keys.return_value = [mock_key]

        result = await service.deactivate_key("key_123")

        assert result is False
        mock_repo.deactivate_key.assert_not_called()


class TestJWKServiceExpireKey:
    """Tests for expire_key method."""

    @pytest.fixture
    def mock_repo(self):
        repo = AsyncMock()
        repo.get_by_kid = AsyncMock()
        repo.expire_key = AsyncMock(return_value=True)
        return repo

    @pytest.fixture
    def service(self, mock_repo):
        return JWKService(mock_repo)

    async def test_expire_key_success(self, service, mock_repo):
        mock_key = MagicMock(spec=JWKKey)
        mock_repo.get_by_kid.return_value = mock_key

        result = await service.expire_key("key_123")

        assert result is True
        mock_repo.expire_key.assert_called_once_with("key_123")

    async def test_expire_key_not_found(self, service, mock_repo):
        mock_repo.get_by_kid.return_value = None

        with pytest.raises(NotFoundException):
            await service.expire_key("nonexistent")


class TestJWKServiceRotateKeys:
    """Tests for rotate_keys method."""

    @pytest.fixture
    def mock_repo(self):
        repo = AsyncMock()
        repo.create = AsyncMock()
        repo.get_active_keys = AsyncMock()
        repo.deactivate_key = AsyncMock()
        repo.get_by_kid = AsyncMock(return_value=None)
        return repo

    @pytest.fixture
    def service(self, mock_repo):
        return JWKService(mock_repo)

    async def test_rotate_keys_success(self, service, mock_repo):
        """Test successful key rotation."""
        old_key = MagicMock(spec=JWKKey)
        old_key.kid = "old_key"
        old_key.created_at = datetime.now(timezone.utc) - timedelta(hours=48)
        mock_repo.get_active_keys.return_value = [old_key]

        with patch.object(service, "generate_key_pair", AsyncMock()) as mock_generate:
            new_key = MagicMock(spec=JWKKey)
            new_key.kid = "new_key"
            mock_generate.return_value = (new_key, "private", "public")
            mock_repo.create.return_value = new_key

            result_key, private_pem, public_pem = await service.rotate_keys(
                algorithm="RS256",
                key_size=2048,
                grace_period_hours=24,
                rotated_by="admin",
            )

        assert result_key == new_key
        assert result_key.is_active is True
        assert result_key.activated_by == "admin"
        mock_repo.deactivate_key.assert_called_once_with("old_key")

    async def test_rotate_keys_no_old_keys(self, service, mock_repo):
        """Test rotation with no existing active keys."""
        mock_repo.get_active_keys.return_value = []

        with patch.object(service, "generate_key_pair", AsyncMock()) as mock_generate:
            new_key = MagicMock(spec=JWKKey)
            new_key.kid = "new_key"
            mock_generate.return_value = (new_key, "private", "public")
            mock_repo.create.return_value = new_key

            result_key, _, _ = await service.rotate_keys()

        assert result_key == new_key
        mock_repo.deactivate_key.assert_not_called()


class TestJWKServiceGetJWKS:
    """Tests for get_jwks method."""

    @pytest.fixture
    def mock_repo(self):
        repo = AsyncMock()
        repo.get_keys_for_verification = AsyncMock()
        return repo

    @pytest.fixture
    def service(self, mock_repo):
        return JWKService(mock_repo)

    async def test_get_jwks_cache_hit(self, service, mock_repo):
        """Test JWKS from cache."""
        cached = {"keys": [{"kid": "cached_key"}]}
        with patch.object(service, "_get_cached_jwks", AsyncMock(return_value=cached)):
            result = await service.get_jwks()

        assert result == cached
        mock_repo.get_keys_for_verification.assert_not_called()

    async def test_get_jwks_cache_miss(self, service, mock_repo):
        """Test JWKS from DB when cache empty."""
        mock_key = MagicMock(spec=JWKKey)
        mock_key.is_valid = True
        mock_key.get_jwks_public_data.return_value = {"kid": "db_key"}
        mock_repo.get_keys_for_verification.return_value = [mock_key]

        with patch.object(service, "_get_cached_jwks", AsyncMock(return_value=None)):
            with patch.object(service, "_cache_jwks", AsyncMock()):
                result = await service.get_jwks()

        assert len(result["keys"]) == 1
        assert result["keys"][0]["kid"] == "db_key"

    async def test_get_jwks_force_refresh(self, service, mock_repo):
        """Test force refresh bypasses cache."""
        mock_key = MagicMock(spec=JWKKey)
        mock_key.is_valid = True
        mock_key.get_jwks_public_data.return_value = {"kid": "refreshed_key"}
        mock_repo.get_keys_for_verification.return_value = [mock_key]

        with patch.object(service, "_get_cached_jwks", AsyncMock()) as mock_cache:
            with patch.object(service, "_cache_jwks", AsyncMock()):
                result = await service.get_jwks(force_refresh=True)

        assert result["keys"][0]["kid"] == "refreshed_key"
        mock_cache.assert_not_called()


class TestJWKServiceMetrics:
    """Tests for get_key_metrics and get_metrics_data."""

    @pytest.fixture
    def mock_repo(self):
        repo = AsyncMock()
        repo.count_active_keys = AsyncMock()
        repo.count_expired_keys = AsyncMock()
        repo.count_total_keys = AsyncMock()
        repo.count_keys_by_algorithm = AsyncMock()
        return repo

    @pytest.fixture
    def service(self, mock_repo):
        return JWKService(mock_repo)

    async def test_get_key_metrics(self, service, mock_repo):
        mock_repo.count_active_keys.return_value = 2
        mock_repo.count_expired_keys.return_value = 5
        mock_repo.count_total_keys.return_value = 10

        active, expired, total = await service.get_key_metrics()

        assert active == 2
        assert expired == 5
        assert total == 10

    async def test_get_metrics_data(self, service, mock_repo):
        mock_repo.count_active_keys.return_value = 3
        mock_repo.count_expired_keys.return_value = 1
        mock_repo.count_total_keys.return_value = 4
        mock_repo.count_keys_by_algorithm.return_value = {"RS256": 4}

        metrics = await service.get_metrics_data()

        assert metrics["active_keys"] == 3
        assert metrics["expired_keys"] == 1
        assert metrics["total_keys"] == 4
        assert "keys_by_algorithm" in metrics


class TestJWKServiceCleanup:
    """Tests for cleanup_expired_keys."""

    @pytest.fixture
    def mock_repo(self):
        repo = AsyncMock()
        repo.delete_expired_keys = AsyncMock()
        return repo

    @pytest.fixture
    def service(self, mock_repo):
        return JWKService(mock_repo)

    async def test_cleanup_expired_keys(self, service, mock_repo):
        mock_repo.delete_expired_keys.return_value = 5

        with patch.object(service, "_invalidate_cache", AsyncMock()):
            deleted = await service.cleanup_expired_keys()

        assert deleted == 5

    async def test_cleanup_no_expired_keys(self, service, mock_repo):
        mock_repo.delete_expired_keys.return_value = 0

        deleted = await service.cleanup_expired_keys()

        assert deleted == 0


class TestJWKServiceCache:
    """Tests for caching methods."""

    @pytest.fixture
    def mock_repo(self):
        return AsyncMock()

    @pytest.fixture
    def service(self, mock_repo):
        return JWKService(mock_repo)

    @patch("app.services.jwk_service.redis_client")
    async def test_get_cached_jwks_hit(self, mock_redis, service):
        import json
        mock_redis.get = AsyncMock(return_value=json.dumps({"keys": [{"kid": "cached"}]}))

        result = await service._get_cached_jwks()

        assert result == {"keys": [{"kid": "cached"}]}

    @patch("app.services.jwk_service.redis_client")
    async def test_get_cached_jwks_miss(self, mock_redis, service):
        mock_redis.get = AsyncMock(return_value=None)

        result = await service._get_cached_jwks()

        assert result is None

    @patch("app.services.jwk_service.redis_client")
    async def test_cache_jwks(self, mock_redis, service):
        mock_redis.setex = AsyncMock()

        await service._cache_jwks({"keys": []})

        mock_redis.setex.assert_called_once()

    @patch("app.services.jwk_service.redis_client")
    async def test_invalidate_cache(self, mock_redis, service):
        mock_redis.delete = AsyncMock()

        await service._invalidate_cache()

        mock_redis.delete.assert_called_once()


class TestJWKServiceHelpers:
    """Tests for health_check, get_primary_key, get_key_by_algorithm."""

    @pytest.fixture
    def mock_repo(self):
        repo = AsyncMock()
        repo.count_total_keys = AsyncMock()
        repo.get_primary_key = AsyncMock()
        repo.get_active_key_by_algorithm = AsyncMock()
        return repo

    @pytest.fixture
    def service(self, mock_repo):
        return JWKService(mock_repo)

    async def test_health_check_healthy(self, service, mock_repo):
        mock_repo.count_total_keys.return_value = 5
        result = await service.health_check()
        assert result is True

    async def test_health_check_unhealthy(self, service, mock_repo):
        mock_repo.count_total_keys.side_effect = Exception("DB error")
        result = await service.health_check()
        assert result is False

    async def test_get_primary_key(self, service, mock_repo):
        mock_key = MagicMock(spec=JWKKey)
        mock_repo.get_primary_key.return_value = mock_key
        result = await service.get_primary_key()
        assert result == mock_key

    async def test_get_key_by_algorithm(self, service, mock_repo):
        mock_key = MagicMock(spec=JWKKey)
        mock_repo.get_active_key_by_algorithm.return_value = mock_key
        result = await service.get_key_by_algorithm("RS256")
        assert result == mock_key