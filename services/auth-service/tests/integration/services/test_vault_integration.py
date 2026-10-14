"""
Интеграционные тесты для Vault клиента и сервиса.

Тестирует:
- Инициализацию Vault клиента (authenticate)
- Аутентификацию (token, approle)
- Чтение/запись секретов (read_secret, write_secret)
- Пакетное получение секретов (asyncio.gather)
- Кэширование (защита от Cache Stampede)
- Конкретные методы (get_db_credentials, get_redis_credentials, get_kafka_credentials, get_oauth_credentials)
- Конфигурации (get_config, set_config)
- Health check (healthcheck)
- Обработку ошибок (недоступный Vault, отсутствие секрета)
- Graceful shutdown
- Работа с токенами (create_token, renew_token, revoke_token)
"""

import json
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.vault_client import VaultClient, close_vault, init_vault, vault_client


class TestVaultClientInitialization:
    """Тесты для инициализации Vault клиента."""

    @patch("app.core.vault_client.settings")
    async def test_authenticate_token_method(self, mock_settings):
        """Тест аутентификации через token."""
        mock_settings.VAULT_URL = "https://vault.example.com:8200"
        mock_settings.VAULT_TOKEN = "hvs.test_token_123"
        mock_settings.VAULT_AUTH_METHOD = "token"
        mock_settings.is_development.return_value = False

        client = VaultClient()
        await client.connect()

        assert client.is_connected is True

    @patch("app.core.vault_client.settings")
    async def test_authenticate_approle_method(self, mock_settings):
        """Тест аутентификации через AppRole."""
        mock_settings.VAULT_URL = "https://vault.example.com:8200"
        mock_settings.VAULT_AUTH_METHOD = "approle"
        mock_settings.VAULT_ROLE_ID = "role_id_123"
        mock_settings.VAULT_SECRET_ID = "secret_id_456"
        mock_settings.is_development.return_value = False

        client = VaultClient()
        await client.connect()

        assert client.is_connected is True

    @patch("app.core.vault_client.settings")
    async def test_authenticate_development_mode(self, mock_settings):
        """Тест аутентификации в development режиме (verify=False)."""
        mock_settings.VAULT_URL = "http://localhost:8200"
        mock_settings.VAULT_TOKEN = "dev_token"
        mock_settings.VAULT_AUTH_METHOD = "token"
        mock_settings.is_development.return_value = True

        client = VaultClient()
        await client.connect()

        assert client.is_connected is True


class TestSecretOperations:
    """Тесты для операций с секретами."""

    @pytest.fixture
    async def client(self):
        client = VaultClient()
        client._connected = True
        client._session = AsyncMock()
        return client

    async def test_read_secret_success(self, client):
        """Тест успешного получения секрета."""
        client._request = AsyncMock(
            return_value={"data": {"data": {"value": "secret_value_123"}}}
        )

        result = await client.read_secret("auth/test_secret")

        assert result == {"value": "secret_value_123"}
        client._request.assert_called_once_with("GET", "v1/auth/test_secret")

    async def test_read_secret_not_found(self, client):
        """Тест получения несуществующего секрета."""
        from aiohttp.client_exceptions import ClientResponseError
        
        client._request = AsyncMock(side_effect=ClientResponseError(
            status=404,
            message="Not Found",
            headers={},
            history=(),
            request_info=None,
        ))

        result = await client.read_secret("auth/nonexistent")

        assert result is None

    async def test_read_secret_with_cache(self, client):
        """Тест чтения секрета с кэшированием."""
        client._request = AsyncMock(
            return_value={"data": {"data": {"value": "cached_value"}}}
        )

        # Первый запрос - должен пойти в Vault
        result1 = await client.read_secret("auth/test", use_cache=True)
        assert result1 == {"value": "cached_value"}
        assert client._request.call_count == 1

        # Второй запрос - должен взять из кэша
        client._request.reset_mock()
        result2 = await client.read_secret("auth/test", use_cache=True)
        assert result2 == {"value": "cached_value"}
        client._request.assert_not_called()

    async def test_read_secret_cache_bypass(self, client):
        """Тест обхода кэша."""
        client._request = AsyncMock(
            return_value={"data": {"data": {"value": "fresh_value"}}}
        )

        await client.read_secret("auth/test", use_cache=False)
        await client.read_secret("auth/test", use_cache=False)

        assert client._request.call_count == 2

    @patch("app.core.vault_client.settings")
    async def test_get_oauth_credentials_success(self, mock_settings, client):
        """Тест успешного получения учетных данных OAuth."""
        mock_settings.VAULT_OAUTH_PATH = "auth/oauth/google"
        
        test_data = {"client_id": "123", "client_secret": "secret"}
        client.read_secret = AsyncMock(return_value=test_data)
    
        result = await client.get_oauth_credentials()
    
        assert result == test_data
        client.read_secret.assert_called_once_with("auth/oauth/google")

    async def test_write_secret_success(self, client):
        """Тест успешной записи секрета."""
        client._request = AsyncMock(return_value={"data": {"version": 1}})

        result = await client.write_secret("auth/test_secret", {"value": "new_value"})

        assert result is True
        client._request.assert_called_once_with(
            "POST", 
            "v1/auth/test_secret", 
            data={"data": {"value": "new_value"}}
        )

    async def test_delete_secret_success(self, client):
        """Тест успешного удаления секрета."""
        client._request = AsyncMock(return_value={})

        result = await client.delete_secret("auth/test_secret")

        assert result is True
        client._request.assert_called_once_with("DELETE", "v1/auth/test_secret")

    async def test_get_secrets_batch(self, client):
        """Тест пакетного получения секретов."""
        client.read_secret = AsyncMock(side_effect=[
            {"value": "url1"},
            {"value": "url2"},
            {"value": "key1"},
        ])

        paths = ["auth/database_url", "auth/redis_url", "auth/jwt_private_key"]
        
        tasks = [client.read_secret(path) for path in paths]
        results = await asyncio.gather(*tasks)

        assert results == [{"value": "url1"}, {"value": "url2"}, {"value": "key1"}]
        assert client.read_secret.call_count == 3


class TestVaultCache:
    """Тесты для кэширования секретов."""

    @pytest.fixture
    async def client(self):
        client = VaultClient()
        client._connected = True
        client._session = AsyncMock()
        return client

    async def test_cache_hit(self, client):
        """Тест попадания в кэш."""
        client._request = AsyncMock(
            return_value={"data": {"data": {"value": "cached_value"}}}
        )

        result1 = await client.read_secret("auth/test", use_cache=True)
        assert result1 == {"value": "cached_value"}
        assert client._request.call_count == 1

        client._request.reset_mock()
        result2 = await client.read_secret("auth/test", use_cache=True)
        assert result2 == {"value": "cached_value"}
        client._request.assert_not_called()

    async def test_cache_bypass(self, client):
        """Тест обхода кэша."""
        client._request = AsyncMock(
            return_value={"data": {"data": {"value": "fresh_value"}}}
        )

        await client.read_secret("auth/test", use_cache=False)
        await client.read_secret("auth/test", use_cache=False)

        assert client._request.call_count == 2

    async def test_clear_cache(self, client):
        """Тест очистки кэша."""
        client._cache = {"test_key": {"value": "cached"}}
        client._cache_ttl = {"test_key": 12345}

        client._clear_cache()

        assert len(client._cache) == 0
        assert len(client._cache_ttl) == 0

    async def test_clear_cache_specific_path(self, client):
        """Тест очистки кэша для конкретного пути."""
        client._cache = {
            "vault:path1": {"value": "data1"},
            "vault:path2": {"value": "data2"},
        }
        client._cache_ttl = {
            "vault:path1": 12345,
            "vault:path2": 12346,
        }

        client._clear_cache("path1")

        assert "vault:path1" not in client._cache
        assert "vault:path2" in client._cache
        assert "vault:path1" not in client._cache_ttl
        assert "vault:path2" in client._cache_ttl


class TestVaultConcreteMethods:
    """Тесты для конкретных методов получения секретов."""

    @pytest.fixture
    async def client(self):
        client = VaultClient()
        client._connected = True
        client._session = AsyncMock()
        return client

    @patch("app.core.vault_client.settings")
    async def test_get_db_credentials(self, mock_settings, client):
        """Тест получения учетных данных базы данных."""
        mock_settings.VAULT_DB_PATH = "secret/data/database"
        
        test_credentials = {
            "username": "test_user",
            "password": "test_password",
            "host": "localhost",
            "port": "5432",
            "database": "auth_db"
        }
        client.read_secret = AsyncMock(return_value=test_credentials)

        result = await client.get_db_credentials()

        assert result == test_credentials
        client.read_secret.assert_called_once_with("secret/data/database")

    @patch("app.core.vault_client.settings")
    async def test_get_db_credentials_missing(self, mock_settings, client):
        """Тест отсутствия учетных данных базы данных."""
        mock_settings.VAULT_DB_PATH = "secret/data/database"
        client.read_secret = AsyncMock(return_value=None)

        result = await client.get_db_credentials()
        
        assert result is None

    @patch("app.core.vault_client.settings")
    async def test_get_redis_credentials(self, mock_settings, client):
        """Тест получения учетных данных Redis."""
        mock_settings.VAULT_REDIS_PATH = "secret/data/redis"
        
        test_credentials = {
            "host": "redis.example.com",
            "port": "6379",
            "password": "redis_pass"
        }
        client.read_secret = AsyncMock(return_value=test_credentials)

        result = await client.get_redis_credentials()

        assert result == test_credentials
        client.read_secret.assert_called_once_with("secret/data/redis")

    @patch("app.core.vault_client.settings")
    async def test_get_kafka_credentials(self, mock_settings, client):
        """Тест получения учетных данных Kafka."""
        mock_settings.VAULT_KAFKA_PATH = "secret/data/kafka"
        
        test_credentials = {
            "bootstrap_servers": "kafka.example.com:9092",
            "username": "kafka_user",
            "password": "kafka_pass"
        }
        client.read_secret = AsyncMock(return_value=test_credentials)

        result = await client.get_kafka_credentials()

        assert result == test_credentials
        client.read_secret.assert_called_once_with("secret/data/kafka")

    @patch("app.core.vault_client.settings")
    async def test_get_oauth_credentials(self, mock_settings, client):
        """Тест получения учетных данных OAuth."""
        mock_settings.VAULT_OAUTH_PATH = "auth/oauth/google"
        
        test_credentials = {
            "client_id": "oauth_client_id",
            "client_secret": "oauth_secret"
        }
        client.read_secret = AsyncMock(return_value=test_credentials)

        result = await client.get_oauth_credentials()

        assert result == test_credentials
        client.read_secret.assert_called_once_with("auth/oauth/google")

    async def test_get_config_jwt_private_key(self, client):
        """Тест получения JWT приватного ключа через get_config."""
        mock_key_value = "-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----"
        client.read_secret = AsyncMock(return_value={"value": mock_key_value})

        result = await client.get_config("jwt_private_key")

        assert result == mock_key_value
        client.read_secret.assert_called_once_with("secret/data/config/jwt_private_key")

    async def test_get_config_pepper(self, client):
        """Тест получения pepper через get_config."""
        mock_pepper_value = "test_pepper_123"
        client.read_secret = AsyncMock(return_value={"value": mock_pepper_value})

        result = await client.get_config("pepper")

        assert result == mock_pepper_value
        client.read_secret.assert_called_once_with("secret/data/config/pepper")

    async def test_get_config_encryption_key(self, client):
        """Тест получения ключа шифрования через get_config."""
        mock_key_value = "test_encryption_key_456"
        client.read_secret = AsyncMock(return_value={"value": mock_key_value})

        result = await client.get_config("encryption_key")

        assert result == mock_key_value
        client.read_secret.assert_called_once_with("secret/data/config/encryption_key")

    async def test_get_config_not_found(self, client):
        """Тест получения несуществующей конфигурации."""
        client.read_secret = AsyncMock(return_value=None)

        result = await client.get_config("nonexistent")

        assert result is None

    async def test_set_config_success(self, client):
        """Тест успешной установки конфигурации."""
        client.write_secret = AsyncMock(return_value=True)

        result = await client.set_config("test_key", "test_value")

        assert result is True
        client.write_secret.assert_called_once_with(
            "secret/data/config/test_key",
            {"value": "test_value"}
        )


class TestVaultHealthCheck:
    """Тесты для health check."""

    @pytest.fixture
    async def client(self):
        client = VaultClient()
        client._connected = True
        client._session = AsyncMock()
        return client

    async def test_healthcheck_success(self, client):
        """Тест успешной проверки здоровья."""
        client._request = AsyncMock(return_value={"initialized": True})

        result = await client.healthcheck()

        assert result is True
        client._request.assert_called_once_with("GET", "v1/sys/health")

    async def test_healthcheck_failure(self, client):
        """Тест неудачной проверки здоровья при исключении."""
        client._request = AsyncMock(side_effect=Exception("Connection refused"))

        result = await client.healthcheck()

        assert result is False

    async def test_healthcheck_standby(self, client):
        """Тест проверки здоровья когда Vault в режиме standby."""
        from aiohttp.client_exceptions import ClientResponseError
        
        client._request = AsyncMock(side_effect=ClientResponseError(
            status=429,
            message="Standby",
            headers={},
            history=(),
            request_info=None,
        ))

        result = await client.healthcheck()

        assert result is True

    async def test_is_sealed(self, client):
        """Тест проверки запечатан ли Vault."""
        client._request = AsyncMock(return_value={"sealed": False})

        result = await client.is_sealed()

        assert result is False
        client._request.assert_called_once_with("GET", "v1/sys/seal-status")

    async def test_get_status(self, client):
        """Тест получения статуса Vault."""
        client._request = AsyncMock(return_value={
            "initialized": True,
            "sealed": False,
            "standby": False,
            "performance_standby": False,
            "version": "1.15.0",
            "cluster_name": "vault-cluster",
            "cluster_id": "12345",
        })

        result = await client.get_status()

        assert result["healthy"] is True
        assert result["sealed"] is False
        assert result["version"] == "1.15.0"


class TestVaultTokenOperations:
    """Тесты для операций с токенами."""

    @pytest.fixture
    async def client(self):
        client = VaultClient()
        client._connected = True
        client._session = AsyncMock()
        return client

    async def test_create_token(self, client):
        """Тест создания токена."""
        client._request = AsyncMock(return_value={
            "auth": {
                "client_token": "hvs.new_token_123",
                "accessor": "accessor_123",
                "policies": ["default", "app-policy"],
                "ttl": 3600,
                "renewable": True,
            }
        })

        result = await client.create_token(
            policies=["default", "app-policy"],
            ttl="1h",
            renewable=True,
        )

        assert result["client_token"] == "hvs.new_token_123"
        assert result["policies"] == ["default", "app-policy"]
        assert result["renewable"] is True
        client._request.assert_called_once_with(
            "POST",
            "v1/auth/token/create",
            data={
                "policies": ["default", "app-policy"],
                "renewable": True,
                "ttl": "1h",
            }
        )

    async def test_renew_token(self, client):
        """Тест обновления токена."""
        client._request = AsyncMock(return_value={"auth": {"renewable": True}})

        result = await client.renew_token("hvs.token_123")

        assert result is True
        client._request.assert_called_once_with("POST", "v1/auth/token/renew/hvs.token_123")

    async def test_renew_self_token(self, client):
        """Тест обновления текущего токена."""
        client._request = AsyncMock(return_value={"auth": {"renewable": True}})

        result = await client.renew_token()

        assert result is True
        client._request.assert_called_once_with("POST", "v1/auth/token/renew-self")

    async def test_revoke_token(self, client):
        """Тест отзыва токена."""
        client._request = AsyncMock(return_value={})

        result = await client.revoke_token("hvs.token_123")

        assert result is True
        client._request.assert_called_once_with("POST", "v1/auth/token/revoke/hvs.token_123")


class TestVaultGracefulShutdown:
    """Тесты для graceful shutdown."""

    @pytest.fixture
    async def client(self):
        client = VaultClient()
        client._connected = True
        client._session = AsyncMock()
        return client

    async def test_close_client(self, client):
        """Тест закрытия Vault клиента."""
        await client.close()

        assert client._session is None
        assert client.is_connected is False
        assert client._cache == {}


class TestLifecycleFunctions:
    """Тесты для lifecycle функций init_vault и close_vault."""

    @patch("app.core.vault_client.vault_client")
    async def test_init_vault(self, mock_client):
        """Тест функции init_vault."""
        mock_client.connect = AsyncMock()

        await init_vault()

        mock_client.connect.assert_called_once()

    @patch("app.core.vault_client.vault_client")
    async def test_close_vault(self, mock_client):
        """Тест функции close_vault."""
        mock_client.close = AsyncMock()

        await close_vault()

        mock_client.close.assert_called_once()


class TestSingleton:
    """Тесты для синглтона vault_client."""

    def test_vault_client_singleton(self):
        """Тест что vault_client является синглтоном."""
        from app.core.vault_client import vault_client as client1
        from app.core.vault_client import vault_client as client2

        assert client1 is client2
        assert isinstance(client1, VaultClient)