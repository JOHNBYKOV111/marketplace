"""
Unit tests for Settings configuration.

Tests cover:
- Default values for all configuration fields
- Environment variable overrides
- Field validators (patterns, ge, le)
- Custom validator methods (parse_cors_origins, parse_cors_methods, etc.)
- Properties (is_development, is_production, jwt_secret_key, etc.)
- Edge cases and boundary values
"""

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.core.config import Settings


class TestSettingsDefaults:
    """Tests for default configuration values (with env cleared)."""

    @pytest.fixture
    def clean_settings(self):
        """Create Settings with environment cleared to test true defaults."""
        with patch.dict(os.environ, {}, clear=True):
            yield Settings()

    def test_default_environment_values(self, clean_settings):
        """Test default values for environment and service config."""
        assert clean_settings.APP_NAME == "Auth Service"
        assert clean_settings.APP_VERSION == "1.0.0"
        assert clean_settings.ENVIRONMENT == "development"
        assert clean_settings.DEBUG is False
        assert clean_settings.SERVICE_NAME == "auth-service"

    def test_default_server_values(self, clean_settings):
        """Test default server configuration values."""
        assert clean_settings.HOST == "0.0.0.0"
        assert clean_settings.PORT == 8000
        assert clean_settings.RELOAD is False
        assert clean_settings.WORKERS == 1

    def test_default_database_values(self, clean_settings):
        """Test default database configuration values."""
        assert "postgresql+asyncpg://" in clean_settings.DATABASE_URL
        assert clean_settings.DB_POOL_SIZE == 20
        assert clean_settings.DB_MAX_OVERFLOW == 10
        assert clean_settings.DB_ECHO is False
        assert clean_settings.DB_POOL_PRE_PING is True
        assert clean_settings.DB_POOL_RECYCLE == 3600
        assert clean_settings.DB_POOL_DISABLED is False

    def test_default_redis_values(self, clean_settings):
        """Test default Redis configuration values."""
        assert "redis://" in clean_settings.REDIS_URL
        assert clean_settings.REDIS_MAX_CONNECTIONS == 10
        assert clean_settings.REDIS_CONNECT_TIMEOUT == 5
        assert clean_settings.REDIS_TIMEOUT == 5
        assert clean_settings.SESSION_TTL == 86400

    def test_default_kafka_values(self, clean_settings):
        """Test default Kafka configuration values."""
        assert clean_settings.KAFKA_ENABLED is True
        assert clean_settings.KAFKA_BOOTSTRAP_SERVERS == "localhost:9092"
        assert clean_settings.KAFKA_CONSUMER_GROUP == "auth-service"
        assert clean_settings.KAFKA_PRODUCER_ACKS == "all"
        assert clean_settings.KAFKA_PRODUCER_MAX_BATCH_SIZE == 16384
        assert clean_settings.KAFKA_PRODUCER_LINGER_MS == 10
        assert clean_settings.KAFKA_PRODUCER_COMPRESSION_TYPE == "snappy"

    def test_default_jwt_values(self, clean_settings):
        """Test default JWT configuration values."""
        assert clean_settings.JWT_SECRET_KEY == "your-secret-key-change-in-production"
        assert clean_settings.JWT_ALGORITHM == "HS256"
        assert clean_settings.JWT_PRIVATE_KEY == ""
        assert clean_settings.JWT_PUBLIC_KEY == ""
        assert clean_settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES == 60
        assert clean_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS == 30
        assert clean_settings.JWT_BLACKLIST_TTL_MINUTES == 15

    def test_default_password_values(self, clean_settings):
        """Test default password configuration values."""
        assert clean_settings.PASSWORD_MIN_LENGTH == 8
        assert clean_settings.PASSWORD_MAX_LENGTH == 128
        assert clean_settings.PASSWORD_BCRYPT_ROUNDS == 12
        assert clean_settings.PASSWORD_REQUIRE_UPPERCASE is True
        assert clean_settings.PASSWORD_REQUIRE_LOWERCASE is True
        assert clean_settings.PASSWORD_REQUIRE_DIGITS is True
        assert clean_settings.PASSWORD_REQUIRE_SPECIAL_CHARS is True

    def test_default_password_reset_values(self, clean_settings):
        """Test default password reset configuration values."""
        assert clean_settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES == 60
        assert clean_settings.PASSWORD_RESET_TOKEN_LENGTH == 32
        assert clean_settings.PASSWORD_RESET_RATE_LIMIT == 3
        assert clean_settings.PASSWORD_RESET_RATE_LIMIT_WINDOW == 600

    def test_default_otp_values(self, clean_settings):
        """Test default OTP configuration."""
        assert clean_settings.OTP_TTL_SECONDS == 300

    def test_default_rate_limit_values(self, clean_settings):
        """Test default rate limiting configuration."""
        assert clean_settings.RATE_LIMIT_ENABLED is True
        assert clean_settings.RATE_LIMIT_DEFAULT == "100/minute"
        assert clean_settings.RATE_LIMIT_AUTH == "10/minute"
        assert clean_settings.RATE_LIMIT_ADMIN == "50/minute"

    def test_default_logging_values(self, clean_settings):
        """Test default logging configuration."""
        assert clean_settings.LOG_LEVEL == "INFO"
        assert clean_settings.LOG_FORMAT == "json"
        assert clean_settings.LOG_PII_MASKING_ENABLED is True

    def test_default_vault_values(self, clean_settings):
        """Test default Vault configuration values."""
        assert clean_settings.VAULT_URL == "http://vault:8200"
        assert clean_settings.VAULT_AUTH_METHOD == "token"
        assert clean_settings.VAULT_SECRET_PATH == "secret/data/auth"

    def test_default_jwks_values(self, clean_settings):
        """Test default JWKS configuration values."""
        assert clean_settings.JWKS_ROTATION_INTERVAL_HOURS == 24
        assert clean_settings.JWKS_KEY_SIZE == 2048
        assert clean_settings.JWKS_KEY_ALGORITHM == "RS256"
        assert clean_settings.JWKS_MAX_KEYS == 10

    def test_default_oauth_values(self, clean_settings):
        """Test default OAuth configuration values."""
        assert clean_settings.OAUTH_GOOGLE_CLIENT_ID is None
        assert clean_settings.OAUTH_VK_CLIENT_ID is None
        assert clean_settings.OAUTH_APPLE_CLIENT_ID is None
        assert clean_settings.OAUTH_STATE_TTL_SECONDS == 600

    def test_default_internal_api_values(self, clean_settings):
        """Test default Internal API configuration values."""
        assert clean_settings.INTERNAL_ENABLED is True
        assert clean_settings.INTERNAL_API_KEY == "test_api_key"
        assert clean_settings.INTERNAL_RATE_LIMIT_REQUESTS == 100

    def test_default_grpc_values(self, clean_settings):
        """Test default gRPC configuration values."""
        assert clean_settings.USER_SERVICE_GRPC_URL == ""
        assert clean_settings.PROFILE_SERVICE_GRPC_URL == ""
        assert clean_settings.GRPC_TIMEOUT_SECONDS == 5


class TestSettingsValidation:
    """Tests for field validation rules."""

    def test_environment_pattern_validation(self):
        """Test ENVIRONMENT only accepts valid values."""
        valid_envs = ["development", "staging", "production"]
        for env in valid_envs:
            s = Settings(ENVIRONMENT=env)
            assert s.ENVIRONMENT == env

        with pytest.raises(ValidationError):
            Settings(ENVIRONMENT="invalid")

    def test_log_level_validation(self):
        """Test LOG_LEVEL only accepts standard log levels."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        for level in valid_levels:
            s = Settings(LOG_LEVEL=level)
            assert s.LOG_LEVEL == level

        with pytest.raises(ValidationError):
            Settings(LOG_LEVEL="TRACE")

    def test_vault_auth_method_validation(self):
        """Test VAULT_AUTH_METHOD only accepts valid methods."""
        valid_methods = ["token", "approle", "kubernetes", "ldap"]
        for method in valid_methods:
            s = Settings(VAULT_AUTH_METHOD=method)
            assert s.VAULT_AUTH_METHOD == method

        with pytest.raises(ValidationError):
            Settings(VAULT_AUTH_METHOD="invalid")

    def test_grpc_timeout_boundaries(self):
        """Test GRPC_TIMEOUT_SECONDS boundaries."""
        s_min = Settings(GRPC_TIMEOUT_SECONDS=1)
        s_max = Settings(GRPC_TIMEOUT_SECONDS=60)
        assert s_min.GRPC_TIMEOUT_SECONDS == 1
        assert s_max.GRPC_TIMEOUT_SECONDS == 60

        with pytest.raises(ValidationError):
            Settings(GRPC_TIMEOUT_SECONDS=0)
        with pytest.raises(ValidationError):
            Settings(GRPC_TIMEOUT_SECONDS=61)

    def test_password_min_length_boundaries(self):
        """Test PASSWORD_MIN_LENGTH boundaries."""
        s_min = Settings(PASSWORD_MIN_LENGTH=6)
        s_max = Settings(PASSWORD_MIN_LENGTH=256)
        assert s_min.PASSWORD_MIN_LENGTH == 6
        assert s_max.PASSWORD_MIN_LENGTH == 256

        with pytest.raises(ValidationError):
            Settings(PASSWORD_MIN_LENGTH=5)
        with pytest.raises(ValidationError):
            Settings(PASSWORD_MIN_LENGTH=257)

    def test_password_bcrypt_rounds_boundaries(self):
        """Test PASSWORD_BCRYPT_ROUNDS boundaries."""
        s_min = Settings(PASSWORD_BCRYPT_ROUNDS=4)
        s_max = Settings(PASSWORD_BCRYPT_ROUNDS=31)
        assert s_min.PASSWORD_BCRYPT_ROUNDS == 4
        assert s_max.PASSWORD_BCRYPT_ROUNDS == 31

        with pytest.raises(ValidationError):
            Settings(PASSWORD_BCRYPT_ROUNDS=3)
        with pytest.raises(ValidationError):
            Settings(PASSWORD_BCRYPT_ROUNDS=32)

    def test_internal_rate_limit_boundaries(self):
        """Test INTERNAL_RATE_LIMIT_REQUESTS boundaries."""
        s_min = Settings(INTERNAL_RATE_LIMIT_REQUESTS=1)
        s_max = Settings(INTERNAL_RATE_LIMIT_REQUESTS=10000)
        assert s_min.INTERNAL_RATE_LIMIT_REQUESTS == 1
        assert s_max.INTERNAL_RATE_LIMIT_REQUESTS == 10000

        with pytest.raises(ValidationError):
            Settings(INTERNAL_RATE_LIMIT_REQUESTS=0)
        with pytest.raises(ValidationError):
            Settings(INTERNAL_RATE_LIMIT_REQUESTS=10001)

    def test_oauth_state_ttl_boundaries(self):
        """Test OAUTH_STATE_TTL_SECONDS boundaries."""
        s_min = Settings(OAUTH_STATE_TTL_SECONDS=60)
        s_max = Settings(OAUTH_STATE_TTL_SECONDS=3600)
        assert s_min.OAUTH_STATE_TTL_SECONDS == 60
        assert s_max.OAUTH_STATE_TTL_SECONDS == 3600

        with pytest.raises(ValidationError):
            Settings(OAUTH_STATE_TTL_SECONDS=59)
        with pytest.raises(ValidationError):
            Settings(OAUTH_STATE_TTL_SECONDS=3601)


class TestSettingsEnvironmentOverrides:
    """Tests for environment variable overrides."""

    @patch.dict(os.environ, {"ENVIRONMENT": "production"}, clear=True)
    def test_environment_override(self):
        """Test ENVIRONMENT can be overridden by env var."""
        settings = Settings()
        assert settings.ENVIRONMENT == "production"

    @patch.dict(os.environ, {"PORT": "9000"}, clear=True)
    def test_port_override(self):
        """Test PORT can be overridden by env var."""
        settings = Settings()
        assert settings.PORT == 9000

    @patch.dict(os.environ, {"JWT_ACCESS_TOKEN_EXPIRE_MINUTES": "30"}, clear=True)
    def test_jwt_expire_override(self):
        """Test JWT_ACCESS_TOKEN_EXPIRE_MINUTES can be overridden."""
        settings = Settings()
        assert settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES == 30

    @patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}, clear=True)
    def test_log_level_override(self):
        """Test LOG_LEVEL can be overridden."""
        settings = Settings()
        assert settings.LOG_LEVEL == "DEBUG"

    @patch.dict(os.environ, {"DB_POOL_SIZE": "50"}, clear=True)
    def test_db_pool_size_override(self):
        """Test DB_POOL_SIZE can be overridden by env var."""
        settings = Settings()
        assert settings.DB_POOL_SIZE == 50


class TestSettingsValidators:
    """Tests for custom field validators."""

    def test_cors_allow_origins_parse_string(self):
        """Test CORS_ALLOWED_ORIGINS parses comma-separated string."""
        settings = Settings(
            CORS_ALLOWED_ORIGINS="http://localhost:3000,https://example.com"
        )
        assert settings.CORS_ALLOWED_ORIGINS == [
            "http://localhost:3000",
            "https://example.com"
        ]

    def test_cors_allow_origins_parse_list(self):
        """Test CORS_ALLOWED_ORIGINS accepts list directly."""
        settings = Settings(
            CORS_ALLOWED_ORIGINS=["http://localhost:3000", "https://example.com"]
        )
        assert settings.CORS_ALLOWED_ORIGINS == [
            "http://localhost:3000",
            "https://example.com"
        ]

    def test_cors_allow_origins_with_spaces(self):
        """Test CORS_ALLOWED_ORIGINS strips whitespace from origins."""
        settings = Settings(
            CORS_ALLOWED_ORIGINS=" http://localhost:3000 , https://example.com "
        )
        assert settings.CORS_ALLOWED_ORIGINS == [
            "http://localhost:3000",
            "https://example.com"
        ]

    def test_cors_allow_methods_parse_string(self):
        """Test CORS_ALLOWED_METHODS parses and uppercases methods."""
        settings = Settings(
            CORS_ALLOWED_METHODS="get, post, put"
        )
        assert settings.CORS_ALLOWED_METHODS == ["GET", "POST", "PUT"]

    def test_cors_allow_headers_parse_string(self):
        """Test CORS_ALLOWED_HEADERS parses comma-separated string."""
        settings = Settings(
            CORS_ALLOWED_HEADERS="Authorization, Content-Type"
        )
        assert settings.CORS_ALLOWED_HEADERS == ["Authorization", "Content-Type"]

    def test_internal_ips_parse_string(self):
        """Test INTERNAL_ALLOWED_IPS parses comma-separated string."""
        settings = Settings(
            INTERNAL_ALLOWED_IPS="127.0.0.1, 10.0.0.1"
        )
        assert settings.INTERNAL_ALLOWED_IPS == ["127.0.0.1", "10.0.0.1"]

    def test_oauth_redirect_uris_parse_string(self):
        """Test OAUTH_REDIRECT_URI_WHITELIST parses comma-separated string."""
        settings = Settings(
            OAUTH_REDIRECT_URI_WHITELIST="http://localhost:3000, https://app.example.com"
        )
        assert settings.OAUTH_REDIRECT_URI_WHITELIST == [
            "http://localhost:3000",
            "https://app.example.com"
        ]


class TestSettingsProperties:
    """Tests for Settings properties."""

    def test_jwt_secret_key_property(self):
        """Test jwt_secret_key property."""
        settings = Settings(JWT_SECRET_KEY="custom-secret")
        assert settings.jwt_secret_key == "custom-secret"

    def test_jwt_algorithm_property(self):
        """Test jwt_algorithm property."""
        settings = Settings(JWT_ALGORITHM="RS256")
        assert settings.jwt_algorithm == "RS256"

    def test_access_token_expire_minutes_property(self):
        """Test access_token_expire_minutes property."""
        settings = Settings(JWT_ACCESS_TOKEN_EXPIRE_MINUTES=45)
        assert settings.access_token_expire_minutes == 45

    def test_refresh_token_expire_days_property(self):
        """Test refresh_token_expire_days property."""
        settings = Settings(JWT_REFRESH_TOKEN_EXPIRE_DAYS=60)
        assert settings.refresh_token_expire_days == 60

    def test_jwt_blacklist_ttl_minutes_property(self):
        """Test jwt_blacklist_ttl_minutes property."""
        settings = Settings(JWT_BLACKLIST_TTL_MINUTES=30)
        assert settings.jwt_blacklist_ttl_minutes == 30

    def test_is_development_property(self):
        """Test is_development property."""
        dev = Settings(ENVIRONMENT="development")
        staging = Settings(ENVIRONMENT="staging")
        prod = Settings(ENVIRONMENT="production")

        assert dev.is_development is True
        assert staging.is_development is False
        assert prod.is_development is False

    def test_is_staging_property(self):
        """Test is_staging property."""
        dev = Settings(ENVIRONMENT="development")
        staging = Settings(ENVIRONMENT="staging")
        prod = Settings(ENVIRONMENT="production")

        assert dev.is_staging is False
        assert staging.is_staging is True
        assert prod.is_staging is False

    def test_is_production_property(self):
        """Test is_production property."""
        dev = Settings(ENVIRONMENT="development")
        staging = Settings(ENVIRONMENT="staging")
        prod = Settings(ENVIRONMENT="production")

        assert dev.is_production is False
        assert staging.is_production is False
        assert prod.is_production is True

    def test_is_debug_property(self):
        """Test is_debug property."""
        dev = Settings(ENVIRONMENT="development", DEBUG=False)
        debug = Settings(ENVIRONMENT="production", DEBUG=True)

        assert dev.is_debug is True  # development always debug
        assert debug.is_debug is True  # DEBUG=True

    def test_database_url_async_property(self):
        """Test database_url_async property."""
        settings = Settings(DATABASE_URL="postgresql+asyncpg://localhost/test")
        assert settings.database_url_async == "postgresql+asyncpg://localhost/test"

    def test_database_url_sync_property(self):
        """Test database_url_sync property."""
        settings = Settings(DATABASE_URL="postgresql+asyncpg://localhost/test")
        assert settings.database_url_sync == "postgresql://localhost/test"


class TestSettingsSingleton:
    """Tests for settings singleton pattern."""

    def test_settings_singleton_import(self):
        """Test settings singleton can be imported."""
        from app.core.config import settings as global_settings
        assert isinstance(global_settings, Settings)

    def test_get_settings_function(self):
        """Test get_settings returns the global singleton."""
        from app.core.config import get_settings
        settings = get_settings()
        assert isinstance(settings, Settings)

    def test_reload_settings_function(self):
        """Test reload_settings creates a new instance."""
        from app.core.config import reload_settings
        settings = reload_settings()
        assert isinstance(settings, Settings)


class TestSettingsEdgeCases:
    """Tests for edge cases and boundary values."""

    def test_empty_strings_for_optional_secrets(self):
        """Test empty strings are allowed for secret fields."""
        settings = Settings(
            SECRET_PEPPER="",
            ENCRYPTION_KEY="",
            JWT_PRIVATE_KEY="",
            JWT_PUBLIC_KEY="",
        )
        assert settings.SECRET_PEPPER == ""
        assert settings.ENCRYPTION_KEY == ""

    def test_none_values_for_optional_oauth(self):
        """Test None values are allowed for optional OAuth configs."""
        settings = Settings()
        assert settings.OAUTH_GOOGLE_CLIENT_ID is None
        assert settings.OAUTH_VK_CLIENT_ID is None
        assert settings.OAUTH_APPLE_CLIENT_ID is None

    def test_production_mode_default(self):
        """Test PRODUCTION_MODE default is False."""
        settings = Settings()
        assert settings.PRODUCTION_MODE is False

    def test_internal_api_key_min_length(self):
        """Test INTERNAL_API_KEY must have at least 1 character."""
        settings = Settings(INTERNAL_API_KEY="a")
        assert settings.INTERNAL_API_KEY == "a"

    def test_health_check_defaults(self):
        """Test health check default values."""
        settings = Settings()
        assert settings.HEALTH_CHECK_INTERVAL == 30
        assert settings.HEALTH_CHECK_TIMEOUT == 5