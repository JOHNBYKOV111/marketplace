"""
Application configuration for User Service.

Loads settings from environment variables.
Supports override via .env file.
"""

from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """User Service settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        validate_default=True,
    )

    # ==================== GENERAL ====================
    APP_NAME: str = "User Service"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", pattern="^(development|staging|production)$")
    DEBUG: bool = False

    # ==================== SERVER ====================
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    RELOAD: bool = False
    WORKERS: int = 1

    # ==================== DATABASE ====================
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/user_db"
    TEST_DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/user_db_test"
    DB_ECHO: bool = False
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 3600
    DB_POOL_PRE_PING: bool = True

    # ==================== REDIS ====================
    REDIS_URL: str = "redis://marketplace-redis:6379/1"
    REDIS_MAX_CONNECTIONS: int = 10

    # ==================== KAFKA ====================
    KAFKA_ENABLED: bool = False
    KAFKA_BOOTSTRAP_SERVERS: str = "kafka:9092"
    KAFKA_CONSUMER_GROUP: str = "user-service"
    KAFKA_AUTO_OFFSET_RESET: str = "earliest"

    # ==================== JWT ====================
    JWT_SECRET_KEY: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    JWT_BLACKLIST_TTL_MINUTES: int = 15

    # ==================== SECURITY ====================
    SECRET_PEPPER: str = "your-pepper-change-in-production"
    PASSWORD_BCRYPT_ROUNDS: int = 12
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_MAX_LENGTH: int = 128

    # ==================== CORS ====================
    CORS_ALLOWED_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000", "http://localhost:8001"],
    )
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_MAX_AGE: int = 3600

    # ==================== RATE LIMITING ====================
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/minute"

    # ==================== LOGGING ====================
    LOG_LEVEL: str = "DEBUG"

    # ==================== METRICS ====================
    METRICS_ENABLED: bool = True
    METRICS_PORT: int = 9091

    # ==================== gRPC ====================
    USER_GRPC_PORT: int = 50051
    USER_GRPC_HOST: str = "0.0.0.0"

    # ==================== USER SERVICE SPECIFIC ====================
    USER_CACHE_TTL: int = 900
    USER_MAX_SESSIONS: int = 5
    USER_SOFT_DELETE_TTL_DAYS: int = 30
    USER_GDPR_EXPORT_TTL_HOURS: int = 24

    # ==================== AUTH SERVICE CLIENT ====================
    AUTH_SERVICE_URL: str = Field(
        default="http://auth-service:8000",
        description="Auth Service base URL for internal API calls",
    )
    AUTH_SERVICE_INTERNAL_API_KEY: str = Field(
        default="test_api_key",
        description="Internal API key for auth-service inter-service auth",
    )
    AUTH_SERVICE_TIMEOUT: float = Field(
        default=5.0,
        ge=1.0,
        le=60.0,
        description="HTTP request timeout in seconds for auth-service calls",
    )
    AUTH_SERVICE_MAX_CONNECTIONS: int = Field(
        default=500,
        ge=1,
        le=2000,
        description="Maximum concurrent connections to auth-service (tuned for peak load)",
    )
    AUTH_SERVICE_MAX_KEEPALIVE_CONNECTIONS: int = Field(
        default=200,
        ge=1,
        le=1000,
        description="Maximum keep-alive connections in the pool",
    )
    AUTH_SERVICE_KEEPALIVE: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Keep-alive timeout in seconds for auth-service connections",
    )

    # ==================== CACHING ====================
    AUTH_USER_INFO_CACHE_TTL: int = Field(
        default=300,
        ge=10,
        le=3600,
        description="TTL in seconds for cached auth-service user info responses",
    )
    AUTH_USER_INFO_CACHE_ENABLED: bool = Field(
        default=True,
        description="Enable Redis caching for auth-service user info responses",
    )

    # ==================== CIRCUIT BREAKER ====================
    CIRCUIT_BREAKER_ENABLED: bool = Field(
        default=True,
        description="Enable Circuit Breaker for auth-service HTTP calls",
    )
    CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Number of consecutive failures to open the circuit",
    )
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Seconds to wait before attempting half-open recovery",
    )
    CIRCUIT_BREAKER_HALF_OPEN_MAX_REQUESTS: int = Field(
        default=1,
        ge=1,
        le=10,
        description="Number of trial requests allowed in half-open state",
    )
    CIRCUIT_BREAKER_SUCCESS_THRESHOLD: int = Field(
        default=2,
        ge=1,
        le=10,
        description="Number of consecutive successes to close the circuit from half-open",
    )
    CIRCUIT_BREAKER_EXCLUDED_STATUS_CODES: List[int] = Field(
        default=[400, 401, 403, 404, 409, 422],
        description="HTTP status codes that should NOT be counted as failures",
    )
    CIRCUIT_BREAKER_FAILURE_STATUS_CODES: List[int] = Field(
        default=[500, 502, 503, 504],
        description="Additional HTTP status codes to count as failures beyond network errors",
    )

    # ==================== PROPERTIES ====================

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def database_url_async(self) -> str:
        return self.DATABASE_URL

    @field_validator("CORS_ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("CIRCUIT_BREAKER_EXCLUDED_STATUS_CODES", mode="before")
    @classmethod
    def parse_cb_excluded_codes(cls, v):
        if isinstance(v, str):
            return [int(code.strip()) for code in v.split(",") if code.strip()]
        return v

    @field_validator("CIRCUIT_BREAKER_FAILURE_STATUS_CODES", mode="before")
    @classmethod
    def parse_cb_failure_codes(cls, v):
        if isinstance(v, str):
            return [int(code.strip()) for code in v.split(",") if code.strip()]
        return v


settings = Settings()