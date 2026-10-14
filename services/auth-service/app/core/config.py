"""
Конфигурация приложения.

Загружает настройки из переменных окружения.
Поддерживает переопределение через .env файл.

Совместимость с тестами:
- OAuth: OAUTH_GOOGLE_CLIENT_ID, OAUTH_VK_CLIENT_ID, OAUTH_APPLE_CLIENT_ID и др.
- Password: PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH, PASSWORD_RESET_TOKEN_EXPIRE_MINUTES,
  PASSWORD_RESET_RATE_LIMIT, PASSWORD_CHANGE_RATE_LIMIT, PASSWORD_BCRYPT_ROUNDS
- Все параметры имеют префикс PASSWORD_*
"""

import os
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Настройки приложения."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        validate_default=True,
    )
    
    # ==================== ОБЩИЕ НАСТРОЙКИ ====================
    APP_NAME: str = "Auth Service"
    APP_VERSION: str = "1.0.0"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", pattern="^(development|staging|production)$")
    DEBUG: bool = False
    
    # ==================== СЕРВЕР ====================
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    RELOAD: bool = False
    WORKERS: int = 1
    
    # ==================== БАЗА ДАННЫХ ====================
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/auth"
    DB_ECHO: bool = False
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 3600
    DB_POOL_PRE_PING: bool = True
    DB_POOL_DISABLED: bool = False
    DB_ISOLATION_LEVEL: Optional[str] = None
    
    # ==================== REDIS ====================
    REDIS_URL: str = "redis://auth-redis:6379/0"
    REDIS_MAX_CONNECTIONS: int = 10
    REDIS_CONNECT_TIMEOUT: int = 5
    REDIS_TIMEOUT: int = 5
    SESSION_TTL: int = 86400  # 24 часа
    
    # ==================== KAFKA ====================
    KAFKA_ENABLED: bool = True
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_CONSUMER_GROUP: str = "auth-service"
    KAFKA_AUTO_OFFSET_RESET: str = "earliest"
    KAFKA_ENABLE_AUTO_COMMIT: bool = False
    KAFKA_USE_SSL: bool = False
    KAFKA_ACKS: int = -1
    KAFKA_RETRIES: int = 3
    KAFKA_MAX_BATCH_SIZE: int = 16384
    KAFKA_LINGER_MS: int = 0
    KAFKA_BUFFER_MEMORY: int = 33554432
    KAFKA_COMPRESSION_TYPE: Optional[str] = None
    KAFKA_MAX_REQUEST_SIZE: int = 1048576
    KAFKA_RETRY_BACKOFF_MS: int = 100
    KAFKA_REQUEST_TIMEOUT_MS: int = 30000
    KAFKA_METADATA_MAX_AGE_MS: int = 300000
    KAFKA_SECURITY_PROTOCOL: str = "PLAINTEXT"
    KAFKA_SASL_MECHANISM: Optional[str] = None
    KAFKA_SASL_USERNAME: Optional[str] = None
    KAFKA_SASL_PASSWORD: Optional[str] = None
    KAFKA_SSL_CAFILE: Optional[str] = None
    KAFKA_SSL_CERTFILE: Optional[str] = None
    KAFKA_SSL_KEYFILE: Optional[str] = None
    KAFKA_SSL_PASSWORD: Optional[str] = None
    KAFKA_ENABLE_IDEMPOTENCE: bool = True
    KAFKA_MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION: int = 5
    KAFKA_REQUEUE_MAX_RETRIES: int = 3
    KAFKA_TOPIC_AUTH_EVENTS: str = "auth-events"
    KAFKA_TOPIC_USER_EVENTS: str = "user-events"
    KAFKA_TOPIC_AUDIT_LOGS: str = "audit-logs"
    KAFKA_PARTITIONS: int = 3
    KAFKA_REPLICATION_FACTOR: int = 1
    
    # ==================== KAFKA PRODUCER ====================
    KAFKA_PRODUCER_ACKS: str = "all"
    KAFKA_PRODUCER_MAX_BATCH_SIZE: int = 16384
    KAFKA_PRODUCER_LINGER_MS: int = 10
    KAFKA_PRODUCER_COMPRESSION_TYPE: str = "snappy"
    OTP_TTL_SECONDS: int = 300
    
    # ==================== JWT ====================
    JWT_SECRET_KEY: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    JWT_BLACKLIST_TTL_MINUTES: int = 15
    
    JWT_PRIVATE_KEY: str = ""
    JWT_PUBLIC_KEY: str = ""
    
    # ==================== БЕЗОПАСНОСТЬ ====================
    SECRET_PEPPER: str = "your-pepper-change-in-production"
    ENCRYPTION_KEY: Optional[str] = None
    
    # ==================== PASSWORD НАСТРОЙКИ ====================
    # Совместимость с тестами:
    # - TestChangePassword: PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH для валидации new_password
    # - TestResetPasswordRequest: PASSWORD_RESET_TOKEN_EXPIRE_MINUTES, PASSWORD_RESET_RATE_LIMIT
    # - TestResetPasswordConfirm: PASSWORD_RESET_TOKEN_LENGTH для валидации формата токена
    
    PASSWORD_MIN_LENGTH: int = Field(
        default=8,
        description="Минимальная длина пароля",
        ge=6,
        le=256,
    )
    PASSWORD_MAX_LENGTH: int = Field(
        default=128,
        description="Максимальная длина пароля",
        ge=8,
        le=512,
    )
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(
        default=True,
        description="Требовать заглавные буквы в пароле",
    )
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(
        default=True,
        description="Требовать строчные буквы в пароле",
    )
    PASSWORD_REQUIRE_DIGITS: bool = Field(
        default=True,
        description="Требовать цифры в пароле",
    )
    PASSWORD_REQUIRE_SPECIAL_CHARS: bool = Field(
        default=True,
        description="Требовать спецсимволы в пароле",
    )
    PASSWORD_BCRYPT_ROUNDS: int = Field(
        default=12,
        description="Количество раундов bcrypt для хеширования паролей",
        ge=4,
        le=31,
    )
    
    # Настройки сброса пароля
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = Field(
        default=60,
        description="Время жизни токена сброса пароля в минутах",
        ge=5,
        le=1440,
    )
    PASSWORD_RESET_TOKEN_LENGTH: int = Field(
        default=32,
        description="Длина токена сброса пароля в символах",
        ge=16,
        le=128,
    )
    PASSWORD_RESET_RATE_LIMIT: int = Field(
        default=3,
        description="Максимальное количество запросов сброса пароля в окне",
        ge=1,
        le=100,
    )
    PASSWORD_RESET_RATE_LIMIT_WINDOW: int = Field(
        default=600,
        description="Временное окно для rate limit сброса пароля в секундах",
        ge=60,
        le=3600,
    )
    
    # Настройки смены пароля
    PASSWORD_CHANGE_RATE_LIMIT: int = Field(
        default=5,
        description="Максимальное количество попыток смены пароля в окне",
        ge=1,
        le=100,
    )
    PASSWORD_CHANGE_RATE_LIMIT_WINDOW: int = Field(
        default=60,
        description="Временное окно для rate limit смены пароля в секундах",
        ge=30,
        le=3600,
    )
    PASSWORD_CONFIRM_RATE_LIMIT: int = Field(
        default=10,
        description="Максимальное количество попыток подтверждения сброса в окне",
        ge=1,
        le=100,
    )
    PASSWORD_CONFIRM_RATE_LIMIT_WINDOW: int = Field(
        default=60,
        description="Временное окно для rate limit подтверждения сброса в секундах",
        ge=30,
        le=3600,
    )
    
    # Настройки истории паролей
    PASSWORD_HISTORY_SIZE: int = Field(
        default=5,
        description="Количество предыдущих паролей, которые нельзя использовать повторно",
        ge=0,
        le=50,
    )
    PASSWORD_REUSE_PREVENTION_ENABLED: bool = Field(
        default=True,
        description="Запретить повторное использование предыдущих паролей",
    )
    
    # ==================== VAULT ====================
    VAULT_ADDR: str = "http://vault:8200"
    VAULT_URL: str = "http://vault:8200"
    VAULT_NAMESPACE: Optional[str] = None
    VAULT_TOKEN: Optional[str] = None
    VAULT_ROLE_ID: Optional[str] = None
    VAULT_SECRET_ID: Optional[str] = None
    VAULT_MOUNT_POINT: str = "secret"
    VAULT_ENGINE_VERSION: int = 2
    VAULT_CACHE_TTL: int = 60
    VAULT_TIMEOUT: int = 30
    VAULT_CONNECT_TIMEOUT: int = 10
    VAULT_MAX_CONNECTIONS: int = 10
    VAULT_DB_PATH: str = "secret/data/database"
    VAULT_REDIS_PATH: str = "secret/data/redis"
    VAULT_KAFKA_PATH: str = "secret/data/kafka"
    VAULT_OAUTH_PATH: str = "secret/data/oauth"
    VAULT_AUTH_METHOD: str = Field(
        default="token",
        description="Метод аутентификации Vault (token, approle, kubernetes, ldap)",
        pattern="^(token|approle|kubernetes|ldap)$",
    )
    VAULT_SECRET_PATH: str = Field(
        default="secret/data/auth",
        description="Путь к секретам в Vault",
    )
    
    # ==================== JWKS ====================
    JWKS_ROTATION_INTERVAL_HOURS: int = 24
    JWKS_KEY_SIZE: int = 2048
    JWKS_KEY_ALGORITHM: str = "RS256"
    JWKS_MAX_KEYS: int = 10
    
    # ==================== CORS ====================
    CORS_ALLOWED_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="Разрешенные источники для CORS"
    )
    CORS_ALLOWED_METHODS: List[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        description="Разрешенные HTTP методы для CORS"
    )
    CORS_ALLOWED_HEADERS: List[str] = Field(
        default=["Authorization", "Content-Type", "X-Request-ID", "X-User-ID", "X-Trace-Id", "Idempotency-Key"],
        description="Разрешенные заголовки для CORS"
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(
        default=True,
        description="Разрешить передачу credentials через CORS"
    )
    CORS_MAX_AGE: int = Field(
        default=3600,
        description="Максимальное время кэширования CORS preflight"
    )
    
    # ==================== RATE LIMITING ====================
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_ADMIN: str = "50/minute"
    
    # ==================== LOGGING ====================
    LOG_LEVEL: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    LOG_FORMAT: str = "json"
    LOG_STDOUT: bool = True
    LOG_PII_MASKING_ENABLED: bool = True
    SERVICE_NAME: str = "auth-service"
    
    # ==================== HEALTHCHECK ====================
    HEALTH_CHECK_INTERVAL: int = 30
    HEALTH_CHECK_TIMEOUT: int = 5
    
    # ==================== ТЕСТЫ ====================
    TEST_DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/auth_test"
    TEST_REDIS_URL: str = "redis://auth-redis:6379/1"
    TEST_KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    
    # ==================== МЕТРИКИ ====================
    METRICS_ENABLED: bool = True
    METRICS_PORT: int = 9090
    
    # ==================== GRPC ====================
    USER_SERVICE_GRPC_URL: str = Field(
        default="",
        description="URL User Service gRPC (host:port)",
        examples=["user-service:50051", "localhost:50051"],
    )
    
    PROFILE_SERVICE_GRPC_URL: str = Field(
        default="",
        description="URL Profile Service gRPC (host:port)",
        examples=["profile-service:50052", "localhost:50052"],
    )
    
    GRPC_TIMEOUT_SECONDS: int = Field(
        default=5,
        description="Таймаут gRPC вызовов в секундах",
        ge=1,
        le=60,
    )
    
    # ==================== INTERNAL API ====================
    INTERNAL_API_KEY: str = Field(
        default="test_api_key",
        description="Internal API ключ для межсервисного взаимодействия",
        min_length=1,
    )
    
    INTERNAL_ALLOWED_IPS: List[str] = Field(
        default=["127.0.0.1", "::1", "172.19.0.0/16"],
        description="Список разрешенных IP адресов для Internal API",
    )
    
    INTERNAL_ENABLED: bool = Field(
        default=True,
        description="Включить Internal API",
    )
    
    INTERNAL_RATE_LIMIT_ENABLED: bool = Field(
        default=True,
        description="Включить rate limiting для Internal API",
    )
    
    INTERNAL_RATE_LIMIT_REQUESTS: int = Field(
        default=100,
        description="Максимальное количество запросов к Internal API в минуту",
        ge=1,
        le=10000,
    )
    
    INTERNAL_RATE_LIMIT_WINDOW: int = Field(
        default=60,
        description="Временное окно для rate limiting в секундах",
        ge=1,
        le=3600,
    )
    
    # ==================== НОВЫЕ ПОЛЯ ====================
    
    PRODUCTION_MODE: bool = Field(
        default=False,
        description="Режим продакшена (маскирует детали ошибок)",
    )

    # ==================== OAUTH НАСТРОЙКИ ====================
    # Google OAuth 2.0
    OAUTH_GOOGLE_CLIENT_ID: Optional[str] = Field(default=None, description="Google OAuth Client ID")
    OAUTH_GOOGLE_CLIENT_SECRET: Optional[str] = Field(default=None, description="Google OAuth Client Secret")
    OAUTH_GOOGLE_AUTH_URL: str = Field(default="https://accounts.google.com/o/oauth2/v2/auth", description="Google OAuth Authorization URL")
    OAUTH_GOOGLE_TOKEN_URL: str = Field(default="https://oauth2.googleapis.com/token", description="Google OAuth Token Exchange URL")
    OAUTH_GOOGLE_USERINFO_URL: str = Field(default="https://www.googleapis.com/oauth2/v3/userinfo", description="Google OAuth UserInfo URL")
    OAUTH_GOOGLE_SCOPE: str = Field(default="openid email profile", description="Google OAuth Scopes")

    # VK OAuth 2.0
    OAUTH_VK_CLIENT_ID: Optional[str] = Field(default=None, description="VK OAuth Client ID")
    OAUTH_VK_CLIENT_SECRET: Optional[str] = Field(default=None, description="VK OAuth Client Secret")
    OAUTH_VK_AUTH_URL: str = Field(default="https://oauth.vk.com/authorize", description="VK OAuth Authorization URL")
    OAUTH_VK_TOKEN_URL: str = Field(default="https://oauth.vk.com/access_token", description="VK OAuth Token Exchange URL")
    OAUTH_VK_USERINFO_URL: str = Field(default="https://api.vk.com/method/users.get", description="VK OAuth UserInfo URL")
    OAUTH_VK_SCOPE: str = Field(default="email", description="VK OAuth Scopes")
    OAUTH_VK_API_VERSION: str = Field(default="5.131", description="VK API Version")

    # Apple OAuth 2.0
    OAUTH_APPLE_CLIENT_ID: Optional[str] = Field(default=None, description="Apple OAuth Client ID (Service ID)")
    OAUTH_APPLE_CLIENT_SECRET: Optional[str] = Field(default=None, description="Apple OAuth Client Secret")
    OAUTH_APPLE_TEAM_ID: Optional[str] = Field(default=None, description="Apple Developer Team ID")
    OAUTH_APPLE_KEY_ID: Optional[str] = Field(default=None, description="Apple Private Key ID")
    OAUTH_APPLE_PRIVATE_KEY: Optional[str] = Field(default=None, description="Apple Private Key (PEM format)")
    OAUTH_APPLE_AUTH_URL: str = Field(default="https://appleid.apple.com/auth/authorize", description="Apple OAuth Authorization URL")
    OAUTH_APPLE_TOKEN_URL: str = Field(default="https://appleid.apple.com/auth/token", description="Apple OAuth Token Exchange URL")
    OAUTH_APPLE_SCOPE: str = Field(default="name email", description="Apple OAuth Scopes")

    # Общие настройки OAuth
    OAUTH_STATE_TTL_SECONDS: int = Field(default=600, description="Время жизни OAuth state в секундах", ge=60, le=3600)
    OAUTH_REDIRECT_URI_WHITELIST: List[str] = Field(default=["http://localhost:3000", "http://localhost:8000"], description="Список разрешенных redirect_uri")
    OAUTH_DEFAULT_REDIRECT_URI: str = Field(default="http://localhost:3000/auth/callback", description="Redirect URI по умолчанию")
    
    # ==================== СВОЙСТВА ====================
    @property
    def jwt_secret_key(self) -> str:
        return self.JWT_SECRET_KEY
    
    @property
    def jwt_algorithm(self) -> str:
        return self.JWT_ALGORITHM
    
    @property
    def access_token_expire_minutes(self) -> int:
        return self.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    
    @property
    def refresh_token_expire_days(self) -> int:
        return self.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    
    @property
    def jwt_blacklist_ttl_minutes(self) -> int:
        return self.JWT_BLACKLIST_TTL_MINUTES

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"
    
    @property
    def is_staging(self) -> bool:
        return self.ENVIRONMENT == "staging"
    
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"
    
    @property
    def is_debug(self) -> bool:
        return self.DEBUG or self.ENVIRONMENT == "development"
    
    @property
    def database_url_async(self) -> str:
        return self.DATABASE_URL
    
    @property
    def database_url_sync(self) -> str:
        return self.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")

    @field_validator("CORS_ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v
    
    @field_validator("CORS_ALLOWED_METHODS", mode="before")
    @classmethod
    def parse_cors_methods(cls, v):
        if isinstance(v, str):
            return [method.strip().upper() for method in v.split(",") if method.strip()]
        return v
    
    @field_validator("CORS_ALLOWED_HEADERS", mode="before")
    @classmethod
    def parse_cors_headers(cls, v):
        if isinstance(v, str):
            return [header.strip() for header in v.split(",") if header.strip()]
        return v

    @field_validator("INTERNAL_ALLOWED_IPS", mode="before")
    @classmethod
    def parse_internal_ips(cls, v):
        if isinstance(v, str):
            return [ip.strip() for ip in v.split(",") if ip.strip()]
        return v

    @field_validator("OAUTH_REDIRECT_URI_WHITELIST", mode="before")
    @classmethod
    def parse_oauth_redirect_uris(cls, v):
        if isinstance(v, str):
            return [uri.strip() for uri in v.split(",") if uri.strip()]
        return v


settings = Settings()


def get_settings() -> Settings:
    return settings


def reload_settings() -> Settings:
    return Settings()