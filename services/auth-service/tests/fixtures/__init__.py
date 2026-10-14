"""
Фикстуры для тестирования Auth Service.

Экспортирует все фикстуры из модулей fixtures для удобного импорта в тестах.

Использование:
    from tests.fixtures import (
        user_id,
        mock_db_session,
        user_repository_mock,
        audit_log_factory,
        # ...
    )
"""

# Core фикстуры
from tests.fixtures.audit import (
    AuditLogFactory,
    AuditLogDataset,
    audit_log_factory,
    sample_audit_logs,
    sample_failed_logins,
    multi_user_audit_logs,
    date_range_audit_logs,
    create_audit_logs_batch,
    cleanup_audit_logs,
)

# JWKS фикстуры
from tests.fixtures.jwks import (
    JWKKeyFactory,
    JWKSDataset,
    JWKServiceMock,
    jwk_key_factory,
    jwks_dataset,
    rsa_key_pair,
    ec_key_pair,
    active_rsa_key,
    active_ec_key,
    inactive_rsa_key,
    expired_rsa_key,
    rotated_rsa_key,
    multiple_jwk_keys,
    jwk_service_mock,
    jwk_service_with_keys,
    jwks_response_single,
    jwks_response_multiple,
    encrypt_private_key_for_test,
    decrypt_private_key_for_test,
    setup_jwk_service_with_keys,
    cleanup_jwk_keys,
    create_jwks_key_response,
)

# OAuth фикстуры
from tests.fixtures.oauth import (
    OAuthStateFactory,
    OAuthProviderMock,
    OAuthUserProfileFactory,
    OAuthRedisMock,
    oauth_state_factory,
    oauth_provider_mock_google,
    oauth_provider_mock_vk,
    oauth_provider_mock_apple,
    oauth_user_profile_google,
    oauth_user_profile_vk,
    oauth_user_profile_apple,
    oauth_google_login_state,
    oauth_vk_login_state,
    oauth_apple_login_state,
    oauth_redis_mock,
    oauth_state_model,
    oauth_link_state_model,
    oauth_expired_state_model,
    oauth_service_mock,
    setup_oauth_state_in_redis,
    cleanup_oauth_state,
    create_oauth_callback_params,
)

# Repositories фикстуры
from tests.fixtures.repositories import (
    UserTestDataFactory,
    RefreshTokenTestDataFactory,
    JWKKeyTestDataFactory,
    UserRepositoryMock,
    RefreshTokenRepositoryMock,
    JWKKeyRepositoryMock,
    AuditLogRepositoryMock,
    mock_db_session,
    user_repository,
    user_repository_mock,
    user_security_settings_repository,
    audit_log_repository,
    audit_log_repository_mock,
    jwk_key_repository,
    jwk_key_repository_mock,
    password_reset_token_repository,
    oauth_state_repository,
    refresh_token_repository,
    refresh_token_repository_mock,
    setup_user_repository_with_users,
    setup_refresh_token_repository_with_tokens,
    setup_jwk_repository_with_keys,
    setup_audit_log_repository_with_logs,
    get_user_from_repository,
    cleanup_repository_mocks,
)

# User фикстуры (если есть отдельный файл)
from tests.fixtures.user import (
    user_id,
    another_user_id,
    sample_user,
    sample_users_list,
    user_factory,
)

__all__ = [
    # Audit
    "AuditLogFactory",
    "AuditLogDataset",
    "audit_log_factory",
    "sample_audit_logs",
    "sample_failed_logins",
    "multi_user_audit_logs",
    "date_range_audit_logs",
    "create_audit_logs_batch",
    "cleanup_audit_logs",
    
    # JWKS
    "JWKKeyFactory",
    "JWKSDataset",
    "JWKServiceMock",
    "jwk_key_factory",
    "jwks_dataset",
    "rsa_key_pair",
    "ec_key_pair",
    "active_rsa_key",
    "active_ec_key",
    "inactive_rsa_key",
    "expired_rsa_key",
    "rotated_rsa_key",
    "multiple_jwk_keys",
    "jwk_service_mock",
    "jwk_service_with_keys",
    "jwks_response_single",
    "jwks_response_multiple",
    "encrypt_private_key_for_test",
    "decrypt_private_key_for_test",
    "setup_jwk_service_with_keys",
    "cleanup_jwk_keys",
    "create_jwks_key_response",
    
    # OAuth
    "OAuthStateFactory",
    "OAuthProviderMock",
    "OAuthUserProfileFactory",
    "OAuthRedisMock",
    "oauth_state_factory",
    "oauth_provider_mock_google",
    "oauth_provider_mock_vk",
    "oauth_provider_mock_apple",
    "oauth_user_profile_google",
    "oauth_user_profile_vk",
    "oauth_user_profile_apple",
    "oauth_google_login_state",
    "oauth_vk_login_state",
    "oauth_apple_login_state",
    "oauth_redis_mock",
    "oauth_state_model",
    "oauth_link_state_model",
    "oauth_expired_state_model",
    "oauth_service_mock",
    "setup_oauth_state_in_redis",
    "cleanup_oauth_state",
    "create_oauth_callback_params",
    
    # Repositories
    "UserTestDataFactory",
    "RefreshTokenTestDataFactory",
    "JWKKeyTestDataFactory",
    "UserRepositoryMock",
    "RefreshTokenRepositoryMock",
    "JWKKeyRepositoryMock",
    "AuditLogRepositoryMock",
    "mock_db_session",
    "user_repository",
    "user_repository_mock",
    "user_security_settings_repository",
    "audit_log_repository",
    "audit_log_repository_mock",
    "jwk_key_repository",
    "jwk_key_repository_mock",
    "password_reset_token_repository",
    "oauth_state_repository",
    "refresh_token_repository",
    "refresh_token_repository_mock",
    "setup_user_repository_with_users",
    "setup_refresh_token_repository_with_tokens",
    "setup_jwk_repository_with_keys",
    "setup_audit_log_repository_with_logs",
    "get_user_from_repository",
    "cleanup_repository_mocks",
    
    # User
    "user_id",
    "another_user_id",
    "sample_user",
    "sample_users_list",
    "user_factory",
]


# ==================== КОНФИГУРАЦИЯ PYTEST ====================

def pytest_configure(config):
    """
    Автоматическая регистрация фикстур при запуске pytest.
    """
    # Маркеры для тестов
    config.addinivalue_line(
        "markers",
        "unit: Unit tests (no external dependencies)"
    )
    config.addinivalue_line(
        "markers",
        "integration: Integration tests (require database/redis)"
    )
    config.addinivalue_line(
        "markers",
        "slow: Slow tests (performance, heavy operations)"
    )
    config.addinivalue_line(
        "markers",
        "security: Security-related tests"
    )