"""
OAuth схемы для аутентификации через внешних провайдеров.

Содержит Pydantic модели для:
- Запрос на логин через OAuth провайдера
- Ответ после успешного callback
- Данные OAuth state (хранятся в Redis)
- Конфигурация провайдеров
- Ответ со списком доступных провайдеров

Совместимость с тестами:
- TestOAuthProvidersEndpoint: проверяет список провайдеров в ответе
- TestOAuthLoginRedirects: проверяет редирект (302) на URL провайдера
- TestOAuthCallback: проверяет ответ с access_token, is_new_user, is_linked
- TestOAuthStateManagement: проверяет структуру state-данных
- TestOAuthEdgeCases: проверяет валидацию параметров запроса

Связанные модули:
- app.routers.oauth - OAuth роутер
- app.services.oauth_service - бизнес-логика OAuth
- app.core.config - настройки OAUTH_*
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


# ==================== ENUMS ====================

class OAuthProvider(str, Enum):
    """Поддерживаемые OAuth провайдеры."""
    GOOGLE = "google"
    VK = "vk"
    APPLE = "apple"


# ==================== REQUEST SCHEMAS ====================

class OAuthLoginRequest(BaseModel):
    """
    Параметры запроса для GET /oauth/{provider}/login.

    Используется как query parameters.
    """
    redirect_uri: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="URL для редиректа после авторизации у провайдера",
        examples=["https://example.com/auth/callback"],
    )

    @field_validator("redirect_uri")
    @classmethod
    def validate_redirect_uri(cls, v: str) -> str:
        """Проверка что redirect_uri начинается с https:// (кроме localhost)."""
        if not v.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise ValueError(
                "redirect_uri must use HTTPS or be localhost for development"
            )
        return v


class OAuthCallbackRequest(BaseModel):
    """
    Параметры запроса для GET /oauth/{provider}/callback.

    Параметры передаются провайдером в query string.
    """
    code: Optional[str] = Field(
        default=None,
        description="Authorization code от провайдера",
    )
    state: Optional[str] = Field(
        default=None,
        description="OAuth state для защиты от CSRF",
    )
    error: Optional[str] = Field(
        default=None,
        description="Ошибка от провайдера (если пользователь отклонил доступ)",
    )
    error_description: Optional[str] = Field(
        default=None,
        description="Описание ошибки от провайдера",
    )


# ==================== RESPONSE SCHEMAS ====================

class OAuthProvidersResponse(BaseModel):
    """
    Ответ со списком доступных OAuth провайдеров.

    Используется в GET /oauth/providers.
    Возвращает список или словарь доступных провайдеров.
    """
    providers: List[str] = Field(
        default_factory=list,
        description="Список ID доступных провайдеров (google, vk, apple)",
        examples=[["google", "vk", "apple"]],
    )


class OAuthRedirectResponse(BaseModel):
    """
    Ответ с URL для редиректа на страницу провайдера.

    Используется в GET /oauth/{provider}/login.
    FastAPI автоматически выполняет редирект при статусе 302.
    """
    redirect_url: str = Field(
        ...,
        description="URL для редиректа на страницу авторизации провайдера",
    )


class OAuthCallbackResponse(BaseModel):
    """
    Ответ после успешной обработки OAuth callback.

    Используется в GET /oauth/{provider}/callback.

    Совместимость с тестами:
    - test_google_callback_success_login: success=True, access_token, is_new_user=False
    - test_google_callback_new_user: is_new_user=True
    - test_google_callback_link_account: is_linked=True, message содержит "linked successfully"
    """
    success: bool = Field(
        ...,
        description="Статус операции",
    )
    access_token: Optional[str] = Field(
        default=None,
        description="JWT access token (только при логине, не при линковке)",
    )
    token_type: str = Field(
        default="bearer",
        description="Тип токена",
    )
    expires_in: int = Field(
        default=3600,
        description="Время жизни access token в секундах",
    )
    is_new_user: bool = Field(
        default=False,
        description="Флаг: пользователь создан впервые",
    )
    is_linked: bool = Field(
        default=False,
        description="Флаг: аккаунт привязан к существующему пользователю",
    )
    message: str = Field(
        default="OAuth authentication successful",
        description="Сообщение о результате операции",
    )


class OAuthLinkAccountResponse(BaseModel):
    """
    Ответ после успешной привязки OAuth аккаунта.

    Используется в GET /oauth/{provider}/callback?is_linked=true.
    """
    success: bool = Field(
        default=True,
        description="Статус операции",
    )
    is_linked: bool = Field(
        default=True,
        description="Флаг: аккаунт успешно привязан",
    )
    message: str = Field(
        default="OAuth account linked successfully",
        description="Сообщение о результате",
    )


# ==================== STATE SCHEMAS ====================

class OAuthStateData(BaseModel):
    """
    Данные, сохраняемые в Redis как OAuth state.

    Используется в create_oauth_state() и get_oauth_state().

    Совместимость с тестами:
    - test_create_oauth_state: проверяет provider, redirect_uri, code_verifier
    - test_get_oauth_state: проверяет десериализацию из Redis
    - test_google_callback_success_login: проверяет provider, code_verifier, is_linked
    - test_google_callback_link_account: проверяет is_linked=True, user_id
    """
    provider: str = Field(
        ...,
        description="ID провайдера (google, vk, apple)",
    )
    redirect_uri: str = Field(
        ...,
        description="URL для редиректа после авторизации",
    )
    code_verifier: str = Field(
        ...,
        description="PKCE code_verifier для обмена кода на токен",
    )
    scope: Optional[str] = Field(
        default=None,
        description="Запрошенные scope (области доступа)",
    )
    is_linked: bool = Field(
        default=False,
        description="Флаг: это привязка аккаунта (не логин)",
    )
    user_id: Optional[str] = Field(
        default=None,
        description="ID пользователя для привязки (только при is_linked=True)",
    )
    created_at: Optional[float] = Field(
        default=None,
        description="Timestamp создания state (для TTL)",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "provider": "google",
                "redirect_uri": "https://example.com/auth/callback",
                "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                "scope": "openid email profile",
                "is_linked": False,
                "user_id": None,
                "created_at": 1700000000.0,
            }
        }
    }


# ==================== PROVIDER CONFIG SCHEMAS ====================

class OAuthProviderConfig(BaseModel):
    """
    Конфигурация OAuth провайдера.

    Используется для проверки доступности провайдера.
    """
    provider: OAuthProvider = Field(
        ...,
        description="ID провайдера",
    )
    client_id: Optional[str] = Field(
        default=None,
        description="Client ID приложения",
    )
    auth_url: str = Field(
        ...,
        description="URL для авторизации",
    )
    token_url: str = Field(
        ...,
        description="URL для обмена кода на токен",
    )
    userinfo_url: str = Field(
        ...,
        description="URL для получения данных пользователя",
    )
    scope: str = Field(
        default="email",
        description="Области доступа",
    )
    is_configured: bool = Field(
        default=False,
        description="Флаг: провайдер настроен (client_id указан)",
    )


class OAuthProvidersConfigResponse(BaseModel):
    """
    Ответ с конфигурацией всех провайдеров.

    Используется для отладки и мониторинга.
    """
    providers: Dict[str, OAuthProviderConfig] = Field(
        default_factory=dict,
        description="Словарь провайдеров с их конфигурацией",
    )


# ==================== USER INFO SCHEMAS ====================

class OAuthUserInfo(BaseModel):
    """
    Данные пользователя, полученные от OAuth провайдера.

    Унифицированная структура для всех провайдеров.
    """
    provider: OAuthProvider = Field(
        ...,
        description="ID провайдера",
    )
    provider_user_id: str = Field(
        ...,
        description="ID пользователя у провайдера",
        alias="id",
    )
    email: Optional[str] = Field(
        default=None,
        description="Email пользователя",
    )
    name: Optional[str] = Field(
        default=None,
        description="Имя пользователя",
    )
    avatar_url: Optional[str] = Field(
        default=None,
        description="URL аватара",
    )
    raw_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Оригинальные данные от провайдера",
    )

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "example": {
                "provider": "google",
                "id": "123456789",
                "email": "user@gmail.com",
                "name": "Test User",
                "avatar_url": "https://lh3.googleusercontent.com/...",
            }
        }
    }


# ==================== ERROR RESPONSE SCHEMAS ====================

class OAuthErrorResponse(BaseModel):
    """Стандартный ответ с ошибкой OAuth."""
    detail: str = Field(
        ...,
        description="Описание ошибки",
    )
    error_code: Optional[str] = Field(
        default=None,
        description="Код ошибки для машинной обработки",
    )
    provider: Optional[str] = Field(
        default=None,
        description="Провайдер, от которого пришла ошибка",
    )


class OAuthStateNotFoundResponse(BaseModel):
    """Ответ при отсутствии OAuth state."""
    detail: str = Field(
        default="Invalid or expired OAuth state",
        description="Описание ошибки",
    )


class OAuthProviderMismatchResponse(BaseModel):
    """Ответ при несовпадении провайдера в state и callback."""
    detail: str = Field(
        default="Provider mismatch: state was created for a different provider",
        description="Описание ошибки",
    )


class OAuthUserBlockedResponse(BaseModel):
    """Ответ для заблокированного пользователя."""
    detail: str = Field(
        default="User account is blocked",
        description="Описание ошибки",
    )


# ==================== COMMON RESPONSES (для документации) ====================

COMMON_OAUTH_RESPONSES = {
    302: {
        "description": "Редирект на страницу авторизации провайдера",
    },
    400: {
        "model": OAuthErrorResponse,
        "description": "Неверный запрос (неверный state, ошибка провайдера)",
    },
    403: {
        "model": OAuthUserBlockedResponse,
        "description": "Пользователь заблокирован",
    },
    422: {
        "description": "Ошибка валидации параметров запроса",
    },
    500: {
        "model": OAuthErrorResponse,
        "description": "Внутренняя ошибка сервера",
    },
}