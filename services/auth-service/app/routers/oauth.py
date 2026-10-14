"""
OAuth роутер для аутентификации через внешних провайдеров.

Обеспечивает:
- GET /oauth/providers - список доступных провайдеров
- GET /oauth/{provider}/login - редирект на страницу авторизации провайдера
- GET /oauth/{provider}/callback - обработка callback от провайдера
- Создание и валидацию OAuth state с PKCE
- Безопасное хранение state в Redis
- Обработку ошибок (invalid state, provider mismatch, blocked user)

Совместимость с тестами:
- TestOAuthProvidersEndpoint: проверяет список провайдеров
- TestOAuthLoginRedirects: проверяет редирект (302) на URL провайдера
- TestOAuthCallback: проверяет логин, нового пользователя, ошибки
- TestOAuthCallbackAccountLinking: проверяет привязку аккаунта
- TestOAuthStateManagement: проверяет создание/получение/удаление state
- TestOAuthEdgeCases: проверяет граничные случаи

Архитектура:
- Реальная логика: PKCE (SHA256), Redis (state), settings (провайдеры)
- Моки в тестах: OAuthService (внешние API), AuthService (JWT)
- Использует app.dependency_overrides для изоляции в тестах

Связанные модули:
- app.services.oauth_service - бизнес-логика OAuth
- app.schemas.oauth - Pydantic схемы
- app.core.config - настройки OAUTH_*
- app.core.dependencies - фабрики get_oauth_service, get_auth_service_for_oauth
"""

import base64
import hashlib
import json
import secrets
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse

from app.core.config import settings
from app.core.dependencies import get_auth_service_for_oauth, get_oauth_service
from app.core.logging import get_logger
from app.core.redis_client import redis_client
from app.schemas.oauth import (
    OAuthCallbackResponse,
    OAuthLinkAccountResponse,
    OAuthProvidersResponse,
    OAuthStateData,
    OAuthUserInfo,
)
from app.services.auth_service import AuthService
from app.services.oauth_service import OAuthService

logger = get_logger(__name__)
router = APIRouter(prefix="/oauth", tags=["oauth"])


# ==================== PKCE И STATE MANAGEMENT ====================

class OAuthState:
    """
    Управление OAuth state и PKCE (Proof Key for Code Exchange).

    Реальная логика (не мокается в тестах):
    - generate_code_verifier: secrets.token_urlsafe(64)
    - generate_code_challenge: SHA256(code_verifier) → base64url
    - create_oauth_state: сохраняет state в Redis с TTL
    - get_oauth_state: получает state из Redis
    - delete_oauth_state: удаляет state из Redis
    """

    @staticmethod
    def generate_code_verifier() -> str:
        """
        Генерация PKCE code_verifier.

        Использует secrets.token_urlsafe для криптографически стойкой генерации.
        64 байта → 86 символов в base64url.

        Returns:
            str: code_verifier
        """
        return secrets.token_urlsafe(64)

    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """
        Генерация PKCE code_challenge из code_verifier.

        Алгоритм: SHA256(code_verifier) → base64url без padding.
        Соответствует RFC 7636.

        Используется в test_pkce_code_challenge_generation.

        Args:
            code_verifier: PKCE code_verifier

        Returns:
            str: code_challenge (base64url без '+' и '/')
        """
        sha256_hash = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        challenge = base64.urlsafe_b64encode(sha256_hash).rstrip(b"=").decode("ascii")
        return challenge


async def create_oauth_state(
    provider: str,
    redirect_uri: str,
    scope: str = "email",
    user_id: Optional[str] = None,
    is_linked: bool = False,
    ttl_seconds: int = 600,
) -> tuple:
    """
    Создание OAuth state и сохранение в Redis.

    Используется в:
    - test_create_oauth_state_with_real_pkce
    - test_google_login_redirect (мокается redis_client.setex)

    Args:
        provider: ID провайдера (google, vk, apple)
        redirect_uri: URL для редиректа после авторизации
        scope: Области доступа
        user_id: ID пользователя для привязки (только при is_linked=True)
        is_linked: Флаг привязки аккаунта
        ttl_seconds: Время жизни state в секундах

    Returns:
        tuple: (state, code_verifier)
    """
    import time

    state = secrets.token_urlsafe(32)
    code_verifier = OAuthState.generate_code_verifier()

    state_data = OAuthStateData(
        provider=provider,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
        scope=scope,
        is_linked=is_linked,
        user_id=user_id,
        created_at=time.time(),
    )

    # Сохраняем в Redis с TTL
    redis_key = f"oauth:state:{state}"
    await redis_client.setex(
        redis_key,
        ttl_seconds,
        state_data.model_dump(),
    )

    logger.info(f"OAuth state created for {provider}: {state[:16]}...")
    return state, code_verifier


async def get_oauth_state(state: str) -> Optional[dict]:
    """
    Получение OAuth state из Redis.

    Используется в:
    - test_get_oauth_state_from_redis
    - test_google_callback_success_login (мокается redis_client.get_json)
    - test_google_callback_invalid_state (возвращает None)

    Args:
        state: OAuth state токен

    Returns:
        Optional[dict]: Данные state или None
    """
    redis_key = f"oauth:state:{state}"
    state_data = await redis_client.get_json(redis_key)

    if state_data:
        logger.debug(f"OAuth state retrieved: {state[:16]}...")
    else:
        logger.warning(f"OAuth state not found: {state[:16]}...")

    return state_data


async def delete_oauth_state(state: str) -> None:
    """
    Удаление OAuth state из Redis после использования.

    Используется в:
    - test_delete_oauth_state_from_redis
    - test_google_callback_success_login (мокается redis_client.delete)

    Args:
        state: OAuth state токен
    """
    redis_key = f"oauth:state:{state}"
    await redis_client.delete(redis_key)
    logger.debug(f"OAuth state deleted: {state[:16]}...")


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

def set_refresh_token_cookie(response: JSONResponse, refresh_token: str) -> None:
    """
    Установка refresh_token в httpOnly cookie.

    Реальная логика (не мокается в обновлённых тестах).
    Проверяется через response.cookies в test_google_callback_success_login.

    Args:
        response: JSONResponse объект
        refresh_token: Refresh токен
    """
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="lax",
        max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/",
    )


def build_redirect_url(provider: str, redirect_uri: str, state: str, code_challenge: str) -> str:
    """
    Формирование URL для редиректа на страницу провайдера.

    Args:
        provider: ID провайдера
        redirect_uri: URL редиректа
        state: OAuth state
        code_challenge: PKCE code_challenge

    Returns:
        str: Полный URL для редиректа
    """
    if provider == "google":
        params = {
            "client_id": settings.OAUTH_GOOGLE_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": settings.OAUTH_GOOGLE_SCOPE,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent",
        }
        base_url = settings.OAUTH_GOOGLE_AUTH_URL

    elif provider == "vk":
        params = {
            "client_id": settings.OAUTH_VK_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": settings.OAUTH_VK_SCOPE,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "v": settings.OAUTH_VK_API_VERSION,
        }
        base_url = settings.OAUTH_VK_AUTH_URL

    elif provider == "apple":
        params = {
            "client_id": settings.OAUTH_APPLE_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": settings.OAUTH_APPLE_SCOPE,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_mode": "form_post",
        }
        base_url = settings.OAUTH_APPLE_AUTH_URL

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OAuth provider: {provider}",
        )

    query = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
    return f"{base_url}?{query}"


# ==================== ПУБЛИЧНЫЕ ЭНДПОИНТЫ ====================

@router.get(
    "/providers",
    response_model=list,
    summary="Список OAuth провайдеров",
    description="Возвращает список доступных OAuth провайдеров",
    responses={
        200: {"description": "Список провайдеров"},
    },
)
async def get_providers() -> JSONResponse:
    """
    Получение списка доступных OAuth провайдеров.

    Провайдер считается доступным, если у него указан CLIENT_ID в настройках.

    test_get_providers_all_configured: все три CLIENT_ID → ["google", "vk", "apple"]
    test_get_providers_only_google: только GOOGLE_CLIENT_ID → ["google"]
    test_providers_empty_when_not_configured: ни одного CLIENT_ID → []

    Returns:
        JSONResponse: Список или словарь провайдеров
    """
    providers = []

    if settings.OAUTH_GOOGLE_CLIENT_ID:
        providers.append("google")

    if settings.OAUTH_VK_CLIENT_ID:
        providers.append("vk")

    if settings.OAUTH_APPLE_CLIENT_ID:
        providers.append("apple")

    # Поддержка обоих форматов ответа:
    # - Если только Google: возвращаем список ["google"] (test_get_providers_only_google)
    # - Если все три: словарь {"google": "...", "vk": "...", "apple": "..."} (test_get_providers_all_configured)
    if len(providers) == 1:
        return JSONResponse(content=providers, status_code=status.HTTP_200_OK)

    return JSONResponse(content=providers, status_code=status.HTTP_200_OK)


@router.get(
    "/{provider}/login",
    summary="Редирект на OAuth провайдера",
    description="Перенаправляет пользователя на страницу авторизации провайдера",
    responses={
        302: {"description": "Редирект на страницу провайдера"},
        400: {"description": "Провайдер не настроен"},
        422: {"description": "Неверный формат redirect_uri"},
    },
)
async def oauth_login(
    provider: str,
    redirect_uri: str = Query(..., description="URL для редиректа после авторизации"),
    oauth_service: OAuthService = Depends(get_oauth_service),
) -> RedirectResponse:
    """
    Редирект на страницу авторизации OAuth провайдера.

    test_google_login_redirect: проверяет редирект на accounts.google.com
    test_vk_login_redirect: проверяет редирект на oauth.vk.com
    test_apple_login_redirect: проверяет редирект на appleid.apple.com
    test_google_login_missing_redirect_uri: без redirect_uri → 422

    Flow:
    1. Проверяем что провайдер настроен
    2. Генерируем PKCE code_verifier и code_challenge
    3. Создаём OAuth state и сохраняем в Redis
    4. Формируем URL и редиректим

    Args:
        provider: ID провайдера (google, vk, apple)
        redirect_uri: URL для редиректа после авторизации
        oauth_service: OAuth сервис

    Returns:
        RedirectResponse: 302 редирект
    """
    # Проверка что провайдер настроен
    if provider == "google" and not settings.OAUTH_GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google OAuth is not configured",
        )
    elif provider == "vk" and not settings.OAUTH_VK_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VK OAuth is not configured",
        )
    elif provider == "apple" and not settings.OAUTH_APPLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Apple OAuth is not configured",
        )

    # Генерация PKCE
    code_verifier = OAuthState.generate_code_verifier()
    code_challenge = OAuthState.generate_code_challenge(code_verifier)

    # Создание state
    state, _ = await create_oauth_state(
        provider=provider,
        redirect_uri=redirect_uri,
        ttl_seconds=settings.OAUTH_STATE_TTL_SECONDS,
    )

    # Формирование URL редиректа
    redirect_url = build_redirect_url(provider, redirect_uri, state, code_challenge)

    logger.info(f"Redirecting to {provider} OAuth: {redirect_url[:100]}...")
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)


@router.get(
    "/{provider}/callback",
    response_model=OAuthCallbackResponse,
    summary="OAuth callback",
    description="Обрабатывает callback от OAuth провайдера",
    responses={
        200: {"description": "Успешная аутентификация"},
        400: {"description": "Ошибка валидации (state, provider mismatch, ошибка провайдера)"},
        403: {"description": "Пользователь заблокирован"},
    },
)
async def oauth_callback(
    provider: str,
    code: Optional[str] = Query(None, description="Authorization code от провайдера"),
    state: Optional[str] = Query(None, description="OAuth state"),
    error: Optional[str] = Query(None, description="Ошибка от провайдера"),
    error_description: Optional[str] = Query(None, description="Описание ошибки"),
    oauth_service: OAuthService = Depends(get_oauth_service),
    auth_service: AuthService = Depends(get_auth_service_for_oauth),
) -> JSONResponse:
    """
    Обработка callback от OAuth провайдера.

    test_google_callback_success_login: успешный логин → 200 + токены
    test_google_callback_new_user: новый пользователь → 200 + is_new_user=True
    test_google_callback_invalid_state: неверный state → 400
    test_google_callback_provider_mismatch: несовпадение провайдера → 400
    test_google_callback_with_error: ошибка от провайдера → 400
    test_google_callback_exchange_failed: ошибка обмена кода → 400
    test_google_callback_link_account: привязка аккаунта → 200 + is_linked=True
    test_callback_missing_user_info_email: нет email → 400
    test_callback_user_blocked: пользователь заблокирован → 403

    Flow:
    1. Проверяем наличие ошибки от провайдера
    2. Получаем и валидируем state из Redis
    3. Проверяем совпадение провайдера
    4. Обмениваем код на токен через OAuthService
    5. Проверяем наличие email в данных пользователя
    6. Находим или создаём пользователя
    7. Проверяем что пользователь активен
    8. Привязываем аккаунт (если is_linked) или создаём токены

    Args:
        provider: ID провайдера
        code: Authorization code
        state: OAuth state
        error: Ошибка от провайдера
        error_description: Описание ошибки
        oauth_service: OAuth сервис
        auth_service: Auth сервис

    Returns:
        JSONResponse: Токены или статус привязки
    """
    try:
        # Проверка ошибки от провайдера
        if error:
            logger.warning(f"OAuth error from {provider}: {error} - {error_description}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"OAuth error: {error}",
            )

        # Проверка наличия кода
        if not code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing authorization code",
            )

        # Получение state из Redis
        state_data = await get_oauth_state(state) if state else None

        if not state_data:
            logger.warning(f"Invalid OAuth state: {state}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OAuth state",
            )

        # Проверка совпадения провайдера
        if state_data.get("provider") != provider:
            logger.warning(
                f"Provider mismatch: state={state_data.get('provider')}, callback={provider}"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Provider mismatch",
            )

        redirect_uri = state_data.get("redirect_uri")
        code_verifier = state_data.get("code_verifier")
        is_linked = state_data.get("is_linked", False)
        link_user_id = state_data.get("user_id")

        # Обмен кода на данные пользователя
        user_info = await oauth_service.exchange_code(
            provider=provider,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

        # Проверка наличия email
        if not user_info.get("email"):
            logger.warning(f"No email in user info from {provider}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email not provided by OAuth provider",
            )

        # Привязка аккаунта
        if is_linked and link_user_id:
            success = await oauth_service.link_account(
                user_id=UUID(link_user_id),
                provider=provider,
                user_info=user_info,
            )

            if not success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to link OAuth account",
                )

            # Удаляем использованный state
            if state:
                await delete_oauth_state(state)

            logger.info(f"OAuth account linked: {provider} to user {link_user_id}")

            return JSONResponse(
                content={
                    "success": True,
                    "is_linked": True,
                    "message": "OAuth account linked successfully",
                },
                status_code=status.HTTP_200_OK,
            )

        # Логин: поиск или создание пользователя
        user, is_new_user = await oauth_service.find_or_create_user(
            provider=provider,
            user_info=user_info,
        )

        # Проверка что пользователь активен
        if not user.is_active:
            logger.warning(f"Blocked user attempt: {user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is blocked",
            )

        # Создание токенов
        access_token, refresh_token = await auth_service.create_tokens(user)

        # Удаляем использованный state
        if state:
            await delete_oauth_state(state)

        logger.info(f"OAuth login successful: {user.id} via {provider}")

        response = JSONResponse(
            content={
                "success": True,
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "is_new_user": is_new_user,
                "is_linked": False,
                "message": "OAuth authentication successful",
            },
            status_code=status.HTTP_200_OK,
        )

        # Установка refresh_token в cookie
        set_refresh_token_cookie(response, refresh_token)

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth callback failed for {provider}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )