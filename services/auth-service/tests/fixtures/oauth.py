"""
Фикстуры для тестирования OAuth2 функциональности.

Предоставляет:
- Фикстуры OAuth state и PKCE параметров (code_verifier, code_challenge)
- Моки ответов Google/VK/Apple API
- Тестовые профили пользователей от провайдеров
- Моки успешных и ошибочных callback'ов
- OAuth сессии в Redis
- OAuthState модели для тестирования
"""

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_state import OAuthState
from app.services.oauth_service import OAuthService


class OAuthStateFactory:
    """
    Фабрика для создания тестовых OAuthState записей.
    """
    
    @staticmethod
    def generate_state() -> str:
        """Генерация тестового state."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_code_verifier() -> str:
        """Генерация тестового code_verifier."""
        return secrets.token_urlsafe(64)[:128]
    
    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """Генерация code_challenge из code_verifier (S256)."""
        digest = hashlib.sha256(code_verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().replace('=', '')
    
    @staticmethod
    def create_oauth_state(
        provider: str = "google",
        redirect_uri: str = "https://example.com/callback",
        scope: str | None = "email profile",
        user_id: UUID | None = None,
        is_linked: bool = False,
        ttl_seconds: int = 600,
    ) -> tuple[OAuthState, str, str]:
        """
        Создание OAuthState записи.
        Возвращает (модель, state, code_verifier)
        """
        state = OAuthStateFactory.generate_state()
        code_verifier = OAuthStateFactory.generate_code_verifier()
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        
        oauth_state = OAuthState(
            state=state,
            code_verifier=code_verifier,
            provider=provider,
            redirect_uri=redirect_uri,
            scope=scope,
            user_id=user_id,
            is_linked=is_linked,
            expires_at=expires_at,
        )
        
        return oauth_state, state, code_verifier
    
    @staticmethod
    def create_login_state(
        provider: str = "google",
        redirect_uri: str = "https://example.com/callback",
        scope: str | None = "email profile",
        ttl_seconds: int = 600,
    ) -> tuple[OAuthState, str, str]:
        """Создание state для входа."""
        return OAuthStateFactory.create_oauth_state(
            provider=provider,
            redirect_uri=redirect_uri,
            scope=scope,
            is_linked=False,
            ttl_seconds=ttl_seconds,
        )
    
    @staticmethod
    def create_link_state(
        provider: str = "google",
        redirect_uri: str = "https://example.com/callback",
        user_id: UUID | None = None,
        scope: str | None = "email profile",
        ttl_seconds: int = 600,
    ) -> tuple[OAuthState, str, str]:
        """Создание state для привязки аккаунта."""
        return OAuthStateFactory.create_oauth_state(
            provider=provider,
            redirect_uri=redirect_uri,
            scope=scope,
            user_id=user_id or uuid4(),
            is_linked=True,
            ttl_seconds=ttl_seconds,
        )
    
    @staticmethod
    def create_expired_state(
        provider: str = "google",
        ttl_seconds: int = -3600,
    ) -> tuple[OAuthState, str, str]:
        """Создание просроченного state."""
        state = OAuthStateFactory.generate_state()
        code_verifier = OAuthStateFactory.generate_code_verifier()
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        
        oauth_state = OAuthState(
            state=state,
            code_verifier=code_verifier,
            provider=provider,
            redirect_uri="https://example.com/callback",
            scope="email",
            is_linked=False,
            expires_at=expires_at,
        )
        
        return oauth_state, state, code_verifier


class OAuthProviderMock:
    """
    Мок для OAuth провайдера с предопределёнными ответами.
    """
    
    def __init__(self, provider: str):
        self.provider = provider
        self.token_response = None
        self.userinfo_response = None
        self.should_fail = False
        self.error_code = None
        self.error_description = None
    
    def set_success_response(
        self,
        access_token: str = "test_access_token",
        refresh_token: str = "test_refresh_token",
        user_id: str = "123456789",
        email: str = "user@example.com",
        name: str = "Test User",
        first_name: str = "Test",
        last_name: str = "User",
        avatar_url: str | None = None,
        is_verified: bool = True,
    ) -> None:
        """Настройка успешного ответа от провайдера."""
        if self.provider == "google":
            self.token_response = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": 3600,
            }
            self.userinfo_response = {
                "id": user_id,
                "email": email,
                "name": name,
                "given_name": first_name,
                "family_name": last_name,
                "picture": avatar_url,
                "verified_email": is_verified,
            }
        elif self.provider == "vk":
            self.token_response = {
                "access_token": access_token,
                "user_id": int(user_id),
                "email": email,
            }
            self.userinfo_response = {
                "response": [{
                    "first_name": first_name,
                    "last_name": last_name,
                    "photo_max": avatar_url,
                }]
            }
        elif self.provider == "apple":
            import jwt
            id_token = jwt.encode(
                {"sub": user_id, "email": email},
                "secret",
                algorithm="HS256",
            )
            self.token_response = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": id_token,
                "expires_in": 3600,
            }
            self.userinfo_response = None
    
    def set_error_response(
        self,
        error_code: str = "access_denied",
        error_description: str = "User denied access",
    ) -> None:
        """Настройка ошибочного ответа от провайдера."""
        self.should_fail = True
        self.error_code = error_code
        self.error_description = error_description
    
    def get_mock_http_client(self):
        """Получение мока HTTP клиента с настроенными ответами."""
        mock_client = AsyncMock()
        
        if self.should_fail:
            from httpx import HTTPStatusError
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = HTTPStatusError(
                "Error", request=MagicMock(), response=MagicMock()
            )
            mock_client.post.return_value = mock_response
            mock_client.get.return_value = mock_response
        else:
            mock_token_response = MagicMock()
            mock_token_response.json.return_value = self.token_response or {}
            mock_token_response.raise_for_status = MagicMock()
            
            mock_userinfo_response = MagicMock()
            mock_userinfo_response.json.return_value = self.userinfo_response or {}
            mock_userinfo_response.raise_for_status = MagicMock()
            
            if self.provider in ["google", "apple"]:
                mock_client.post.return_value = mock_token_response
                mock_client.get.return_value = mock_userinfo_response
            elif self.provider == "vk":
                mock_client.get.side_effect = [mock_token_response, mock_userinfo_response]
        
        return mock_client


class OAuthUserProfileFactory:
    """
    Фабрика тестовых профилей пользователей от OAuth провайдеров.
    """
    
    @staticmethod
    def google_profile(
        user_id: str = "google_123456789",
        email: str = "google_user@gmail.com",
        name: str = "Google User",
        first_name: str = "Google",
        last_name: str = "User",
        avatar_url: str = "https://lh3.googleusercontent.com/a/avatar.jpg",
        is_verified: bool = True,
    ) -> dict[str, Any]:
        """Профиль пользователя Google."""
        return {
            "provider": "google",
            "external_id": user_id,
            "email": email,
            "name": name,
            "first_name": first_name,
            "last_name": last_name,
            "avatar_url": avatar_url,
            "is_verified": is_verified,
        }
    
    @staticmethod
    def vk_profile(
        user_id: str = "987654321",
        email: str = "vk_user@vk.ru",
        first_name: str = "Иван",
        last_name: str = "Петров",
        avatar_url: str = "https://vk.com/avatar.jpg",
    ) -> dict[str, Any]:
        """Профиль пользователя VK."""
        return {
            "provider": "vk",
            "external_id": user_id,
            "email": email,
            "name": f"{first_name} {last_name}",
            "first_name": first_name,
            "last_name": last_name,
            "avatar_url": avatar_url,
            "is_verified": True,
        }
    
    @staticmethod
    def apple_profile(
        user_id: str = "apple_001234.56789",
        email: str = "apple_user@privaterelay.appleid.com",
    ) -> dict[str, Any]:
        """Профиль пользователя Apple."""
        return {
            "provider": "apple",
            "external_id": user_id,
            "email": email,
            "name": None,
            "first_name": None,
            "last_name": None,
            "avatar_url": None,
            "is_verified": True,
        }


class OAuthRedisMock:
    """
    Мок для Redis при тестировании OAuth.
    """
    
    def __init__(self):
        self.storage = {}
    
    async def setex(self, key: str, ttl: int, value: dict) -> bool:
        """Мок setex."""
        self.storage[key] = {"value": value, "ttl": ttl, "created_at": datetime.now(timezone.utc)}
        return True
    
    async def get_json(self, key: str) -> dict | None:
        """Мок get_json."""
        data = self.storage.get(key)
        if data:
            return data["value"]
        return None
    
    async def delete(self, key: str) -> int:
        """Мок delete."""
        if key in self.storage:
            del self.storage[key]
            return 1
        return 0
    
    async def exists(self, key: str) -> bool:
        """Мок exists."""
        return key in self.storage
    
    def clear(self) -> None:
        """Очистка хранилища."""
        self.storage.clear()


# ==================== Pytest FIXTURES ====================

@pytest.fixture
def oauth_state_factory() -> OAuthStateFactory:
    """Фикстура фабрики OAuthState."""
    return OAuthStateFactory()


@pytest.fixture
def oauth_provider_mock_google() -> OAuthProviderMock:
    """Фикстура мока Google OAuth провайдера."""
    return OAuthProviderMock("google")


@pytest.fixture
def oauth_provider_mock_vk() -> OAuthProviderMock:
    """Фикстура мока VK OAuth провайдера."""
    return OAuthProviderMock("vk")


@pytest.fixture
def oauth_provider_mock_apple() -> OAuthProviderMock:
    """Фикстура мока Apple OAuth провайдера."""
    return OAuthProviderMock("apple")


@pytest.fixture
def oauth_user_profile_google() -> dict[str, Any]:
    """Фикстура профиля пользователя Google."""
    return OAuthUserProfileFactory.google_profile()


@pytest.fixture
def oauth_user_profile_vk() -> dict[str, Any]:
    """Фикстура профиля пользователя VK."""
    return OAuthUserProfileFactory.vk_profile()


@pytest.fixture
def oauth_user_profile_apple() -> dict[str, Any]:
    """Фикстура профиля пользователя Apple."""
    return OAuthUserProfileFactory.apple_profile()


@pytest.fixture
def oauth_google_login_state() -> tuple[str, str, str]:
    """Фикстура Google login URL, state, code_verifier."""
    state = OAuthStateFactory.generate_state()
    code_verifier = OAuthStateFactory.generate_code_verifier()
    code_challenge = OAuthStateFactory.generate_code_challenge(code_verifier)
    
    import urllib.parse
    params = {
        "client_id": "test_google_client_id",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "scope": "email profile",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
    
    return url, state, code_verifier


@pytest.fixture
def oauth_vk_login_state() -> tuple[str, str, str]:
    """Фикстура VK login URL, state, code_verifier."""
    state = OAuthStateFactory.generate_state()
    code_verifier = OAuthStateFactory.generate_code_verifier()
    
    import urllib.parse
    params = {
        "client_id": "test_vk_client_id",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "scope": "email",
        "state": state,
        "v": "5.131",
    }
    url = "https://oauth.vk.com/authorize?" + urllib.parse.urlencode(params)
    
    return url, state, code_verifier


@pytest.fixture
def oauth_apple_login_state() -> tuple[str, str, str]:
    """Фикстура Apple login URL, state, code_verifier."""
    state = OAuthStateFactory.generate_state()
    code_verifier = OAuthStateFactory.generate_code_verifier()
    code_challenge = OAuthStateFactory.generate_code_challenge(code_verifier)
    
    import urllib.parse
    params = {
        "client_id": "test_apple_client_id",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "scope": "name email",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "response_mode": "form_post",
    }
    url = "https://appleid.apple.com/auth/authorize?" + urllib.parse.urlencode(params)
    
    return url, state, code_verifier


@pytest.fixture
def oauth_redis_mock() -> OAuthRedisMock:
    """Фикстура мока Redis для OAuth тестов."""
    return OAuthRedisMock()


@pytest.fixture
def oauth_state_model(oauth_state_factory: OAuthStateFactory) -> OAuthState:
    """Фикстура модели OAuthState для входа."""
    oauth_state, _, _ = oauth_state_factory.create_login_state()
    return oauth_state


@pytest.fixture
def oauth_link_state_model(
    oauth_state_factory: OAuthStateFactory,
    user_id: UUID,
) -> OAuthState:
    """Фикстура модели OAuthState для привязки аккаунта."""
    oauth_state, _, _ = oauth_state_factory.create_link_state(user_id=user_id)
    return oauth_state


@pytest.fixture
def oauth_expired_state_model(oauth_state_factory: OAuthStateFactory) -> OAuthState:
    """Фикстура просроченной модели OAuthState."""
    oauth_state, _, _ = oauth_state_factory.create_expired_state()
    return oauth_state


@pytest.fixture
def oauth_service_mock() -> AsyncMock:
    """Фикстура мока OAuthService."""
    mock = AsyncMock(spec=OAuthService)
    mock.get_oauth_login_url = AsyncMock(return_value=("https://test.com", "state", "verifier"))
    mock.handle_oauth_callback = AsyncMock(return_value={
        "provider": "google",
        "external_id": "123",
        "email": "test@example.com",
        "name": "Test User",
        "first_name": "Test",
        "last_name": "User",
        "avatar_url": None,
        "is_verified": True,
    })
    mock.find_or_create_user = AsyncMock(return_value=(MagicMock(), False))
    mock.link_oauth_account = AsyncMock(return_value=True)
    return mock


# ==================== HELPER ФУНКЦИИ ДЛЯ ТЕСТОВ ====================

async def setup_oauth_state_in_redis(
    redis_mock: OAuthRedisMock,
    state: str,
    code_verifier: str,
    redirect_uri: str = "https://example.com/callback",
    ttl_seconds: int = 600,
) -> None:
    """
    Настройка OAuth state в Redis моке.
    """
    await redis_mock.setex(
        f"oauth:google:{state}",
        ttl_seconds,
        {"code_verifier": code_verifier, "redirect_uri": redirect_uri}
    )


async def cleanup_oauth_state(
    session: AsyncSession,
    state: str | None = None,
) -> None:
    """
    Очистка OAuth state из БД после тестов.
    """
    from sqlalchemy import delete
    
    stmt = delete(OAuthState)
    if state:
        stmt = stmt.where(OAuthState.state == state)
    
    await session.execute(stmt)
    await session.commit()


def create_oauth_callback_params(
    code: str = "test_auth_code",
    state: str = "test_state",
    error: str | None = None,
    error_description: str | None = None,
) -> dict[str, str]:
    """
    Создание параметров callback для OAuth провайдера.
    """
    params = {}
    if code:
        params["code"] = code
    if state:
        params["state"] = state
    if error:
        params["error"] = error
    if error_description:
        params["error_description"] = error_description
    return params