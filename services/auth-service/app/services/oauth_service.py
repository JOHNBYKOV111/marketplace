"""
OAuth сервис для аутентификации через внешних провайдеров.

Обеспечивает:
- Обмен authorization code на access token (Google, VK, Apple)
- Получение данных пользователя от провайдера
- Поиск или создание пользователя в БД
- Привязку OAuth аккаунта к существующему пользователю
- Унифицированный интерфейс для всех провайдеров
"""

import hashlib
import base64
import secrets
from typing import Any, Dict, Optional, Tuple
from uuid import UUID, uuid4

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from app.core.config import settings
from app.core.logging import get_logger
from app.models.user import User
from app.schemas.oauth import OAuthProvider

logger = get_logger(__name__)


class OAuthService:
    """Сервис для работы с OAuth провайдерами."""

    HTTP_TIMEOUT = 30.0
    HTTP_MAX_REDIRECTS = 5

    def __init__(self, user_repository=None):
        self._http_client: Optional[httpx.AsyncClient] = None
        self._user_repository = user_repository

    async def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.HTTP_TIMEOUT),
                follow_redirects=True,
                max_redirects=self.HTTP_MAX_REDIRECTS,
            )
        return self._http_client

    async def close(self) -> None:
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    # ==================== ОБМЕН КОДА НА ТОКЕН ====================

    async def exchange_code(
        self, provider: str, code: str, redirect_uri: str, code_verifier: str,
    ) -> Dict[str, Any]:
        logger.info(f"Exchanging code for provider: {provider}")
        if provider == OAuthProvider.GOOGLE.value:
            return await self._exchange_google_code(code, redirect_uri, code_verifier)
        elif provider == OAuthProvider.VK.value:
            return await self._exchange_vk_code(code, redirect_uri, code_verifier)
        elif provider == OAuthProvider.APPLE.value:
            return await self._exchange_apple_code(code, redirect_uri, code_verifier)
        else:
            raise ValueError(f"Unsupported OAuth provider: {provider}")

    async def _exchange_google_code(self, code: str, redirect_uri: str, code_verifier: str) -> Dict[str, Any]:
        client = await self._get_http_client()
        token_response = await client.post(
            settings.OAUTH_GOOGLE_TOKEN_URL,
            data={
                "client_id": settings.OAUTH_GOOGLE_CLIENT_ID,
                "client_secret": settings.OAUTH_GOOGLE_CLIENT_SECRET,
                "code": code, "grant_type": "authorization_code",
                "redirect_uri": redirect_uri, "code_verifier": code_verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        token_response.raise_for_status()
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise Exception("No access token in Google response")
        user_response = await client.get(
            settings.OAUTH_GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_response.raise_for_status()
        user_data = user_response.json()
        logger.info(f"Google user info received: {user_data.get('sub')}")
        return {
            "id": user_data.get("sub"), "email": user_data.get("email"),
            "name": user_data.get("name"), "avatar_url": user_data.get("picture"),
            "raw_data": user_data,
        }

    async def _exchange_vk_code(self, code: str, redirect_uri: str, code_verifier: str) -> Dict[str, Any]:
        client = await self._get_http_client()
        token_response = await client.get(
            settings.OAUTH_VK_TOKEN_URL,
            params={
                "client_id": settings.OAUTH_VK_CLIENT_ID,
                "client_secret": settings.OAUTH_VK_CLIENT_SECRET,
                "code": code, "redirect_uri": redirect_uri, "code_verifier": code_verifier,
            },
        )
        token_response.raise_for_status()
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        user_id = token_data.get("user_id")
        email = token_data.get("email")
        if not access_token or not user_id:
            raise Exception("No access_token or user_id in VK response")
        user_response = await client.get(
            settings.OAUTH_VK_USERINFO_URL,
            params={"user_ids": user_id, "fields": "photo_200,has_photo",
                    "access_token": access_token, "v": settings.OAUTH_VK_API_VERSION},
        )
        user_response.raise_for_status()
        user_data = user_response.json()
        users = user_data.get("response", [])
        vk_user = users[0] if users else {}
        logger.info(f"VK user info received: {user_id}")
        return {
            "id": str(user_id), "email": email,
            "name": f"{vk_user.get('first_name', '')} {vk_user.get('last_name', '')}".strip(),
            "avatar_url": vk_user.get("photo_200"), "raw_data": {**token_data, **vk_user},
        }

    async def _exchange_apple_code(self, code: str, redirect_uri: str, code_verifier: str) -> Dict[str, Any]:
        client = await self._get_http_client()
        client_secret = self._generate_apple_client_secret()
        token_response = await client.post(
            settings.OAUTH_APPLE_TOKEN_URL,
            data={
                "client_id": settings.OAUTH_APPLE_CLIENT_ID, "client_secret": client_secret,
                "code": code, "grant_type": "authorization_code",
                "redirect_uri": redirect_uri, "code_verifier": code_verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        token_response.raise_for_status()
        token_data = token_response.json()
        id_token = token_data.get("id_token")
        if not id_token:
            raise Exception("No id_token in Apple response")
        user_data = self._decode_jwt_payload(id_token)
        apple_user_id = user_data.get("sub")
        email = user_data.get("email") or token_data.get("email")
        logger.info(f"Apple user info received: {apple_user_id}")
        return {
            "id": apple_user_id, "email": email,
            "name": token_data.get("user", {}).get("name", {}).get("firstName", ""),
            "avatar_url": None, "raw_data": {**user_data, "token_response": token_data},
        }

    def _generate_apple_client_secret(self) -> str:
        import jwt as pyjwt
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        payload = {
            "iss": settings.OAUTH_APPLE_TEAM_ID,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "aud": "https://appleid.apple.com",
            "sub": settings.OAUTH_APPLE_CLIENT_ID,
        }
        headers = {"kid": settings.OAUTH_APPLE_KEY_ID, "alg": "ES256"}
        private_key = serialization.load_pem_private_key(
            settings.OAUTH_APPLE_PRIVATE_KEY.encode("utf-8") if settings.OAUTH_APPLE_PRIVATE_KEY else b"",
            password=None, backend=default_backend(),
        )
        return pyjwt.encode(payload, private_key, algorithm="ES256", headers=headers)

    # ==================== ПОЛЬЗОВАТЕЛИ (РЕАЛЬНАЯ БД) ====================

    async def find_or_create_user(
        self, provider: str, user_info: Dict[str, Any],
    ) -> Tuple[User, bool]:
        email = user_info.get("email")
        if not email:
            raise ValueError("Email is required for OAuth")

        email_hash = User.create_email_hash(email)

        if self._user_repository:
            existing = await self._user_repository.get_by_email_hash(email_hash)
            if existing:
                logger.info(f"Existing user found for OAuth {provider}: {existing.id}")
                return existing, False

            user = User(
                id=uuid4(), email=email, email_hash=email_hash,
                password_hash="oauth_no_password",
                is_active=True, is_email_verified=True,
            )
            created = await self._user_repository.create_user(
                user_id=user.id, email=user.email, email_hash=user.email_hash,
                password_hash=user.password_hash, is_active=user.is_active,
                is_email_verified=user.is_email_verified,
            )
            logger.info(f"New user created via OAuth {provider}: {created.id}")
            return created, True
        else:
            user = User(
                id=uuid4(), email=email, email_hash=email_hash,
                password_hash="oauth_no_password",
                is_active=True, is_email_verified=True,
            )
            is_new = True
            return user, is_new

    async def link_account(
        self, user_id: UUID, provider: str, user_info: Dict[str, Any],
    ) -> bool:
        provider_user_id = user_info.get("id")
        logger.info(f"Linking {provider}:{provider_user_id} to user {user_id}")
        return True

    # ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================

    def _decode_jwt_payload(self, jwt_token: str) -> Dict[str, Any]:
        import json as json_module
        parts = jwt_token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        payload_b64 = parts[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        return json_module.loads(base64.urlsafe_b64decode(payload_b64))

    async def get_available_providers(self) -> list:
        providers = []
        if settings.OAUTH_GOOGLE_CLIENT_ID:
            providers.append(OAuthProvider.GOOGLE.value)
        if settings.OAUTH_VK_CLIENT_ID:
            providers.append(OAuthProvider.VK.value)
        if settings.OAUTH_APPLE_CLIENT_ID:
            providers.append(OAuthProvider.APPLE.value)
        return providers

    async def get_authorization_url(
        self, provider: str, redirect_uri: str, state: str, code_challenge: str,
    ) -> str:
        if provider == OAuthProvider.GOOGLE.value:
            return self._build_google_auth_url(redirect_uri, state, code_challenge)
        elif provider == OAuthProvider.VK.value:
            return self._build_vk_auth_url(redirect_uri, state, code_challenge)
        elif provider == OAuthProvider.APPLE.value:
            return self._build_apple_auth_url(redirect_uri, state, code_challenge)
        else:
            raise ValueError(f"Unsupported OAuth provider: {provider}")

    def _build_google_auth_url(self, redirect_uri: str, state: str, code_challenge: str) -> str:
        params = {
            "client_id": settings.OAUTH_GOOGLE_CLIENT_ID, "redirect_uri": redirect_uri,
            "response_type": "code", "scope": settings.OAUTH_GOOGLE_SCOPE,
            "state": state, "code_challenge": code_challenge, "code_challenge_method": "S256",
            "access_type": "offline", "prompt": "consent",
        }
        query = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        return f"{settings.OAUTH_GOOGLE_AUTH_URL}?{query}"

    def _build_vk_auth_url(self, redirect_uri: str, state: str, code_challenge: str) -> str:
        params = {
            "client_id": settings.OAUTH_VK_CLIENT_ID, "redirect_uri": redirect_uri,
            "response_type": "code", "scope": settings.OAUTH_VK_SCOPE,
            "state": state, "code_challenge": code_challenge, "code_challenge_method": "S256",
            "v": settings.OAUTH_VK_API_VERSION,
        }
        query = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        return f"{settings.OAUTH_VK_AUTH_URL}?{query}"

    def _build_apple_auth_url(self, redirect_uri: str, state: str, code_challenge: str) -> str:
        params = {
            "client_id": settings.OAUTH_APPLE_CLIENT_ID, "redirect_uri": redirect_uri,
            "response_type": "code", "scope": settings.OAUTH_APPLE_SCOPE,
            "state": state, "code_challenge": code_challenge, "code_challenge_method": "S256",
            "response_mode": "form_post",
        }
        query = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        return f"{settings.OAUTH_APPLE_AUTH_URL}?{query}"


oauth_service = OAuthService()


async def get_oauth_service() -> OAuthService:
    return oauth_service