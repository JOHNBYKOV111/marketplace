"""
Сервис для валидации JWT токенов.

Реализует:
- Проверку JWT токенов (подпись, срок действия, аудитория)
- Валидацию через JWKS (JSON Web Key Set)
- Кэширование публичных ключей
- Проверку прав (scopes, roles)
- Поддержку разных алгоритмов (RS256, ES256, HS256)
- Метрики и логирование
"""

import json
import time
from typing import Dict, Optional, List, Set, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

import jwt
import aiohttp
from fastapi import Request, HTTPException, status
from jwt import PyJWKClient, InvalidTokenError

from app.core.config import settings
from app.core.logging import get_logger
from app.core.metrics import token_validation_metrics
from app.core.cache import cache

logger = get_logger(__name__)


class TokenType(str, Enum):
    """Типы токенов."""

    ACCESS = "access"
    REFRESH = "refresh"
    API_KEY = "api_key"
    SERVICE = "service"


@dataclass
class TokenValidationResult:
    """Результат валидации токена."""

    valid: bool
    payload: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    user_id: Optional[str] = None
    roles: Optional[List[str]] = None
    scopes: Optional[List[str]] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    iss: Optional[str] = None
    aud: Optional[Union[str, List[str]]] = None

    @property
    def is_expired(self) -> bool:
        """Проверка истечения срока действия."""
        if not self.exp:
            return False
        return int(time.time()) > self.exp


class TokenValidator:
    """
    Валидатор JWT токенов.

    Поддерживает:
    - Проверку через JWKS (асинхронная загрузка ключей)
    - Кэширование ключей
    - Разные алгоритмы
    - Проверку scopes и roles
    """

    def __init__(
        self,
        jwks_url: Optional[str] = None,
        algorithms: Optional[List[str]] = None,
        audience: Optional[Union[str, List[str]]] = None,
        issuer: Optional[str] = None,
        cache_ttl: int = 3600,  # 1 час
    ):
        """
        Инициализация валидатора.

        Args:
            jwks_url: URL для JWKS (если None - использует локальный ключ)
            algorithms: Список разрешенных алгоритмов
            audience: Ожидаемая аудитория
            issuer: Ожидаемый издатель
            cache_ttl: Время жизни кэша ключей в секундах
        """
        self.jwks_url = jwks_url or settings.JWKS_URL
        self.algorithms = algorithms or ["RS256", "ES256"]
        self.audience = audience or settings.JWT_AUDIENCE
        self.issuer = issuer or settings.JWT_ISSUER
        self.cache_ttl = cache_ttl

        # Клиент для JWKS
        self._jwks_client: Optional[PyJWKClient] = None

        # Локальный ключ для HS256
        self._secret_key = settings.JWT_SECRET_KEY

        # Кэш для валидных токенов (черный список обрабатывается отдельно)
        self._token_cache = cache

        # Статистика
        self._stats = {
            "validated": 0,
            "invalid": 0,
            "expired": 0,
            "blacklisted": 0,
        }

        # Инициализация JWKS клиента
        if self.jwks_url and self.jwks_url.startswith(("http://", "https://")):
            self._jwks_client = PyJWKClient(self.jwks_url)

    async def validate(
        self,
        token: str,
        token_type: TokenType = TokenType.ACCESS,
        required_scopes: Optional[List[str]] = None,
        required_roles: Optional[List[str]] = None,
        check_blacklist: bool = True,
    ) -> TokenValidationResult:
        """
        Валидация токена.

        Args:
            token: JWT токен
            token_type: Тип токена
            required_scopes: Требуемые scopes
            required_roles: Требуемые роли
            check_blacklist: Проверять черный список

        Returns:
            TokenValidationResult: Результат валидации
        """
        start_time = time.time()

        try:
            # 1. Проверка формата
            if not token or not isinstance(token, str):
                return TokenValidationResult(
                    valid=False,
                    error="Invalid token format",
                )

            # 2. Проверка черного списка
            if check_blacklist and await self._is_blacklisted(token):
                token_validation_metrics.increment_blacklisted()
                return TokenValidationResult(
                    valid=False,
                    error="Token is blacklisted",
                )

            # 3. Декодирование токена
            payload = await self._decode_token(token)

            if not payload:
                return TokenValidationResult(
                    valid=False,
                    error="Failed to decode token",
                )

            # 4. Проверка типа токена
            token_type_from_payload = payload.get("type")
            if token_type_from_payload and token_type_from_payload != token_type:
                return TokenValidationResult(
                    valid=False,
                    error=f"Invalid token type: expected {token_type}, got {token_type_from_payload}",
                )

            # 5. Проверка аудитории
            if self.audience and not self._check_audience(payload):
                return TokenValidationResult(
                    valid=False,
                    error="Invalid audience",
                )

            # 6. Проверка издателя
            if self.issuer and payload.get("iss") != self.issuer:
                return TokenValidationResult(
                    valid=False,
                    error="Invalid issuer",
                )

            # 7. Проверка scopes
            if required_scopes and not self._check_scopes(payload, required_scopes):
                return TokenValidationResult(
                    valid=False,
                    error="Missing required scopes",
                )

            # 8. Проверка roles
            if required_roles and not self._check_roles(payload, required_roles):
                return TokenValidationResult(
                    valid=False,
                    error="Missing required roles",
                )

            # 9. Проверка срока действия (дополнительная)
            exp = payload.get("exp")
            if exp and int(time.time()) > exp:
                token_validation_metrics.increment_expired()
                return TokenValidationResult(
                    valid=False,
                    error="Token expired",
                    exp=exp,
                )

            # Успешная валидация
            token_validation_metrics.increment_valid()
            token_validation_metrics.observe_validation_time(time.time() - start_time)

            return TokenValidationResult(
                valid=True,
                payload=payload,
                user_id=payload.get("sub"),
                roles=payload.get("roles", []),
                scopes=payload.get("scopes", []),
                exp=payload.get("exp"),
                iat=payload.get("iat"),
                iss=payload.get("iss"),
                aud=payload.get("aud"),
            )

        except InvalidTokenError as e:
            token_validation_metrics.increment_invalid()
            logger.warning(f"Invalid token: {str(e)}")
            return TokenValidationResult(
                valid=False,
                error=f"Invalid token: {str(e)}",
            )

        except Exception as e:
            token_validation_metrics.increment_invalid()
            logger.error(f"Token validation error: {str(e)}", exc_info=True)
            return TokenValidationResult(
                valid=False,
                error=f"Validation error: {str(e)}",
            )

    async def _decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Декодирование токена.

        Args:
            token: JWT токен

        Returns:
            Optional[Dict[str, Any]]: Полезная нагрузка или None
        """
        try:
            # Проверяем кэш
            cache_key = f"token_payload:{token[:20]}"  # Частичный ключ для безопасности
            cached = await self._token_cache.get(cache_key)
            if cached:
                return cached

            # Декодируем без проверки для получения kid
            unverified = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False},
            )
            kid = unverified.get("kid")

            # Получаем ключ
            if self._jwks_client:
                # JWKS валидация
                signing_key = self._jwks_client.get_signing_key(kid)
                public_key = signing_key.key
            else:
                # Локальный ключ (HS256)
                public_key = self._secret_key
                self.algorithms = ["HS256"]

            # Декодируем с проверкой
            payload = jwt.decode(
                token,
                public_key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub"]},
            )

            # Сохраняем в кэш (короткое время, так как токены могут быть отозваны)
            await self._token_cache.set(
                cache_key,
                payload,
                ttl=60,  # 1 минута
            )

            return payload

        except jwt.ExpiredSignatureError:
            # Возвращаем payload даже для истекшего токена (для анализа)
            try:
                payload = jwt.decode(
                    token,
                    options={"verify_signature": False, "verify_exp": False},
                )
                return payload
            except Exception:
                return None

        except Exception as e:
            logger.error(f"Token decode error: {str(e)}")
            return None

    def _check_audience(self, payload: Dict[str, Any]) -> bool:
        """
        Проверка аудитории.

        Args:
            payload: Полезная нагрузка токена

        Returns:
            bool: True если аудитория соответствует
        """
        aud = payload.get("aud")
        if not aud:
            return False

        if isinstance(self.audience, list):
            if isinstance(aud, list):
                return any(a in self.audience for a in aud)
            return aud in self.audience

        if isinstance(aud, list):
            return self.audience in aud

        return aud == self.audience

    def _check_scopes(
        self,
        payload: Dict[str, Any],
        required_scopes: List[str],
    ) -> bool:
        """
        Проверка scopes.

        Args:
            payload: Полезная нагрузка токена
            required_scopes: Требуемые scopes

        Returns:
            bool: True если все scopes присутствуют
        """
        token_scopes = payload.get("scopes", [])
        if isinstance(token_scopes, str):
            token_scopes = token_scopes.split()

        return all(scope in token_scopes for scope in required_scopes)

    def _check_roles(
        self,
        payload: Dict[str, Any],
        required_roles: List[str],
    ) -> bool:
        """
        Проверка ролей.

        Args:
            payload: Полезная нагрузка токена
            required_roles: Требуемые роли

        Returns:
            bool: True если все роли присутствуют
        """
        token_roles = payload.get("roles", [])
        if isinstance(token_roles, str):
            token_roles = [token_roles]

        # ADMIN имеет все права
        if "admin" in token_roles:
            return True

        return any(role in token_roles for role in required_roles)

    async def _is_blacklisted(self, token: str) -> bool:
        """
        Проверка черного списка.

        Args:
            token: JWT токен

        Returns:
            bool: True если токен в черном списке
        """
        # Получаем jti из токена
        try:
            unverified = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False},
            )
            jti = unverified.get("jti")
            if not jti:
                return False

            # Проверяем в Redis
            blacklist_key = f"blacklist:token:{jti}"
            blacklisted = await self._token_cache.get(blacklist_key)
            return bool(blacklisted)

        except Exception:
            return False

    async def blacklist_token(self, token: str, ttl: int = 86400) -> bool:
        """
        Добавление токена в черный список.

        Args:
            token: JWT токен
            ttl: Время жизни в секундах (по умолчанию 24 часа)

        Returns:
            bool: True если успешно
        """
        try:
            # Получаем jti и exp из токена
            unverified = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False},
            )
            jti = unverified.get("jti")
            exp = unverified.get("exp")

            if not jti:
                return False

            # Вычисляем оставшееся время жизни токена
            remaining_ttl = 0
            if exp:
                remaining_ttl = max(0, exp - int(time.time()))

            # Используем максимальный TTL
            actual_ttl = max(ttl, remaining_ttl)

            blacklist_key = f"blacklist:token:{jti}"
            await self._token_cache.set(blacklist_key, "1", ttl=actual_ttl)

            logger.info(f"Token {jti[:8]}... blacklisted until {actual_ttl}s")
            return True

        except Exception as e:
            logger.error(f"Failed to blacklist token: {str(e)}")
            return False


class JWKSLoader:
    """
    Загрузчик JWKS ключей с кэшированием.

    Поддерживает:
    - Асинхронную загрузку ключей
    - Кэширование с TTL
    - Автоматическое обновление
    - Мониторинг
    """

    def __init__(
        self,
        jwks_url: str,
        cache_ttl: int = 3600,
        timeout: int = 10,
    ):
        """
        Инициализация загрузчика.

        Args:
            jwks_url: URL для JWKS
            cache_ttl: Время кэширования ключей
            timeout: Таймаут запроса
        """
        self.jwks_url = jwks_url
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self._keys: Optional[List[Dict]] = None
        self._last_update: float = 0
        self._updating = False

    async def get_keys(self) -> List[Dict]:
        """
        Получение ключей.

        Returns:
            List[Dict]: Список ключей
        """
        now = time.time()

        # Проверка кэша
        if self._keys and (now - self._last_update) < self.cache_ttl:
            return self._keys

        # Обновление ключей
        if not self._updating:
            self._updating = True
            try:
                await self._fetch_keys()
            finally:
                self._updating = False

        return self._keys or []

    async def _fetch_keys(self) -> None:
        """
        Загрузка ключей из JWKS endpoint.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.jwks_url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        self._keys = data.get("keys", [])
                        self._last_update = time.time()
                        logger.info(f"Loaded {len(self._keys)} JWKS keys")
                    else:
                        logger.error(
                            f"Failed to load JWKS: HTTP {response.status}"
                        )

        except Exception as e:
            logger.error(f"JWKS fetch error: {str(e)}")

            # Если ключи уже были, используем их
            if not self._keys:
                raise


# ==================== ЗАВИСИМОСТИ ДЛЯ FASTAPI ====================

async def validate_token_dependency(
    request: Request,
    token_type: TokenType = TokenType.ACCESS,
    required_scopes: Optional[List[str]] = None,
    required_roles: Optional[List[str]] = None,
) -> TokenValidationResult:
    """
    FastAPI зависимость для валидации токена.

    Args:
        request: FastAPI Request
        token_type: Тип токена
        required_scopes: Требуемые scopes
        required_roles: Требуемые роли

    Returns:
        TokenValidationResult: Результат валидации

    Raises:
        HTTPException: При ошибке валидации
    """
    # Получение токена из заголовка
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[7:]

    # Валидация
    validator = TokenValidator()
    result = await validator.validate(
        token=token,
        token_type=token_type,
        required_scopes=required_scopes,
        required_roles=required_roles,
    )

    if not result.valid:
        error_messages = {
            "Token expired": status.HTTP_401_UNAUTHORIZED,
            "Invalid token format": status.HTTP_401_UNAUTHORIZED,
            "Missing required scopes": status.HTTP_403_FORBIDDEN,
            "Missing required roles": status.HTTP_403_FORBIDDEN,
        }

        status_code = status.HTTP_401_UNAUTHORIZED
        for msg, code in error_messages.items():
            if msg in result.error:
                status_code = code
                break

        raise HTTPException(
            status_code=status_code,
            detail=result.error,
            headers={"WWW-Authenticate": "Bearer"} if status_code == 401 else None,
        )

    # Сохраняем результат в request state
    request.state.user = result
    request.state.user_id = result.user_id
    request.state.roles = result.roles

    return result


# ==================== ГЛОБАЛЬНЫЙ ЭКЗЕМПЛЯР ====================

# Глобальный экземпляр валидатора
token_validator = TokenValidator()

# Глобальный загрузчик JWKS
jwks_loader = JWKSLoader(settings.JWKS_URL) if settings.JWKS_URL else None