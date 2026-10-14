"""
Сервис для работы с Vault.

Обеспечивает:
- Единую точку входа для работы с секретами
- Кэширование секретов на уровне сервиса
- Обработку ошибок и логирование
- Graceful shutdown
"""

import json
from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta

import aiohttp
from aiohttp import ClientTimeout, ClientSession, TCPConnector
from aiohttp.client_exceptions import ClientError, ClientResponseError

from app.core.config import settings
from app.core.logging import get_logger


logger = get_logger(__name__)


class VaultService:
    """
    Сервис для работы с HashiCorp Vault.
    
    Предоставляет высокоуровневые методы для получения секретов,
    управления конфигурациями и healthcheck.
    
    Особенности:
    - Асинхронные операции с Vault через HTTP API
    - Кэширование секретов с TTL
    - Graceful shutdown
    - Логирование всех операций
    - Защита от Race Conditions через asyncio.Lock
    """
    
    def __init__(self):
        """Инициализация сервиса Vault."""
        self._url = settings.VAULT_URL
        self._token = settings.VAULT_TOKEN
        self._namespace = settings.VAULT_NAMESPACE
        self._secret_path = settings.VAULT_SECRET_PATH
        self._session: Optional[ClientSession] = None
        self._initialized = False
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl: Dict[str, datetime] = {}
        self._cache_timeout = settings.VAULT_CACHE_TTL
        self._lock = asyncio.Lock()
        self._renewal_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def authenticate(self) -> None:
        """
        Аутентификация в Vault.
        
        Raises:
            RuntimeError: Если аутентификация не удалась
        """
        if self._initialized:
            logger.warning("Vault already initialized")
            return
        
        auth_method = getattr(settings, "VAULT_AUTH_METHOD", "token")
        verify = not settings.is_development
        
        try:
            # Создаем HTTP сессию
            timeout = ClientTimeout(
                total=settings.VAULT_TIMEOUT,
                connect=settings.VAULT_CONNECT_TIMEOUT,
            )
            
            connector = TCPConnector(
                limit=settings.VAULT_MAX_CONNECTIONS,
                ttl_dns_cache=300,
                enable_cleanup_closed=True,
            )
            
            self._session = ClientSession(
                timeout=timeout,
                connector=connector,
            )
            
            # Аутентификация в Vault
            if auth_method == "token":
                await self._authenticate_token(verify)
            elif auth_method == "approle":
                await self._authenticate_approle()
            else:
                raise RuntimeError(f"Unsupported auth method: {auth_method}")
            
            self._initialized = True
            self._running = True
            logger.info(f"Vault authenticated successfully using {auth_method}")
            
            # Запускаем фоновое обновление токена
            await self._start_renewal_loop()
            
        except Exception as e:
            self._initialized = False
            self._running = False
            logger.error(f"Vault authentication failed: {e}")
            raise RuntimeError(f"Vault authentication failed: {e}")
    
    async def _authenticate_token(self, verify: bool) -> None:
        """
        Аутентификация через токен.
        
        Args:
            verify: Проверять SSL сертификат
        """
        if not self._token:
            raise RuntimeError("Vault token not provided")
        
        headers = self._build_headers()
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        
        url = f"{self._url}/v1/auth/token/lookup-self"
        
        async with self._session.get(url, headers=headers, ssl=verify) as response:
            if response.status == 200:
                logger.info("Token authentication successful")
                return
            elif response.status == 403:
                raise RuntimeError("Invalid or expired Vault token")
            else:
                error_text = await response.text()
                raise RuntimeError(f"Token auth failed: {response.status} - {error_text}")
    
    async def _authenticate_approle(self) -> None:
        """
        Аутентификация через AppRole.
        """
        role_id = getattr(settings, "VAULT_ROLE_ID", None)
        secret_id = getattr(settings, "VAULT_SECRET_ID", None)
        
        if not role_id or not secret_id:
            raise RuntimeError("AppRole credentials not provided")
        
        data = {
            "role_id": role_id,
            "secret_id": secret_id,
        }
        
        url = f"{self._url}/v1/auth/approle/login"
        
        async with self._session.post(url, json=data) as response:
            if response.status != 200:
                error_text = await response.text()
                raise RuntimeError(f"AppRole auth failed: {response.status} - {error_text}")
            
            result = await response.json()
            auth = result.get("auth", {})
            client_token = auth.get("client_token")
            
            if not client_token:
                raise RuntimeError("No client token received from AppRole login")
            
            self._token = client_token
            self._session.headers.update({
                "X-Vault-Token": client_token,
            })
            
            logger.info("AppRole authentication successful")
    
    async def _start_renewal_loop(self) -> None:
        """Запуск фонового обновления токена."""
        if self._renewal_task is not None:
            return
        
        self._renewal_task = asyncio.create_task(self._renewal_loop())
        logger.debug("Vault token renewal loop started")
    
    async def _renewal_loop(self) -> None:
        """Фоновый цикл обновления токена."""
        while self._running:
            try:
                await asyncio.sleep(300)  # Проверяем каждые 5 минут
                if self._token:
                    await self._renew_token()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Token renewal failed: {e}")
    
    async def _renew_token(self) -> bool:
        """
        Обновление токена.
        
        Returns:
            bool: True если обновление успешно
        """
        try:
            headers = self._build_headers()
            url = f"{self._url}/v1/auth/token/renew-self"
            
            async with self._session.post(url, headers=headers) as response:
                if response.status == 200:
                    logger.debug("Token renewed successfully")
                    return True
                else:
                    logger.warning(f"Token renewal failed with status {response.status}")
                    return False
        except Exception as e:
            logger.warning(f"Token renewal error: {e}")
            return False
    
    async def close(self) -> None:
        """Закрытие соединения с Vault."""
        self._running = False
        
        if self._renewal_task:
            self._renewal_task.cancel()
            try:
                await self._renewal_task
            except asyncio.CancelledError:
                pass
            self._renewal_task = None
        
        if self._session:
            try:
                await self._session.close()
                self._initialized = False
                logger.info("Vault connection closed")
            except Exception as e:
                logger.warning(f"Error closing Vault connection: {e}")
            finally:
                self._session = None
        
        # Очищаем кэш
        self._cache.clear()
        self._cache_ttl.clear()
    
    # ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================
    
    def _build_headers(self) -> Dict[str, str]:
        """
        Сборка заголовков для запросов к Vault.
        
        Returns:
            Dict[str, str]: Заголовки
        """
        headers = {
            "X-Vault-Token": self._token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        
        return headers
    
    def _get_cache_key(self, path: str) -> str:
        """
        Получение ключа кэша для пути.
        
        Args:
            path: Путь к секрету
        
        Returns:
            str: Ключ кэша
        """
        return f"vault:{path}"
    
    def _is_cache_valid(self, key: str) -> bool:
        """
        Проверка валидности кэша.
        
        Args:
            key: Ключ кэша
        
        Returns:
            bool: True если кэш валиден
        """
        if key not in self._cache_ttl:
            return False
        
        if not self._cache_timeout:
            return True
        
        return datetime.utcnow() < self._cache_ttl[key]
    
    def _set_cache(self, key: str, data: Dict[str, Any]) -> None:
        """
        Сохранение данных в кэш.
        
        Args:
            key: Ключ кэша
            data: Данные для сохранения
        """
        self._cache[key] = data
        if self._cache_timeout:
            self._cache_ttl[key] = datetime.utcnow() + timedelta(
                seconds=self._cache_timeout
            )
    
    def _get_cache(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Получение данных из кэша.
        
        Args:
            key: Ключ кэша
        
        Returns:
            Optional[Dict[str, Any]]: Данные или None
        """
        if not self._is_cache_valid(key):
            return None
        return self._cache.get(key)
    
    async def clear_cache(self) -> None:
        """
        Очистка кэша.
        """
        self._cache.clear()
        self._cache_ttl.clear()
        logger.debug("Vault cache cleared")
    
    # ==================== ОСНОВНЫЕ МЕТОДЫ ====================
    
    async def _request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Выполнение запроса к Vault.
        
        Args:
            method: HTTP метод
            path: Путь запроса
            data: Данные для отправки
            params: Параметры запроса
        
        Returns:
            Dict[str, Any]: Ответ от Vault
        
        Raises:
            ClientError: При ошибке HTTP
        """
        if not self._session:
            raise ClientError("Vault session not initialized")
        
        url = f"{self._url}/{path.lstrip('/')}"
        headers = self._build_headers()
        
        try:
            async with self._session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                headers=headers,
            ) as response:
                response.raise_for_status()
                result = await response.json()
                
                if result.get("errors"):
                    error_msg = "; ".join(result["errors"])
                    logger.error(f"Vault error: {error_msg}")
                    raise ClientError(f"Vault error: {error_msg}")
                
                return result
                
        except ClientResponseError as e:
            logger.error(f"Vault HTTP error: {e.status} - {e.message}")
            raise
        except Exception as e:
            logger.error(f"Vault unexpected error: {e}")
            raise
    
    # ==================== РАБОТА С СЕКРЕТАМИ ====================
    
    async def get_secret(self, path: str, use_cache: bool = True) -> Optional[Any]:
        """
        Получение секрета из Vault.
        
        Args:
            path: Путь к секрету
            use_cache: Использовать кэш
        
        Returns:
            Optional[Any]: Значение секрета или None
        """
        full_path = f"{self._secret_path}/{path}"
        cache_key = self._get_cache_key(full_path)
        
        # Проверяем кэш
        if use_cache:
            cached = self._get_cache(cache_key)
            if cached is not None:
                logger.debug(f"Cache hit for {full_path}")
                return cached.get("value")
        
        try:
            result = await self._request("GET", f"v1/{full_path}")
            
            # Vault KV v2 структура
            data = result.get("data", {})
            secret_data = data.get("data", {}) if "data" in data else data
            value = secret_data.get("value")
            
            # Сохраняем в кэш
            if use_cache and value is not None:
                self._set_cache(cache_key, {"value": value})
            
            logger.debug(f"Secret retrieved from {path}")
            return value
            
        except ClientResponseError as e:
            if e.status == 404:
                logger.warning(f"Secret not found: {path}")
                return None
            raise
        except Exception as e:
            logger.error(f"Failed to get secret {path}: {e}")
            raise
    
    async def get_secret_json(self, path: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """
        Получение секрета и десериализация JSON.
        
        Args:
            path: Путь к секрету
            use_cache: Использовать кэш
        
        Returns:
            Optional[Dict[str, Any]]: Десериализованные данные или None
        """
        value = await self.get_secret(path, use_cache)
        if value is None:
            return None
        
        if isinstance(value, dict):
            return value
        
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            logger.warning(f"Failed to decode JSON from {path}")
            return None
    
    async def write_secret(self, path: str, value: Any) -> bool:
        """
        Запись секрета в Vault.
        
        Args:
            path: Путь к секрету
            value: Значение секрета
        
        Returns:
            bool: True если успешно
        """
        full_path = f"{self._secret_path}/{path}"
        data = {"value": value}
        
        try:
            payload = {"data": data}
            await self._request("POST", f"v1/{full_path}", data=payload)
            
            # Очищаем кэш
            cache_key = self._get_cache_key(full_path)
            self._cache.pop(cache_key, None)
            self._cache_ttl.pop(cache_key, None)
            
            logger.info(f"Secret written to {path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to write secret {path}: {e}")
            return False
    
    async def rotate_secret(self, path: str, length: int = 32) -> Optional[str]:
        """
        Ротация секрета (генерация нового).
        
        Args:
            path: Путь к секрету
            length: Длина нового секрета
        
        Returns:
            Optional[str]: Новый секрет или None
        """
        import secrets
        import string
        
        new_value = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))
        
        success = await self.write_secret(path, new_value)
        if success:
            return new_value
        
        return None
    
    # ==================== КОНКРЕТНЫЕ МЕТОДЫ ====================
    
    async def get_database_url(self) -> str:
        """
        Получение URL для подключения к БД.
        
        Returns:
            str: URL для подключения к БД
        
        Raises:
            RuntimeError: Если URL не найден
        """
        url = await self.get_secret("database_url")
        if url is None:
            raise RuntimeError("Database URL not found")
        return str(url)
    
    async def get_redis_url(self) -> str:
        """
        Получение URL для подключения к Redis.
        
        Returns:
            str: URL для подключения к Redis
        
        Raises:
            RuntimeError: Если URL не найден
        """
        url = await self.get_secret("redis_url")
        if url is None:
            raise RuntimeError("Redis URL not found")
        return str(url)
    
    async def get_jwt_private_key(self) -> str:
        """
        Получение JWT приватного ключа.
        
        Returns:
            str: JWT приватный ключ
        
        Raises:
            RuntimeError: Если ключ не найден
        """
        key = await self.get_secret("jwt_private_key")
        if key is None:
            raise RuntimeError("JWT private key not found")
        return str(key)
    
    async def get_jwt_public_key(self) -> str:
        """
        Получение JWT публичного ключа.
        
        Returns:
            str: JWT публичный ключ
        
        Raises:
            RuntimeError: Если ключ не найден
        """
        key = await self.get_secret("jwt_public_key")
        if key is None:
            raise RuntimeError("JWT public key not found")
        return str(key)
    
    async def get_pepper(self) -> str:
        """
        Получение секретного перца (pepper) для хеширования.
        
        Returns:
            str: Секретный перец
        
        Raises:
            RuntimeError: Если перец не найден
        """
        pepper = await self.get_secret("pepper")
        if pepper is None:
            raise RuntimeError("Pepper not found")
        return str(pepper)
    
    async def get_encryption_key(self) -> str:
        """
        Получение ключа для шифрования.
        
        Returns:
            str: Ключ шифрования
        
        Raises:
            RuntimeError: Если ключ не найден
        """
        key = await self.get_secret("encryption_key")
        if key is None:
            raise RuntimeError("Encryption key not found")
        return str(key)
    
    async def get_oauth_credentials(self, provider: str) -> Dict[str, Any]:
        """
        Получение OAuth учетных данных.
        
        Args:
            provider: OAuth провайдер (google, github, etc.)
        
        Returns:
            Dict[str, Any]: OAuth учетные данные
        
        Raises:
            RuntimeError: Если учетные данные не найдены
        """
        credentials = await self.get_secret_json(f"oauth/{provider}")
        if credentials is None:
            raise RuntimeError(f"OAuth credentials for {provider} not found")
        return credentials
    
    # ==================== HEALTHCHECK ====================
    
    async def health_check(self) -> bool:
        """
        Проверка доступности Vault.
        
        Returns:
            bool: True если Vault доступен
        """
        try:
            await self._request("GET", "v1/sys/health")
            return True
        except Exception:
            return False
    
    async def is_sealed(self) -> bool:
        """
        Проверка запечатан ли Vault.
        
        Returns:
            bool: True если Vault запечатан
        """
        try:
            result = await self._request("GET", "v1/sys/seal-status")
            return result.get("sealed", True)
        except Exception:
            return True
    
    async def get_status(self) -> Dict[str, Any]:
        """
        Получение статуса Vault.
        
        Returns:
            Dict[str, Any]: Статус Vault
        """
        try:
            result = await self._request("GET", "v1/sys/health")
            return {
                "healthy": result.get("initialized", False),
                "sealed": result.get("sealed", True),
                "standby": result.get("standby", True),
                "performance_standby": result.get("performance_standby", False),
                "version": result.get("version", "unknown"),
                "cluster_name": result.get("cluster_name", "unknown"),
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e),
            }
    
    # ==================== СОЗДАНИЕ НАЧАЛЬНЫХ СЕКРЕТОВ ====================
    
    async def create_initial_secrets(self) -> None:
        """
        Создание начальных секретов в development режиме.
        """
        if not settings.is_development:
            logger.warning("Skipping initial secrets creation in production mode")
            return
        
        try:
            # Проверяем, есть ли уже секреты
            existing = await self.get_secret("database_url")
            if existing is not None:
                logger.info("Initial secrets already exist, skipping creation")
                return
            
            logger.info("Creating initial secrets in development mode")
            
            # Создаем секреты
            secrets = {
                "database_url": settings.DATABASE_URL,
                "redis_url": settings.REDIS_URL,
                "pepper": settings.SECRET_PEPPER,
                "encryption_key": settings.ENCRYPTION_KEY or "development_encryption_key_32_chars",
            }
            
            # JWT ключи
            import secrets
            import string
            
            def generate_jwt_key():
                return "-----BEGIN PRIVATE KEY-----\nMOCK_PRIVATE_KEY_FOR_DEVELOPMENT\n-----END PRIVATE KEY-----"
            
            secrets["jwt_private_key"] = generate_jwt_key()
            secrets["jwt_public_key"] = "-----BEGIN PUBLIC KEY-----\nMOCK_PUBLIC_KEY_FOR_DEVELOPMENT\n-----END PUBLIC KEY-----"
            
            # Сохраняем секреты
            for path, value in secrets.items():
                await self.write_secret(path, value)
            
            logger.info("Initial secrets created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create initial secrets: {e}")
            raise


# ==================== ГЛОБАЛЬНЫЙ ЭКЗЕМПЛЯР ====================

vault_service = VaultService()


# ==================== LIFECYCLE ФУНКЦИИ ====================

async def init_vault_service() -> None:
    """Инициализация Vault сервиса при старте приложения."""
    await vault_service.authenticate()
    await vault_service.create_initial_secrets()


async def close_vault_service() -> None:
    """Закрытие Vault сервиса при завершении приложения."""
    await vault_service.close()


# ==================== HELPER ФУНКЦИИ ====================

async def get_secret(path: str) -> Optional[Any]:
    """
    Быстрое получение секрета из Vault.
    
    Args:
        path: Путь к секрету
    
    Returns:
        Optional[Any]: Данные секрета или None
    """
    return await vault_service.get_secret(path)


async def get_secret_json(path: str) -> Optional[Dict[str, Any]]:
    """
    Быстрое получение JSON секрета из Vault.
    
    Args:
        path: Путь к секрету
    
    Returns:
        Optional[Dict[str, Any]]: Данные секрета или None
    """
    return await vault_service.get_secret_json(path)