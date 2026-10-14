"""
Vault клиент для auth-service.

Обеспечивает:
- Подключение к HashiCorp Vault
- Получение секретов
- Получение конфигураций
- Healthcheck
- Graceful shutdown
- Кэширование секретов
- Автоматическое обновление токенов
"""

import json
import asyncio
from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta

import aiohttp
from aiohttp import ClientTimeout, ClientSession, TCPConnector
from aiohttp.client_exceptions import ClientError, ClientResponseError

from app.core.config import settings
from app.core.logging import get_logger


logger = get_logger(__name__)


# ==================== КЛИЕНТ VAULT ====================

class VaultClient:
    """
    Клиент для работы с HashiCorp Vault.
    
    Предоставляет методы для получения секретов,
    управления токенами и healthcheck.
    """
    
    def __init__(self):
        """Инициализация клиента Vault."""
        self._url = settings.VAULT_URL
        self._token = settings.VAULT_TOKEN
        self._namespace = settings.VAULT_NAMESPACE
        self._session: Optional[ClientSession] = None
        self._connected = False
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl: Dict[str, datetime] = {}
        self._cache_timeout = settings.VAULT_CACHE_TTL
        self._lock = asyncio.Lock()
    
    async def connect(self) -> None:
        """
        Установка соединения с Vault.
        
        Raises:
            ClientError: Если не удалось подключиться
        """
        if self._session is not None:
            return
        
        try:
            # Создаем сессию с таймаутами
            timeout = ClientTimeout(
                total=settings.VAULT_TIMEOUT,
                connect=settings.VAULT_CONNECT_TIMEOUT,
                sock_read=settings.VAULT_TIMEOUT,
            )
            
            connector = TCPConnector(
                limit=settings.VAULT_MAX_CONNECTIONS,
                ttl_dns_cache=300,
                enable_cleanup_closed=True,
            )
            
            self._session = ClientSession(
                timeout=timeout,
                connector=connector,
                headers=self._build_headers(),
            )
            
            # Проверяем подключение
            await self.healthcheck()
            self._connected = True
            logger.info(f"Connected to Vault at {self._url}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Vault: {e}")
            self._connected = False
            raise ClientError(f"Vault connection failed: {e}")
    
    async def close(self) -> None:
        """Закрытие соединения с Vault."""
        if self._session:
            try:
                await self._session.close()
                self._connected = False
                logger.info("Vault connection closed")
            except Exception as e:
                logger.warning(f"Error closing Vault connection: {e}")
            finally:
                self._session = None
        
        # Очищаем кэш
        self._cache.clear()
        self._cache_ttl.clear()
    
    @property
    def is_connected(self) -> bool:
        """
        Проверка статуса подключения.
        
        Returns:
            bool: True если подключение установлено
        """
        return self._connected and self._session is not None
    
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
    
    def _clear_cache(self, path: Optional[str] = None) -> None:
        """
        Очистка кэша.
        
        Args:
            path: Путь для очистки (если None - очищает всё)
        """
        if path is None:
            self._cache.clear()
            self._cache_ttl.clear()
        else:
            key = self._get_cache_key(path)
            self._cache.pop(key, None)
            self._cache_ttl.pop(key, None)
    
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
            method: HTTP метод (GET, POST, PUT, DELETE)
            path: Путь запроса
            data: Данные для отправки
            params: Параметры запроса
        
        Returns:
            Dict[str, Any]: Ответ от Vault
        
        Raises:
            ClientResponseError: При ошибке HTTP
        """
        if not self._session:
            raise ClientError("Vault session not initialized")
        
        url = f"{self._url}/{path.lstrip('/')}"
        
        try:
            async with self._session.request(
                method=method,
                url=url,
                json=data,
                params=params,
            ) as response:
                response.raise_for_status()
                result = await response.json()
                
                # Проверяем ошибку Vault
                if result.get("errors"):
                    error_msg = "; ".join(result["errors"])
                    logger.error(f"Vault error: {error_msg}")
                    raise ClientError(f"Vault error: {error_msg}")
                
                return result
                
        except ClientResponseError as e:
            logger.error(f"Vault HTTP error: {e.status} - {e.message}")
            raise
        except ClientError as e:
            logger.error(f"Vault client error: {e}")
            raise
        except Exception as e:
            logger.error(f"Vault unexpected error: {e}")
            raise
    
    # ==================== РАБОТА С СЕКРЕТАМИ ====================
    
    async def read_secret(
        self,
        path: str,
        use_cache: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """
        Чтение секрета из Vault.
        
        Args:
            path: Путь к секрету (например, "secret/data/app")
            use_cache: Использовать кэш
        
        Returns:
            Optional[Dict[str, Any]]: Данные секрета или None
        """
        cache_key = self._get_cache_key(path)
        
        # Проверяем кэш
        if use_cache:
            cached = self._get_cache(cache_key)
            if cached is not None:
                return cached
        
        try:
            result = await self._request("GET", f"v1/{path}")
            
            # Извлекаем данные
            data = result.get("data", {})
            
            # Vault KV v2 возвращает nested data
            if "data" in data:
                secret_data = data["data"]
            else:
                secret_data = data
            
            # Сохраняем в кэш
            if use_cache:
                self._set_cache(cache_key, secret_data)
            
            return secret_data
            
        except ClientResponseError as e:
            if e.status == 404:
                logger.warning(f"Secret not found: {path}")
                return None
            raise
        except Exception as e:
            logger.error(f"Failed to read secret {path}: {e}")
            raise
    
    async def write_secret(
        self,
        path: str,
        data: Dict[str, Any],
        use_cache: bool = True,
    ) -> bool:
        """
        Запись секрета в Vault.
        
        Args:
            path: Путь к секрету
            data: Данные для записи
            use_cache: Использовать кэш
        
        Returns:
            bool: True если успешно
        """
        try:
            # Для KV v2 нужно обернуть данные
            payload = {"data": data}
            
            await self._request("POST", f"v1/{path}", data=payload)
            
            # Очищаем кэш
            if use_cache:
                self._clear_cache(path)
            
            logger.info(f"Secret written to {path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to write secret {path}: {e}")
            return False
    
    async def delete_secret(
        self,
        path: str,
        use_cache: bool = True,
    ) -> bool:
        """
        Удаление секрета из Vault.
        
        Args:
            path: Путь к секрету
            use_cache: Использовать кэш
        
        Returns:
            bool: True если успешно
        """
        try:
            await self._request("DELETE", f"v1/{path}")
            
            # Очищаем кэш
            if use_cache:
                self._clear_cache(path)
            
            logger.info(f"Secret deleted from {path}")
            return True
            
        except ClientResponseError as e:
            if e.status == 404:
                logger.warning(f"Secret not found for deletion: {path}")
                return False
            raise
        except Exception as e:
            logger.error(f"Failed to delete secret {path}: {e}")
            return False
    
    # ==================== РАБОТА С КОНФИГУРАЦИЯМИ ====================
    
    async def get_config(self, key: str) -> Optional[Any]:
        """
        Получение конфигурации из Vault.
        
        Args:
            key: Ключ конфигурации
        
        Returns:
            Optional[Any]: Значение конфигурации или None
        """
        try:
            # Используем KV для конфигураций
            path = f"secret/data/config/{key}"
            data = await self.read_secret(path)
            
            if data and "value" in data:
                return data["value"]
            return data
            
        except Exception as e:
            logger.error(f"Failed to get config {key}: {e}")
            return None
    
    async def set_config(self, key: str, value: Any) -> bool:
        """
        Установка конфигурации в Vault.
        
        Args:
            key: Ключ конфигурации
            value: Значение конфигурации
        
        Returns:
            bool: True если успешно
        """
        path = f"secret/data/config/{key}"
        data = {"value": value}
        return await self.write_secret(path, data)
    
    # ==================== HEALTHCHECK ====================
    
    async def healthcheck(self) -> bool:
        """
        Проверка доступности Vault.
        
        Returns:
            bool: True если Vault доступен
        """
        try:
            # Используем системный health endpoint
            result = await self._request("GET", "v1/sys/health")
            return result.get("initialized", False)
        except ClientResponseError as e:
            # Vault возвращает разные статусы в зависимости от состояния
            # 200 - healthy, 429 - standby, 503 - unsealed
            if e.status in (200, 429):
                return True
            logger.warning(f"Vault health check failed with status {e.status}")
            return False
        except Exception as e:
            logger.warning(f"Vault health check failed: {e}")
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
            Dict: Статус Vault
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
                "cluster_id": result.get("cluster_id", "unknown"),
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e),
            }
    
    # ==================== РАБОТА С ТОКЕНАМИ ====================
    
    async def create_token(
        self,
        policies: List[str],
        ttl: Optional[str] = None,
        renewable: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """
        Создание нового токена.
        
        Args:
            policies: Список политик
            ttl: Время жизни (например, "1h")
            renewable: Возможность обновления
        
        Returns:
            Optional[Dict[str, Any]]: Информация о токене
        """
        try:
            data = {
                "policies": policies,
                "renewable": renewable,
            }
            if ttl:
                data["ttl"] = ttl
            
            result = await self._request("POST", "v1/auth/token/create", data=data)
            
            auth = result.get("auth", {})
            return {
                "client_token": auth.get("client_token"),
                "accessor": auth.get("accessor"),
                "policies": auth.get("policies", []),
                "ttl": auth.get("ttl"),
                "renewable": auth.get("renewable", False),
            }
            
        except Exception as e:
            logger.error(f"Failed to create token: {e}")
            return None
    
    async def renew_token(self, token: Optional[str] = None) -> bool:
        """
        Обновление токена.
        
        Args:
            token: Токен для обновления (если None - использует текущий)
        
        Returns:
            bool: True если успешно
        """
        try:
            path = "v1/auth/token/renew-self"
            if token:
                path = f"v1/auth/token/renew/{token}"
            
            await self._request("POST", path)
            logger.info("Token renewed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to renew token: {e}")
            return False
    
    async def revoke_token(self, token: str) -> bool:
        """
        Отзыв токена.
        
        Args:
            token: Токен для отзыва
        
        Returns:
            bool: True если успешно
        """
        try:
            await self._request("POST", f"v1/auth/token/revoke/{token}")
            logger.info("Token revoked successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False
    
    # ==================== РАБОТА С СЕКРЕТНЫМИ КЛЮЧАМИ ====================
    
    async def get_db_credentials(self) -> Optional[Dict[str, str]]:
        """
        Получение учетных данных для БД.
        
        Returns:
            Optional[Dict[str, str]]: Учетные данные
        """
        return await self.read_secret(settings.VAULT_DB_PATH)
    
    async def get_redis_credentials(self) -> Optional[Dict[str, str]]:
        """
        Получение учетных данных для Redis.
        
        Returns:
            Optional[Dict[str, str]]: Учетные данные
        """
        return await self.read_secret(settings.VAULT_REDIS_PATH)
    
    async def get_kafka_credentials(self) -> Optional[Dict[str, str]]:
        """
        Получение учетных данных для Kafka.
        
        Returns:
            Optional[Dict[str, str]]: Учетные данные
        """
        return await self.read_secret(settings.VAULT_KAFKA_PATH)
    
    async def get_oauth_credentials(self) -> Optional[Dict[str, str]]:
        """
        Получение учетных данных для OAuth.
        
        Returns:
            Optional[Dict[str, str]]: Учетные данные
        """
        return await self.read_secret(settings.VAULT_OAUTH_PATH)


# ==================== ГЛОБАЛЬНЫЙ КЛИЕНТ ====================

vault_client = VaultClient()


# ==================== ИНИЦИАЛИЗАЦИЯ И ЗАКРЫТИЕ ====================

async def init_vault() -> None:
    """Инициализация Vault клиента при старте приложения."""
    await vault_client.connect()


async def close_vault() -> None:
    """Закрытие Vault клиента при завершении приложения."""
    await vault_client.close()


# ==================== HELPER ФУНКЦИИ ====================

async def get_secret(path: str) -> Optional[Dict[str, Any]]:
    """
    Быстрое получение секрета из Vault.
    
    Args:
        path: Путь к секрету
    
    Returns:
        Optional[Dict[str, Any]]: Данные секрета или None
    """
    return await vault_client.read_secret(path)


async def get_config_value(key: str) -> Optional[Any]:
    """
    Быстрое получение конфигурации из Vault.
    
    Args:
        key: Ключ конфигурации
    
    Returns:
        Optional[Any]: Значение конфигурации или None
    """
    return await vault_client.get_config(key)


async def set_config_value(key: str, value: Any) -> bool:
    """
    Быстрая установка конфигурации в Vault.
    
    Args:
        key: Ключ конфигурации
        value: Значение конфигурации
    
    Returns:
        bool: True если успешно
    """
    return await vault_client.set_config(key, value)