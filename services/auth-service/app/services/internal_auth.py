"""
Internal API аутентификация и безопасность.

Обеспечивает:
- Проверку Internal API Key
- IP whitelist валидацию
- Rate limiting для Internal API
- Логирование попыток доступа
- Защиту от brute force
"""

import hashlib
import hmac
import time
from typing import Optional, List
from ipaddress import ip_address, ip_network

from app.core.config import settings
from app.core.logging import get_logger
from app.core.cache import cache


logger = get_logger(__name__)


class InternalAuthService:
    """
    Сервис аутентификации для Internal API.
    
    Обеспечивает проверку API ключей и IP адресов для
    межсервисного взаимодействия.
    """
    
    def __init__(self, config=None):
        """
        Инициализация сервиса аутентификации.
        
        Args:
            config: Объект конфигурации (по умолчанию settings)
        """
        self.config = config or settings
        self._api_key = self.config.INTERNAL_API_KEY
        self._allowed_ips = self._parse_allowed_ips(
            getattr(self.config, "INTERNAL_ALLOWED_IPS", [])
        )
        self._rate_limit_enabled = getattr(
            self.config, "INTERNAL_RATE_LIMIT_ENABLED", True
        )
        self._rate_limit_requests = getattr(
            self.config, "INTERNAL_RATE_LIMIT_REQUESTS", 100
        )
        self._rate_limit_window = getattr(
            self.config, "INTERNAL_RATE_LIMIT_WINDOW", 60
        )
    
    def _parse_allowed_ips(self, ips: List[str]) -> List[ip_network]:
        """
        Парсинг списка разрешенных IP адресов.
        
        Args:
            ips: Список IP адресов/сетей в строковом формате
            
        Returns:
            List[ip_network]: Список объектов IP сетей
        """
        parsed = []
        for ip_str in ips:
            try:
                # Поддерживаем CIDR нотацию
                if "/" in ip_str:
                    parsed.append(ip_network(ip_str.strip()))
                else:
                    parsed.append(ip_network(f"{ip_str.strip()}/32"))
            except ValueError as e:
                logger.warning(f"Invalid IP address in whitelist: {ip_str} - {e}")
                continue
        return parsed
    
    def validate_api_key(self, api_key: str) -> bool:
        """
        Проверка валидности API ключа.
        
        Args:
            api_key: API ключ для проверки
            
        Returns:
            bool: True если ключ валидный
        """
        if not self._api_key:
            logger.warning("Internal API key not configured")
            return False
        
        if not api_key:
            return False
        
        # Используем constant-time сравнение для защиты от timing attacks
        return hmac.compare_digest(api_key, self._api_key)
    
    def is_ip_allowed(self, client_ip: str) -> bool:
        """
        Проверка, разрешен ли IP адрес.
        
        Args:
            client_ip: IP адрес клиента
            
        Returns:
            bool: True если IP разрешен
        """
        # Если список разрешенных IP пуст - разрешаем все
        if not self._allowed_ips:
            return True
        
        try:
            ip = ip_address(client_ip)
            
            # Проверяем принадлежность к разрешенным сетям
            for network in self._allowed_ips:
                if ip in network:
                    return True
            
            logger.warning(f"IP {client_ip} not in whitelist: {self._allowed_ips}")
            return False
            
        except ValueError as e:
            logger.warning(f"Invalid IP address: {client_ip} - {e}")
            return False
    
    async def check_rate_limit(
        self,
        client_ip: str,
        api_key: str,
    ) -> bool:
        """
        Проверка rate limit для Internal API.
        
        Args:
            client_ip: IP адрес клиента
            api_key: API ключ клиента
            
        Returns:
            bool: True если лимит не превышен
        """
        if not self._rate_limit_enabled:
            return True
        
        # Используем комбинацию IP и ключа для rate limiting
        key_hash = hashlib.md5(api_key.encode()).hexdigest()[:8]
        cache_key = f"internal_rate_limit:{key_hash}:{client_ip}"
        
        try:
            # Получаем текущее количество запросов
            current = await cache.get(cache_key) or 0
            
            if current >= self._rate_limit_requests:
                logger.warning(
                    f"Rate limit exceeded for IP {client_ip}, "
                    f"key {key_hash}: {current}/{self._rate_limit_requests}"
                )
                return False
            
            # Инкрементируем счетчик
            await cache.incr(cache_key)
            await cache.expire(cache_key, self._rate_limit_window)
            
            return True
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            # В случае ошибки кэша - пропускаем (fail open)
            return True
    
    async def authenticate(
        self,
        api_key: str,
        client_ip: Optional[str] = None,
    ) -> bool:
        """
        Полная аутентификация Internal API запроса.
        
        Args:
            api_key: API ключ
            client_ip: IP адрес клиента
            
        Returns:
            bool: True если аутентификация успешна
        """
        # 1. Проверяем API ключ
        if not self.validate_api_key(api_key):
            logger.warning(f"Invalid API key attempt from {client_ip}")
            return False
        
        # 2. Проверяем IP
        if client_ip and not self.is_ip_allowed(client_ip):
            logger.warning(f"IP {client_ip} not allowed for Internal API")
            return False
        
        # 3. Проверяем rate limit
        if client_ip and not await self.check_rate_limit(client_ip, api_key):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return False
        
        return True
    
    def get_audit_info(self, api_key: str) -> dict:
        """
        Получение информации для аудита.
        
        Args:
            api_key: API ключ
            
        Returns:
            dict: Информация для аудита
        """
        key_hash = hashlib.md5(api_key.encode()).hexdigest()[:8]
        return {
            "api_key_hash": key_hash,
            "timestamp": time.time(),
            "service": "internal_auth",
        }


# ==================== HELPER FUNCTIONS ====================

def create_internal_api_key() -> str:
    """
    Генерация нового Internal API ключа.
    
    Returns:
        str: Сгенерированный API ключ
    """
    import secrets
    import string
    
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(32))


async def verify_internal_request(
    api_key: str,
    client_ip: Optional[str] = None,
) -> bool:
    """
    Быстрая проверка Internal API запроса.
    
    Args:
        api_key: API ключ
        client_ip: IP адрес клиента
        
    Returns:
        bool: True если запрос авторизован
    """
    auth_service = InternalAuthService()
    return await auth_service.authenticate(api_key, client_ip)


def get_internal_auth_service() -> InternalAuthService:
    """
    Получение экземпляра сервиса аутентификации.
    
    Returns:
        InternalAuthService: Экземпляр сервиса
    """
    return InternalAuthService()


# ==================== КОНСТАНТЫ ====================

# Стандартные заголовки для Internal API
INTERNAL_API_KEY_HEADER = "X-Internal-API-Key"
INTERNAL_SERVICE_HEADER = "X-Internal-Service"
INTERNAL_REQUEST_ID_HEADER = "X-Internal-Request-ID"

# Префикс для кэша rate limiting
RATE_LIMIT_CACHE_PREFIX = "internal_rate_limit"

# Настройки по умолчанию
DEFAULT_RATE_LIMIT_REQUESTS = 100
DEFAULT_RATE_LIMIT_WINDOW = 60