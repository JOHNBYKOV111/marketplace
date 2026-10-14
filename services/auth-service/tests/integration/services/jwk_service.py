"""
Сервис для работы с JWK (JSON Web Key) ключами.

Обеспечивает:
- Генерацию асимметричных ключей (RSA, EC)
- Ротацию ключей с grace period
- Активацию/деактивацию ключей
- Очистку истекших ключей
- Получение публичных ключей в формате JWKS
- Шифрование приватных ключей
- Кэширование JWKS в Redis
- Метрики и мониторинг

Связанные модули:
- app.models.jwk_key - модель JWKKey
- app.repositories.jwk_key_repository - CRUD операции
- app.routers.jwks - эндпоинты
"""

import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Tuple
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from app.core.config import settings
from app.core.exceptions import (
    BadRequestException,
    NotFoundException,
    ConflictException,
)
from app.core.logging import get_logger
from app.core.redis_client import redis_client
from app.models.jwk_key import JWKKey
from app.repositories.jwk_key_repository import JWKKeyRepository

logger = get_logger(__name__)


class JWKService:
    """
    Сервис для управления JWK ключами.

    Отвечает за:
    - Генерацию ключей (RSA, EC)
    - Ротацию ключей
    - Активацию/деактивацию
    - Получение JWKS
    - Метрики
    """

    def __init__(self, repository: JWKKeyRepository):
        """
        Инициализация сервиса.

        Args:
            repository: Репозиторий JWK ключей
        """
        self.repo = repository
        self._cache_key = "jwks:public_keys"
        self._cache_ttl = 3600  # 1 час

    # ==================== ГЕНЕРАЦИЯ КЛЮЧЕЙ ====================

    async def generate_key_pair(
        self,
        algorithm: str = "RS256",
        key_size: int = 2048,
    ) -> Tuple[JWKKey, str, str]:
        """
        Генерация пары ключей (приватный + публичный).

        Args:
            algorithm: Алгоритм подписи (RS256, ES256, etc.)
            key_size: Размер ключа (для RSA)

        Returns:
            Tuple[JWKKey, str, str]: (объект ключа, приватный PEM, публичный PEM)

        Raises:
            ValueError: Если алгоритм не поддерживается
        """
        kid = self._generate_kid()

        if algorithm.startswith("RS"):
            private_key, public_key = self._generate_rsa_key_pair(
                key_size=key_size,
            )
        elif algorithm.startswith("ES"):
            curve = self._get_ec_curve(algorithm)
            private_key, public_key = self._generate_ec_key_pair(curve)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        # Конвертируем в PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Создаем объект JWKKey
        expires_at = datetime.now(timezone.utc) + timedelta(days=365)

        key = JWKKey(
            kid=kid,
            private_key_encrypted=private_pem,
            public_key=public_pem,
            algorithm=algorithm,
            key_type="RSA" if algorithm.startswith("RS") else "EC",
            is_active=False,
            is_verification_enabled=True,
            is_expired=False,
            expires_at=expires_at,
            key_size=key_size if algorithm.startswith("RS") else None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )

        logger.info(f"Generated key pair with kid: {kid}, algorithm: {algorithm}")
        return key, private_pem, public_pem

    def _generate_rsa_key_pair(self, key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Генерация RSA ключевой пары.

        Args:
            key_size: Размер ключа (2048, 4096)

        Returns:
            Tuple[RSAPrivateKey, RSAPublicKey]: (приватный, публичный)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def _generate_ec_key_pair(self, curve) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """
        Генерация EC ключевой пары.

        Args:
            curve: Elliptic curve

        Returns:
            Tuple[ECPrivateKey, ECPublicKey]: (приватный, публичный)
        """
        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def _get_ec_curve(self, algorithm: str) -> ec.EllipticCurve:
        """
        Получение EC кривой по алгоритму.

        Args:
            algorithm: ES256, ES384, ES512

        Returns:
            EllipticCurve: Объект кривой

        Raises:
            ValueError: Если алгоритм не поддерживается
        """
        curves = {
            "ES256": ec.SECP256R1(),
            "ES384": ec.SECP384R1(),
            "ES512": ec.SECP521R1(),
        }
        if algorithm not in curves:
            raise ValueError(f"Unsupported EC algorithm: {algorithm}")
        return curves[algorithm]

    def _generate_kid(self) -> str:
        """
        Генерация уникального Key ID.

        Returns:
            str: Уникальный kid
        """
        return f"key_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(8)}"

    # ==================== СОХРАНЕНИЕ И ЗАГРУЗКА ====================

    async def save_key(self, key: JWKKey) -> JWKKey:
        """
        Сохранение ключа в БД.

        Args:
            key: Объект JWKKey

        Returns:
            JWKKey: Сохраненный ключ

        Raises:
            ConflictException: Если kid уже существует
        """
        existing = await self.repo.get_by_kid(key.kid)
        if existing:
            raise ConflictException(f"Key with kid {key.kid} already exists")

        return await self.repo.create(key)

    async def get_key(self, kid: str) -> Optional[JWKKey]:
        """
        Получение ключа по kid.

        Args:
            kid: Key ID

        Returns:
            Optional[JWKKey]: Найденный ключ или None
        """
        return await self.repo.get_by_kid(kid)

    async def get_all_keys(self) -> List[JWKKey]:
        """
        Получение всех ключей.

        Returns:
            List[JWKKey]: Список ключей
        """
        return await self.repo.get_all_keys()

    async def get_active_keys(self) -> List[JWKKey]:
        """
        Получение активных ключей.

        Returns:
            List[JWKKey]: Список активных ключей
        """
        return await self.repo.get_active_keys()

    async def get_keys_for_verification(self) -> List[JWKKey]:
        """
        Получение ключей для верификации.

        Returns:
            List[JWKKey]: Список ключей для верификации
        """
        return await self.repo.get_keys_for_verification()

    # ==================== АКТИВАЦИЯ / ДЕАКТИВАЦИЯ ====================

    async def activate_key(self, kid: str, activated_by: Optional[str] = None) -> bool:
        """
        Активация ключа.

        Args:
            kid: Key ID
            activated_by: Кто активировал

        Returns:
            bool: True если успешно

        Raises:
            NotFoundException: Если ключ не найден
        """
        key = await self.repo.get_by_kid(kid)
        if not key:
            raise NotFoundException(f"Key with kid {kid} not found")

        if key.is_active:
            logger.warning(f"Key {kid} is already active")
            return True

        result = await self.repo.activate_key(kid, activated_by)
        if result:
            await self._invalidate_cache()
            logger.info(f"Key {kid} activated by {activated_by or 'system'}")
        return result

    async def deactivate_key(self, kid: str) -> bool:
        """
        Деактивация ключа.

        Args:
            kid: Key ID

        Returns:
            bool: True если успешно

        Raises:
            NotFoundException: Если ключ не найден
        """
        key = await self.repo.get_by_kid(kid)
        if not key:
            raise NotFoundException(f"Key with kid {kid} not found")

        if not key.is_active:
            logger.warning(f"Key {kid} is already inactive")
            return True

        # Проверяем, что это не единственный активный ключ
        active_keys = await self.repo.get_active_keys()
        if len(active_keys) <= 1:
            logger.warning(f"Cannot deactivate the only active key: {kid}")
            return False

        result = await self.repo.deactivate_key(kid)
        if result:
            await self._invalidate_cache()
            logger.info(f"Key {kid} deactivated")
        return result

    async def expire_key(self, kid: str) -> bool:
        """
        Помечаем ключ как истекший.

        Args:
            kid: Key ID

        Returns:
            bool: True если успешно

        Raises:
            NotFoundException: Если ключ не найден
        """
        key = await self.repo.get_by_kid(kid)
        if not key:
            raise NotFoundException(f"Key with kid {kid} not found")

        result = await self.repo.expire_key(kid)
        if result:
            await self._invalidate_cache()
            logger.info(f"Key {kid} marked as expired")
        return result

    # ==================== РОТАЦИЯ КЛЮЧЕЙ ====================

    async def rotate_keys(
        self,
        algorithm: str = "RS256",
        key_size: int = 2048,
        grace_period_hours: int = 24,
        rotated_by: Optional[str] = None,
    ) -> Tuple[JWKKey, str, str]:
        """
        Ротация ключей.

        Создает новый ключ, деактивирует старые после grace period.

        Args:
            algorithm: Алгоритм для нового ключа
            key_size: Размер ключа
            grace_period_hours: Grace period для старых ключей
            rotated_by: Кто выполняет ротацию

        Returns:
            Tuple[JWKKey, str, str]: (новый ключ, приватный PEM, публичный PEM)

        Raises:
            ValueError: Если алгоритм не поддерживается
            ConflictException: Если kid уже существует
        """
        # Генерируем новый ключ
        new_key, private_pem, public_pem = await self.generate_key_pair(
            algorithm=algorithm,
            key_size=key_size,
        )
        new_key.created_by = rotated_by
        new_key.is_active = True
        new_key.activated_at = datetime.now(timezone.utc)
        new_key.activated_by = rotated_by

        # Сохраняем новый ключ
        saved_key = await self.save_key(new_key)

        # Деактивируем старые ключи с учетом grace period
        active_keys = await self.repo.get_active_keys()
        now = datetime.now(timezone.utc)

        for key in active_keys:
            if key.kid == saved_key.kid:
                continue

            # Если ключ старше grace period, деактивируем
            if key.created_at < (now - timedelta(hours=grace_period_hours)):
                await self.repo.deactivate_key(key.kid)
                logger.info(f"Key {key.kid} deactivated during rotation (grace period expired)")

        await self._invalidate_cache()
        logger.info(f"Keys rotated, new kid: {saved_key.kid}")

        return saved_key, private_pem, public_pem

    # ==================== JWKS ====================

    async def get_jwks(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Получение JWKS (JSON Web Key Set).

        Args:
            force_refresh: Принудительное обновление кэша

        Returns:
            Dict[str, Any]: JWKS данные
        """
        # Пытаемся получить из кэша
        if not force_refresh:
            cached = await self._get_cached_jwks()
            if cached:
                return cached

        # Получаем активные ключи
        keys = await self.repo.get_keys_for_verification()

        # Формируем JWKS
        jwks_data = {
            "keys": [key.get_jwks_public_data() for key in keys if key.is_valid]
        }

        # Сохраняем в кэш
        await self._cache_jwks(jwks_data)

        return jwks_data

    # ==================== МЕТРИКИ ====================

    async def get_key_metrics(self) -> Tuple[int, int, int]:
        """
        Получение метрик ключей.

        Returns:
            Tuple[int, int, int]: (активные, истекшие, всего)
        """
        active = await self.repo.count_active_keys()
        expired = await self.repo.count_expired_keys()
        total = await self.repo.count_total_keys()
        return active, expired, total

    async def get_metrics_data(self) -> Dict[str, Any]:
        """
        Получение расширенных метрик.

        Returns:
            Dict[str, Any]: Метрики
        """
        active, expired, total = await self.get_key_metrics()
        by_algorithm = await self.repo.count_keys_by_algorithm()

        return {
            "active_keys": active,
            "expired_keys": expired,
            "total_keys": total,
            "keys_by_algorithm": by_algorithm,
            "grace_period_hours": getattr(settings, 'JWKS_GRACE_PERIOD_HOURS', 24),
            "algorithm": getattr(settings, 'JWT_ALGORITHM', 'RS256'),
        }

    # ==================== ОЧИСТКА ====================

    async def cleanup_expired_keys(self) -> int:
        """
        Очистка истекших ключей.

        Returns:
            int: Количество удаленных ключей
        """
        count = await self.repo.delete_expired_keys()
        if count > 0:
            await self._invalidate_cache()
            logger.info(f"Cleaned up {count} expired keys")
        return count

    # ==================== КЭШИРОВАНИЕ ====================

    async def _get_cached_jwks(self) -> Optional[Dict[str, Any]]:
        """
        Получение JWKS из кэша Redis.

        Returns:
            Optional[Dict[str, Any]]: JWKS данные или None
        """
        try:
            if not redis_client:
                return None

            cached = await redis_client.get(self._cache_key)
            if cached:
                return json.loads(cached)
        except Exception as e:
            logger.warning(f"Failed to get JWKS from cache: {e}")

        return None

    async def _cache_jwks(self, data: Dict[str, Any]) -> None:
        """
        Сохранение JWKS в кэш Redis.

        Args:
            data: JWKS данные
        """
        try:
            if not redis_client:
                return

            await redis_client.setex(
                self._cache_key,
                self._cache_ttl,
                json.dumps(data),
            )
        except Exception as e:
            logger.warning(f"Failed to cache JWKS: {e}")

    async def _invalidate_cache(self) -> None:
        """
        Инвалидация кэша JWKS.
        """
        try:
            if not redis_client:
                return

            await redis_client.delete(self._cache_key)
            logger.debug("JWKS cache invalidated")
        except Exception as e:
            logger.warning(f"Failed to invalidate JWKS cache: {e}")

    # ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================

    async def health_check(self) -> bool:
        """
        Проверка здоровья сервиса.

        Returns:
            bool: True если сервис работает
        """
        try:
            # Проверяем подключение к БД через репозиторий
            await self.repo.count_total_keys()
            return True
        except Exception as e:
            logger.error(f"JWKService health check failed: {e}")
            return False

    async def get_primary_key(self) -> Optional[JWKKey]:
        """
        Получение первичного активного ключа.

        Returns:
            Optional[JWKKey]: Первичный ключ или None
        """
        return await self.repo.get_primary_key()

    async def get_key_by_algorithm(self, algorithm: str) -> Optional[JWKKey]:
        """
        Получение активного ключа по алгоритму.

        Args:
            algorithm: Алгоритм

        Returns:
            Optional[JWKKey]: Ключ или None
        """
        return await self.repo.get_active_key_by_algorithm(algorithm)