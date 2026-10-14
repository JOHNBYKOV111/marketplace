"""
Фикстуры для тестирования JWKS (JSON Web Key Set).

Предоставляет:
- Генерацию RSA и EC ключей для тестов
- Фикстуры с публичными и приватными ключами в PEM формате
- Зашифрованные приватные ключи (для тестирования AES-256)
- Наборы активных/неактивных/истекших ключей JWKKey
- JWKS ответы в формате RFC 7517
- Разные алгоритмы (RS256, RS384, RS512, ES256, ES384, ES512)
"""

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.models.jwk_key import JWKKey
from app.services.jwk_service import JWKService


class JWKKeyFactory:
    """
    Фабрика для создания тестовых JWK ключей.
    """
    
    @staticmethod
    def generate_rsa_key_pair(
        key_size: int = 2048,
        algorithm: str = "RS256",
    ) -> tuple[JWKKey, str, str]:
        """
        Генерация RSA ключей для тестов.
        Возвращает (модель, приватный_pem, публичный_pem)
        """
        # Генерация реальных RSA ключей
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()
        
        # Сериализация в PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        
        # Создание модели
        kid = f"test_rsa_{hashlib.sha256(public_pem.encode()).hexdigest()[:16]}"
        
        jwk_key = JWKKey(
            kid=kid,
            private_key_encrypted="",  # Не шифруем для тестов
            public_key=public_pem,
            algorithm=algorithm,
            key_type="RSA",
            is_active=False,
        )
        
        return jwk_key, private_pem, public_pem
    
    @staticmethod
    def generate_ec_key_pair(
        curve: str = "P-256",
        algorithm: str = "ES256",
    ) -> tuple[JWKKey, str, str]:
        """
        Генерация EC ключей для тестов.
        Возвращает (модель, приватный_pem, публичный_pem)
        """
        curve_map = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
        }
        curve_obj = curve_map.get(curve, ec.SECP256R1())
        
        # Генерация реальных EC ключей
        private_key = ec.generate_private_key(curve_obj)
        public_key = private_key.public_key()
        
        # Сериализация в PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        
        # Создание модели
        kid = f"test_ec_{hashlib.sha256(public_pem.encode()).hexdigest()[:16]}"
        
        jwk_key = JWKKey(
            kid=kid,
            private_key_encrypted="",
            public_key=public_pem,
            algorithm=algorithm,
            key_type="EC",
            is_active=False,
        )
        
        return jwk_key, private_pem, public_pem
    
    @staticmethod
    def create_active_key(
        kid: str = "active_key_123",
        algorithm: str = "RS256",
        key_type: str = "RSA",
    ) -> JWKKey:
        """Создание активного ключа."""
        _, _, public_pem = JWKKeyFactory.generate_rsa_key_pair()
        
        return JWKKey(
            kid=kid,
            private_key_encrypted="encrypted_private_key_for_test",
            public_key=public_pem,
            algorithm=algorithm,
            key_type=key_type,
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            created_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
    
    @staticmethod
    def create_inactive_key(
        kid: str = "inactive_key_456",
        algorithm: str = "RS256",
        key_type: str = "RSA",
    ) -> JWKKey:
        """Создание неактивного ключа."""
        _, _, public_pem = JWKKeyFactory.generate_rsa_key_pair()
        
        return JWKKey(
            kid=kid,
            private_key_encrypted="encrypted_private_key_for_test",
            public_key=public_pem,
            algorithm=algorithm,
            key_type=key_type,
            is_active=False,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            created_at=datetime.now(timezone.utc) - timedelta(days=5),
        )
    
    @staticmethod
    def create_expired_key(
        kid: str = "expired_key_789",
        algorithm: str = "RS256",
        key_type: str = "RSA",
    ) -> JWKKey:
        """Создание истекшего ключа."""
        _, _, public_pem = JWKKeyFactory.generate_rsa_key_pair()
        
        return JWKKey(
            kid=kid,
            private_key_encrypted="encrypted_private_key_for_test",
            public_key=public_pem,
            algorithm=algorithm,
            key_type=key_type,
            is_active=False,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            created_at=datetime.now(timezone.utc) - timedelta(days=35),
        )
    
    @staticmethod
    def create_rotated_key(
        kid: str = "rotated_key_101",
        rotated_by: str = "system",
        algorithm: str = "RS256",
    ) -> JWKKey:
        """Создание ключа после ротации."""
        _, _, public_pem = JWKKeyFactory.generate_rsa_key_pair()
        
        return JWKKey(
            kid=kid,
            private_key_encrypted="encrypted_private_key_rotated",
            public_key=public_pem,
            algorithm=algorithm,
            key_type="RSA",
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            created_at=datetime.now(timezone.utc) - timedelta(hours=1),
            rotated_at=datetime.now(timezone.utc) - timedelta(hours=1),
            rotated_by=rotated_by,
        )


class JWKSDataset:
    """
    Наборы данных JWKS для тестирования.
    """
    
    @staticmethod
    def get_jwks_response_single_rsa() -> dict[str, Any]:
        """JWKS ответ с одним RSA ключом."""
        return {
            "keys": [
                {
                    "kid": "rsa_key_1",
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB",
                }
            ]
        }
    
    @staticmethod
    def get_jwks_response_multiple_keys() -> dict[str, Any]:
        """JWKS ответ с несколькими ключами (RSA + EC)."""
        return {
            "keys": [
                {
                    "kid": "rsa_current",
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "rsa_modulus_value",
                    "e": "AQAB",
                },
                {
                    "kid": "ec_previous",
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": "x_coordinate_value",
                    "y": "y_coordinate_value",
                },
            ]
        }
    
    @staticmethod
    def get_rsa_jwk_public_data(kid: str = "test_rsa") -> dict[str, Any]:
        """RSA публичные данные в JWKS формате."""
        return {
            "kid": kid,
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": "test_modulus_value",
            "e": "AQAB",
        }
    
    @staticmethod
    def get_ec_jwk_public_data(
        kid: str = "test_ec",
        curve: str = "P-256",
        algorithm: str = "ES256",
    ) -> dict[str, Any]:
        """EC публичные данные в JWKS формате."""
        return {
            "kid": kid,
            "kty": "EC",
            "use": "sig",
            "alg": algorithm,
            "crv": curve,
            "x": "x_coordinate_test_value",
            "y": "y_coordinate_test_value",
        }


class JWKServiceMock:
    """
    Мок для JWKService с предопределёнными ответами.
    Используется для изоляции тестов, не требующих реальной БД.
    """
    
    def __init__(self):
        self.active_keys = []
        self.all_keys = []
        self.rotated_keys = []
    
    def setup_active_keys(self, keys: list[JWKKey]) -> None:
        """Настройка списка активных ключей."""
        self.active_keys = keys
    
    def setup_all_keys(self, keys: list[JWKKey]) -> None:
        """Настройка списка всех ключей."""
        self.all_keys = keys
    
    async def get_active_public_keys(self) -> list[JWKKey]:
        """Мок получения активных ключей."""
        return self.active_keys
    
    async def get_all_keys(self) -> list[dict[str, Any]]:
        """Мок получения всех ключей."""
        return [key.dict() for key in self.all_keys]
    
    async def rotate_keys(
        self,
        algorithm: str = "RS256",
        key_size: int = 2048,
        rotated_by: str = "system",
        grace_period_hours: int = 24,
    ) -> tuple[JWKKey, list[JWKKey]]:
        """Мок ротации ключей."""
        new_key = JWKKeyFactory.create_rotated_key(
            kid=f"rotated_{len(self.rotated_keys) + 1}",
            rotated_by=rotated_by,
            algorithm=algorithm,
        )
        self.rotated_keys.append(new_key)
        return new_key, self.active_keys
    
    async def activate_key(self, kid: str) -> bool:
        """Мок активации ключа."""
        for key in self.all_keys:
            if key.kid == kid:
                key.is_active = True
                return True
        return False
    
    async def deactivate_key(self, kid: str) -> bool:
        """Мок деактивации ключа."""
        for key in self.all_keys:
            if key.kid == kid:
                key.is_active = False
                return True
        return False


# ==================== Pytest FIXTURES ====================

@pytest.fixture
def jwk_key_factory() -> JWKKeyFactory:
    """Фикстура фабрики JWK ключей."""
    return JWKKeyFactory()


@pytest.fixture
def jwks_dataset() -> JWKSDataset:
    """Фикстура набора данных JWKS."""
    return JWKSDataset()


@pytest.fixture
def rsa_key_pair() -> tuple[JWKKey, str, str]:
    """Фикстура с RSA ключами (модель, приватный PEM, публичный PEM)."""
    return JWKKeyFactory.generate_rsa_key_pair(key_size=2048, algorithm="RS256")


@pytest.fixture
def ec_key_pair() -> tuple[JWKKey, str, str]:
    """Фикстура с EC ключами (модель, приватный PEM, публичный PEM)."""
    return JWKKeyFactory.generate_ec_key_pair(curve="P-256", algorithm="ES256")


@pytest.fixture
def active_rsa_key() -> JWKKey:
    """Фикстура активного RSA ключа."""
    return JWKKeyFactory.create_active_key(kid="active_rsa_1", algorithm="RS256", key_type="RSA")


@pytest.fixture
def active_ec_key() -> JWKKey:
    """Фикстура активного EC ключа."""
    return JWKKeyFactory.create_active_key(kid="active_ec_1", algorithm="ES256", key_type="EC")


@pytest.fixture
def inactive_rsa_key() -> JWKKey:
    """Фикстура неактивного RSA ключа."""
    return JWKKeyFactory.create_inactive_key(kid="inactive_rsa_1")


@pytest.fixture
def expired_rsa_key() -> JWKKey:
    """Фикстура истекшего RSA ключа."""
    return JWKKeyFactory.create_expired_key(kid="expired_rsa_1")


@pytest.fixture
def rotated_rsa_key() -> JWKKey:
    """Фикстура ключа после ротации."""
    return JWKKeyFactory.create_rotated_key(kid="rotated_rsa_1", rotated_by="admin")


@pytest.fixture
def multiple_jwk_keys(
    active_rsa_key: JWKKey,
    active_ec_key: JWKKey,
    inactive_rsa_key: JWKKey,
    expired_rsa_key: JWKKey,
) -> list[JWKKey]:
    """Фикстура с набором разных ключей."""
    return [active_rsa_key, active_ec_key, inactive_rsa_key, expired_rsa_key]


@pytest.fixture
def jwk_service_mock() -> JWKServiceMock:
    """Фикстура мока JWKService."""
    return JWKServiceMock()


@pytest.fixture
def jwk_service_with_keys(
    jwk_service_mock: JWKServiceMock,
    active_rsa_key: JWKKey,
    active_ec_key: JWKKey,
) -> JWKServiceMock:
    """Фикстура JWKService мока с предустановленными активными ключами."""
    jwk_service_mock.setup_active_keys([active_rsa_key, active_ec_key])
    jwk_service_mock.setup_all_keys([active_rsa_key, active_ec_key])
    return jwk_service_mock


@pytest.fixture
def jwks_response_single() -> dict[str, Any]:
    """Фикстура JWKS ответа с одним ключом."""
    return JWKSDataset.get_jwks_response_single_rsa()


@pytest.fixture
def jwks_response_multiple() -> dict[str, Any]:
    """Фикстура JWKS ответа с несколькими ключами."""
    return JWKSDataset.get_jwks_response_multiple_keys()


# ==================== HELPER ФУНКЦИИ ДЛЯ ТЕСТОВ ====================

def encrypt_private_key_for_test(private_key_pem: str, encryption_key: str = "test_encryption_key_32bytes!!!") -> str:
    """
    Шифрование приватного ключа для тестов (AES-256 с Fernet).
    """
    from cryptography.fernet import Fernet
    
    key_bytes = base64.urlsafe_b64encode(encryption_key.encode()[:32])
    fernet = Fernet(key_bytes)
    
    return fernet.encrypt(private_key_pem.encode()).decode()


def decrypt_private_key_for_test(encrypted_private_key: str, encryption_key: str = "test_encryption_key_32bytes!!!") -> str:
    """
    Дешифрование приватного ключа для тестов.
    """
    from cryptography.fernet import Fernet
    
    key_bytes = base64.urlsafe_b64encode(encryption_key.encode()[:32])
    fernet = Fernet(key_bytes)
    
    return fernet.decrypt(encrypted_private_key.encode()).decode()


async def setup_jwk_service_with_keys(
    service: JWKService,
    keys: list[JWKKey],
) -> None:
    """
    Настройка JWKService с тестовыми ключами в БД.
    """
    for key in keys:
        await service.repo.create(key)
    await service.db.commit()


async def cleanup_jwk_keys(
    service: JWKService,
    kid: str | None = None,
) -> None:
    """
    Очистка JWK ключей после тестов.
    """
    if kid:
        key = await service.repo.get_by_kid(kid)
        if key:
            await service.repo.delete(key.id)
    else:
        keys = await service.repo.get_all_keys()
        for key in keys:
            await service.repo.delete(key.id)
    await service.db.commit()


def create_jwks_key_response(
    kid: str,
    kty: str = "RSA",
    alg: str = "RS256",
    use: str = "sig",
    **kwargs,
) -> dict[str, Any]:
    """
    Создание JWKS ключа для ответа.
    """
    response = {
        "kid": kid,
        "kty": kty,
        "alg": alg,
        "use": use,
    }
    
    if kty == "RSA":
        response["n"] = kwargs.get("n", "test_modulus")
        response["e"] = kwargs.get("e", "AQAB")
    elif kty == "EC":
        response["crv"] = kwargs.get("crv", "P-256")
        response["x"] = kwargs.get("x", "test_x")
        response["y"] = kwargs.get("y", "test_y")
    
    return response