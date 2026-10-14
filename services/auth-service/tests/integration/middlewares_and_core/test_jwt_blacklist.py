import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import settings
from app.core.redis_client import redis_client
from app.services.token_service import TokenService


@pytest.fixture(scope="session")
async def test_redis():
    """Фикстура для реального Redis."""
    await redis_client.flushdb()
    yield redis_client
    await redis_client.flushdb()


@pytest.fixture
def test_db():
    """Фикстура для тестовой БД."""
    return None


@pytest.fixture
def rsa_keys():
    """Генерация реальных RSA ключей для тестов."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "private": private_pem.decode(),
        "public": public_pem.decode()
    }


@pytest.fixture
def token_service(test_db, rsa_keys, monkeypatch):
    """Фикстура TokenService с реальными зависимостями."""
    monkeypatch.setattr(settings, "JWT_ALGORITHM", "RS256")
    monkeypatch.setattr(settings, "JWT_PRIVATE_KEY", rsa_keys["private"])
    monkeypatch.setattr(settings, "JWT_PUBLIC_KEY", rsa_keys["public"])
    monkeypatch.setattr(settings, "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 15)
    monkeypatch.setattr(settings, "JWT_BLACKLIST_TTL_MINUTES", 15)
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", rsa_keys["private"])

    return TokenService(
        db=test_db,
        algorithm="RS256",
        secret_key=rsa_keys["private"],
        public_key=rsa_keys["public"]
    )


@pytest.fixture
def user_id():
    return uuid4()


@pytest.fixture
def jti():
    return str(uuid4())


class TestBlacklistAccessToken:
    """Тесты для метода blacklist_access_token."""

    async def test_blacklist_access_token_with_default_ttl(
        self,
        token_service,
        test_redis,
        jti,
    ):
        """Тест добавления токена в черный список с TTL по умолчанию."""
        await token_service.blacklist_access_token(jti=jti)

        key = f"token:blacklist:{jti}"
        assert await test_redis.exists(key) == 1
        ttl = await test_redis.ttl(key)
        assert 900 >= ttl >= 895


    async def test_blacklist_access_token_with_custom_ttl(
        self,
        token_service,
        test_redis,
        jti,
    ):
        """Тест добавления токена в черный список с кастомным TTL."""
        await token_service.blacklist_access_token(jti=jti, ttl=3600)

        key = f"token:blacklist:{jti}"
        assert await test_redis.exists(key) == 1
        ttl = await test_redis.ttl(key)
        assert 3600 >= ttl >= 3595


class TestIsBlacklisted:
    """Тесты для метода _is_blacklisted."""

    async def test_is_blacklisted_true(
        self,
        token_service,
        test_redis,
        jti,
    ):
        """Тест проверки токена в черном списке (присутствует)."""
        key = f"token:blacklist:{jti}"
        await test_redis.setex(key, 60, "1")

        assert await token_service._is_blacklisted(jti) is True

    async def test_is_blacklisted_false(
        self,
        token_service,
        test_redis,
        jti,
    ):
        """Тест проверки токена не в черном списке."""
        assert await token_service._is_blacklisted(jti) is False


class TestValidateAccessTokenWithBlacklist:
    """Тесты валидации access token с учетом черного списка."""

    async def test_validate_access_token_not_blacklisted(
        self,
        token_service,
        user_id,
        test_redis,
    ):
        """Тест валидации токена, которого нет в черном списке."""
        token = await token_service.create_access_token(
            user_id=user_id,
            email="test@example.com",
            roles=["user"]
        )

        payload = await token_service.validate_access_token(token)
        assert payload is not None
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "access"

    async def test_validate_access_token_blacklisted(
        self,
        token_service,
        user_id,
        test_redis,
    ):
        """Тест валидации токена, который в черном списке."""
        token = await token_service.create_access_token(
            user_id=user_id,
            email="test@example.com",
            roles=["user"]
        )

        payload = jwt.decode(
            token,
            settings.JWT_PUBLIC_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        jti = payload.get("jti")

        await token_service.blacklist_access_token(jti=jti)

        result = await token_service.validate_access_token(token)
        assert result is None

    async def test_validate_access_token_without_jti(
        self,
        token_service,
        user_id,
        test_redis,
    ):
        """Тест валидации токена без jti (не проверяется blacklist)."""
        token = await token_service.create_access_token(
            user_id=user_id,
            email="test@example.com",
            roles=["user"]
        )

        decoded_payload = jwt.decode(
            token,
            settings.JWT_PUBLIC_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_signature": False}
        )
        original_jti = decoded_payload.pop("jti", None)
        assert "jti" not in decoded_payload

        new_token = jwt.encode(
            decoded_payload,
            settings.JWT_PRIVATE_KEY,
            algorithm=settings.JWT_ALGORITHM
        )

        result = await token_service.validate_access_token(new_token)
        assert result is not None
        assert result.get("jti") != original_jti
        assert "jti" not in result


class TestFullBlacklistFlow:
    """Полный сценарий работы с blacklist."""

    async def test_full_flow_blacklist_token(
        self,
        token_service,
        user_id,
        test_redis,
    ):
        """Полный тест: создание токена -> добавление в blacklist -> проверка."""
        token = await token_service.create_access_token(
            user_id=user_id,
            email="test@example.com",
            roles=["user"]
        )

        payload = jwt.decode(
            token,
            settings.JWT_PUBLIC_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        jti = payload.get("jti")
        assert jti is not None

        await token_service.blacklist_access_token(jti=jti)

        assert await token_service._is_blacklisted(jti) is True

        result = await token_service.validate_access_token(token)
        assert result is None


class TestBlacklistEdgeCases:
    """Тесты для граничных случаев blacklist."""

    async def test_blacklist_access_token_empty_jti(
        self,
        token_service,
        test_redis,
    ):
        """Тест добавления в blacklist с пустым jti."""
        await token_service.blacklist_access_token(jti="")

        key = "token:blacklist:"
        assert await test_redis.exists(key) == 1

    async def test_blacklist_access_token_zero_ttl(
        self,
        token_service,
        test_redis,
        jti,
    ):
        """Тест добавления в blacklist с нулевым TTL."""
        await token_service.blacklist_access_token(jti=jti, ttl=0)

        key = f"token:blacklist:{jti}"
        ttl = await test_redis.ttl(key)
        assert ttl in (0, -2)

    async def test_redis_failure_on_blacklist(
        self,
        token_service,
        test_redis,
        jti,
        monkeypatch,
    ):
        """Тест ошибки Redis при добавлении в blacklist."""
        async def mock_setex(*args, **kwargs):
            raise Exception("Redis connection failed")

        monkeypatch.setattr(token_service._redis_client, "setex", mock_setex)

        with pytest.raises(Exception):
            await token_service.blacklist_access_token(jti=jti)

    async def test_redis_failure_on_check_blacklist(
        self,
        token_service,
        test_redis,
        jti,
        monkeypatch,
    ):
        """Тест ошибки Redis при проверке blacklist."""
        async def mock_exists(*args, **kwargs):
            raise Exception("Redis connection failed")

        monkeypatch.setattr(test_redis, "exists", mock_exists)

        result = await token_service._is_blacklisted(jti)
        assert result is False

    async def test_blacklist_key_expiration(
        self,
        token_service,
        test_redis,
        jti,
    ):
        """Тест истечения срока ключа в blacklist."""
        await token_service.blacklist_access_token(jti=jti, ttl=2)

        assert await token_service._is_blacklisted(jti) is True

        import asyncio
        await asyncio.sleep(3)

        assert await token_service._is_blacklisted(jti) is False

    async def test_blacklist_ttl_from_settings(
        self,
        token_service,
        test_redis,
        jti,
        monkeypatch,
    ):
        """Тест использования TTL из настроек."""
        monkeypatch.setattr(settings, "JWT_BLACKLIST_TTL_MINUTES", 30)
        
        new_token_service = TokenService(
            db=None,
            redis_client=test_redis,
            algorithm="RS256",
            secret_key=settings.JWT_SECRET_KEY,
            public_key=settings.JWT_PUBLIC_KEY
        )
        new_token_service._redis_client = test_redis

        await new_token_service.blacklist_access_token(jti=jti)

        key = f"token:blacklist:{jti}"
        assert await test_redis.exists(key) == 1
        ttl = await test_redis.ttl(key)
        assert 1800 >= ttl >= 1795