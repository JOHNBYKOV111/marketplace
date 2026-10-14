"""
Интеграционные тесты для JWKS роутера.

Тестирует реальную логику:
- Генерацию RSA-ключей (2048 бит) через JWKService напрямую
- Сохранение и чтение из БД
- Ротацию ключей
- Активацию/деактивацию
- Публичный JWKS эндпоинт
- Админские эндпоинты с реальной авторизацией
"""

import pytest_asyncio
from sqlalchemy import text
import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.core.redis_client import redis_client
from app.services.jwk_service import JWKService


@pytest_asyncio.fixture(autouse=True)
async def clean_jwks():
    """Очистка БД и Redis-кэша перед каждым тестом."""
    async with AsyncSessionLocal() as session:
        await session.execute(text("DELETE FROM jwk_keys"))
        await session.commit()
    try:
        await redis_client.delete("jwks_cache")
        await redis_client.delete("jwks:public_keys")
    except Exception:
        pass
    yield


class TestJWKSPublicRoutes:

    @pytest.mark.asyncio
    async def test_get_jwks_with_active_key(
        self,
        jwks_public_client: AsyncClient,
        jwk_service: JWKService,
        db_session: AsyncSession,
    ):
        key, _, _ = await jwk_service.generate_key_pair(algorithm="RS256", key_size=2048)
        key.is_active = True
        key.is_verification_enabled = True
        await jwk_service.save_key(key)
        await db_session.commit()
        response = await jwks_public_client.get("/.well-known/jwks.json")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["keys"]) >= 1
        kids = [k["kid"] for k in data["keys"]]
        assert kids[0] == key.kid

    @pytest.mark.asyncio
    async def test_get_jwks_empty_when_no_active_keys(
        self,
        jwks_public_client: AsyncClient,
    ):
        response = await jwks_public_client.get("/.well-known/jwks.json")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["keys"] == []


class TestAdminJWKSKeysList:

    @pytest.mark.asyncio
    async def test_list_all_keys(
        self,
        jwks_admin_client: AsyncClient,
        jwk_service: JWKService,
        db_session: AsyncSession,
    ):
        key, _, _ = await jwk_service.generate_key_pair(algorithm="RS256", key_size=2048)
        key.is_active = True
        await jwk_service.save_key(key)
        await db_session.commit()
        response = await jwks_admin_client.get("/admin/jwks/keys")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["total"] >= 1

    @pytest.mark.asyncio
    async def test_list_active_keys(
        self,
        jwks_admin_client: AsyncClient,
        jwk_service: JWKService,
        db_session: AsyncSession,
    ):
        key, _, _ = await jwk_service.generate_key_pair(algorithm="RS256", key_size=2048)
        key.is_active = True
        await jwk_service.save_key(key)
        await db_session.commit()
        response = await jwks_admin_client.get("/admin/jwks/keys/active")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["items"]) >= 1

    @pytest.mark.asyncio
    async def test_list_all_keys_unauthorized(self, client: AsyncClient):
        response = await client.get("/admin/jwks/keys")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestAdminJWKSRotate:

    @pytest.mark.asyncio
    async def test_rotate_keys_success(
        self,
        jwks_admin_client: AsyncClient,
        jwk_service: JWKService,
        db_session: AsyncSession,
    ):
        key, _, _ = await jwk_service.generate_key_pair(algorithm="RS256", key_size=2048)
        key.is_active = True
        await jwk_service.save_key(key)
        await db_session.commit()
        response = await jwks_admin_client.post(
            "/admin/jwks/rotate",
            json={"algorithm": "RS256", "key_size": 2048, "grace_period_hours": 24},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "new_kid" in data

    @pytest.mark.asyncio
    async def test_rotate_keys_requires_admin(self, client: AsyncClient):
        response = await client.post("/admin/jwks/rotate", json={})
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_rotate_keys_invalid_algorithm(
        self,
        jwks_admin_client: AsyncClient,
    ):
        response = await jwks_admin_client.post(
            "/admin/jwks/rotate", json={"algorithm": "HS256"}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestAdminJWKSActivateDeactivate:

    @pytest.mark.asyncio
    async def test_activate_key_success(
        self,
        jwks_admin_client: AsyncClient,
        jwk_service: JWKService,
        db_session: AsyncSession,
    ):
        key, _, _ = await jwk_service.generate_key_pair(algorithm="RS256", key_size=2048)
        key.is_active = True
        await jwk_service.save_key(key)
        await db_session.commit()
        await jwk_service.deactivate_key(key.kid)
        await db_session.commit()
        response = await jwks_admin_client.post(f"/admin/jwks/keys/{key.kid}/activate")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["success"] is True

    @pytest.mark.asyncio
    async def test_activate_key_not_found(
        self,
        jwks_admin_client: AsyncClient,
    ):
        response = await jwks_admin_client.post("/admin/jwks/keys/nonexistent/activate")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_deactivate_key_success(
        self,
        jwks_admin_client: AsyncClient,
        jwk_service: JWKService,
        db_session: AsyncSession,
    ):
        key1, _, _ = await jwk_service.generate_key_pair(algorithm="RS256", key_size=2048)
        key1.is_active = True
        await jwk_service.save_key(key1)
        key2, _, _ = await jwk_service.generate_key_pair(algorithm="RS256", key_size=2048)
        key2.is_active = True
        await jwk_service.save_key(key2)
        await db_session.commit()
        response = await jwks_admin_client.post(f"/admin/jwks/keys/{key1.kid}/deactivate")
        assert response.status_code == status.HTTP_200_OK


class TestAdminJWKSCleanup:

    @pytest.mark.asyncio
    async def test_cleanup_expired_keys(
        self,
        jwks_admin_client: AsyncClient,
    ):
        response = await jwks_admin_client.delete("/admin/jwks/keys/expired")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["success"] is True


class TestAdminJWKSMetrics:

    @pytest.mark.asyncio
    async def test_get_metrics(
        self,
        jwks_admin_client: AsyncClient,
        jwk_service: JWKService,
        db_session: AsyncSession,
    ):
        key, _, _ = await jwk_service.generate_key_pair(algorithm="RS256", key_size=2048)
        key.is_active = True
        await jwk_service.save_key(key)
        await db_session.commit()
        response = await jwks_admin_client.get("/admin/jwks/metrics")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["total_keys"] >= 1


class TestJWKSValidation:

    @pytest.mark.asyncio
    async def test_activate_key_invalid_kid_format(
        self,
        jwks_admin_client: AsyncClient,
    ):
        response = await jwks_admin_client.post(
            "/admin/jwks/keys/" + "a" * 100 + "/activate",
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY