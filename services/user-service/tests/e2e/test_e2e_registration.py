"""
E2E Integration Test: User Registration Flow (Internal API → auth → user profile)
"""

import hashlib
from uuid import uuid4

import bcrypt
import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from tests.e2e.schemas.auth_schemas import LoginResponse as AuthLoginResponse
from app.schemas.user import UserProfileResponse


AUTH_PEPPER = "your-pepper-change-in-production"

USER_TEST_DB_URL = "postgresql+asyncpg://postgres:postgres@postgres:5432/user_db_test"


def _unique_email(base_email: str) -> str:
    suffix = str(uuid4())[:8]
    parts = base_email.split("@")
    return f"{parts[0]}+{suffix}@{parts[1]}"


def _normalize_email(email: str) -> str:
    """Отрезает +суффикс — совпадает с логикой user-service."""
    if "+" in email:
        local, domain = email.split("@", 1)
        local = local.split("+")[0]
        return f"{local}@{domain}"
    return email


def _hash_password(password: str) -> str:
    peppered = f"{password}{AUTH_PEPPER}".encode("utf-8")
    return bcrypt.hashpw(peppered, bcrypt.gensalt(rounds=12)).decode("utf-8")


async def _seed_user_profile(
    user_id: str,
    email_hash: str,
    first_name: str,
    last_name: str,
) -> None:
    """Прямой SQL-сидинг в user-service БД с AUTOCOMMIT."""
    isolated_engine = create_async_engine(
        USER_TEST_DB_URL,
        isolation_level="AUTOCOMMIT",
    )
    try:
        async with isolated_engine.connect() as conn:
            await conn.execute(
                text(
                    """
                    INSERT INTO users (id, email_hash, first_name, last_name, is_deleted)
                    VALUES (:id, :email_hash, :first_name, :last_name, false)
                    ON CONFLICT (id) DO UPDATE
                    SET first_name = :first_name, last_name = :last_name, is_deleted = false
                    """
                ),
                {
                    "id": user_id,
                    "email_hash": email_hash,
                    "first_name": first_name,
                    "last_name": last_name,
                },
            )
    finally:
        await isolated_engine.dispose()


class TestE2ERegistration:

    @pytest.mark.asyncio
    async def test_full_registration_flow(
        self,
        auth_client: AsyncClient,
        user_client: AsyncClient,
        dynamic_user_credentials: dict,
        db_session: AsyncSession,
    ):
        email = _unique_email(dynamic_user_credentials["email"])
        password = dynamic_user_credentials["password"]
        first_name = dynamic_user_credentials["first_name"]
        last_name = dynamic_user_credentials["last_name"]
        user_id = str(uuid4())

        # Нормализация email перед хэшированием
        email_clean = _normalize_email(email)
        email_hash = hashlib.sha256(email_clean.lower().strip().encode("utf-8")).hexdigest()
        password_hash = _hash_password(password)

        create_resp = await auth_client.post(
            "/internal/user/create",
            json={
                "user_id": user_id,
                "email": email,
                "email_hash": email_hash,
                "password_hash": password_hash,
                "first_name": first_name,
                "last_name": last_name,
            },
            headers={"X-Internal-API-Key": "test_api_key"},
        )
        assert create_resp.status_code in (200, 201, 204), (
            f"User creation failed: {create_resp.status_code} — {create_resp.text}"
        )

        login_resp = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login_resp.status_code == 200, (
            f"Login failed after registration: {login_resp.status_code} — {login_resp.text}"
        )

        auth_data = AuthLoginResponse.model_validate(login_resp.json())
        assert auth_data.access_token
        assert auth_data.email == email

        # Прямой SQL-сидинг с AUTOCOMMIT
        await _seed_user_profile(
            user_id=user_id,
            email_hash=email_hash,
            first_name=first_name,
            last_name=last_name,
        )

        jwt_headers = {"Authorization": f"Bearer {auth_data.access_token}"}
        profile_resp = await user_client.get("/users/me", headers=jwt_headers)
        assert profile_resp.status_code == 200, (
            f"Profile access failed: {profile_resp.status_code}"
        )

        profile = UserProfileResponse.model_validate(profile_resp.json())
        assert profile.email == email
        assert profile.first_name == first_name
        assert profile.last_name == last_name

        await auth_client.post(
            "/internal/user/delete",
            json={"user_id": user_id},
            headers={"X-Internal-API-Key": "test_api_key"},
        )

    @pytest.mark.asyncio
    async def test_registration_allows_immediate_login(
        self,
        auth_client: AsyncClient,
        dynamic_user_credentials: dict,
    ):
        email = _unique_email(dynamic_user_credentials["email"])
        password = dynamic_user_credentials["password"]
        user_id = str(uuid4())

        email_clean = _normalize_email(email)
        email_hash = hashlib.sha256(email_clean.lower().strip().encode("utf-8")).hexdigest()
        password_hash = _hash_password(password)

        create_resp = await auth_client.post(
            "/internal/user/create",
            json={
                "user_id": user_id,
                "email": email,
                "email_hash": email_hash,
                "password_hash": password_hash,
            },
            headers={"X-Internal-API-Key": "test_api_key"},
        )
        assert create_resp.status_code in (200, 201, 204)

        login_resp = await auth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login_resp.status_code == 200
        assert login_resp.json()["access_token"]

        await auth_client.post(
            "/internal/user/delete",
            json={"user_id": user_id},
            headers={"X-Internal-API-Key": "test_api_key"},
        )

    @pytest.mark.asyncio
    async def test_duplicate_email_rejected(
        self,
        auth_client: AsyncClient,
        dynamic_user_credentials: dict,
    ):
        email = _unique_email(dynamic_user_credentials["email"])
        password = dynamic_user_credentials["password"]
        user_id_1 = str(uuid4())
        user_id_2 = str(uuid4())

        email_clean = _normalize_email(email)
        email_hash = hashlib.sha256(email_clean.lower().strip().encode("utf-8")).hexdigest()
        password_hash = _hash_password(password)

        first = await auth_client.post(
            "/internal/user/create",
            json={
                "user_id": user_id_1,
                "email": email,
                "email_hash": email_hash,
                "password_hash": password_hash,
            },
            headers={"X-Internal-API-Key": "test_api_key"},
        )
        assert first.status_code in (200, 201, 204)

        second = await auth_client.post(
            "/internal/user/create",
            json={
                "user_id": user_id_2,
                "email": email,
                "email_hash": email_hash,
                "password_hash": password_hash,
            },
            headers={"X-Internal-API-Key": "test_api_key"},
        )
        assert second.status_code in (400, 409), (
            f"Duplicate email should be rejected, got {second.status_code}"
        )

        await auth_client.post(
            "/internal/user/delete",
            json={"user_id": user_id_1},
            headers={"X-Internal-API-Key": "test_api_key"},
        )

    @pytest.mark.asyncio
    async def test_registration_requires_internal_api_key(
        self,
        auth_client: AsyncClient,
        dynamic_user_credentials: dict,
    ):
        response = await auth_client.post(
            "/internal/user/create",
            json={
                "user_id": str(uuid4()),
                "email": dynamic_user_credentials["email"],
                "email_hash": "some_hash",
                "password_hash": dynamic_user_credentials["password"],
            },
        )

        assert response.status_code == 401, (
            f"Expected 401 without API key, got {response.status_code}"
        )