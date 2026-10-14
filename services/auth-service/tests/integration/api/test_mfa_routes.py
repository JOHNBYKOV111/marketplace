"""
Интеграционные тесты для MFA роутера с реальной логикой.

TOTP setup сохраняет секрет в Redis для последующей верификации.
SMS/Email коды получаются из реального MFAService (синглтон).
Вся внутренняя логика — реальная: TOTP, backup-коды, MFA сессии, Rate limiting.
"""

import pytest
from fastapi import status
from httpx import AsyncClient

from app.core.redis_client import redis_client
from app.routers.mfa import get_mfa_service


def _get_mfa_service():
    """Получить экземпляр MFAService из dependency_overrides."""
    from app.main import app
    return app.dependency_overrides.get(get_mfa_service, lambda: None)()


class TestMFATOTPRoutes:

    @pytest.mark.asyncio
    async def test_totp_setup_success(self, mfa_client: AsyncClient):
        response = await mfa_client.post("/mfa/totp/setup")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "secret_key" in data
        assert "qr_code_url" in data
        assert "qr_code_base64" in data

    @pytest.mark.asyncio
    async def test_totp_verify_success(self, mfa_client: AsyncClient):
        setup = await mfa_client.post("/mfa/totp/setup")
        assert setup.status_code == 200
        secret = setup.json()["secret_key"]
        user_id = mfa_client.headers.get("X-User-Id")

        await redis_client.set_json(f"totp:setup:{user_id}", {"secret": secret})

        import time
        import hmac
        import hashlib
        secret_bytes = bytes.fromhex(secret)
        counter = int(time.time()) // 30
        hmac_hash = hmac.new(secret_bytes, counter.to_bytes(8, "big"), hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        truncated_hash = int.from_bytes(hmac_hash[offset:offset + 4], "big") & 0x7FFFFFFF
        code = str(truncated_hash % 10**6).zfill(6)

        response = await mfa_client.post("/mfa/totp/verify", json={"code": code})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "backup_codes" in data

    @pytest.mark.asyncio
    async def test_totp_verify_invalid_code(self, mfa_client: AsyncClient):
        setup = await mfa_client.post("/mfa/totp/setup")
        user_id = mfa_client.headers.get("X-User-Id")
        secret = setup.json()["secret_key"]
        await redis_client.set_json(f"totp:setup:{user_id}", {"secret": secret})

        response = await mfa_client.post("/mfa/totp/verify", json={"code": "000000"})
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_totp_disable_success(self, mfa_client: AsyncClient):
        await mfa_client.post("/mfa/totp/setup")
        response = await mfa_client.post("/mfa/totp/disable", json={"password": "any"})
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["success"] is True


class TestMFASMSRoutes:

    @pytest.mark.asyncio
    async def test_sms_send_success(self, mfa_client: AsyncClient):
        response = await mfa_client.post("/mfa/sms/send")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["method"] == "sms"

    @pytest.mark.asyncio
    async def test_sms_verify_success(self, mfa_client: AsyncClient):
        service = _get_mfa_service()
        user_id = mfa_client.headers.get("X-User-Id")
        from uuid import UUID
        uid = UUID(user_id)

        await mfa_client.post("/mfa/sms/send")
        real_code = service._sms_codes.get(uid)

        response = await mfa_client.post("/mfa/sms/verify", json={"code": real_code or "123456"})
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["success"] is True


class TestMFAEmailRoutes:

    @pytest.mark.asyncio
    async def test_email_send_success(self, mfa_client: AsyncClient):
        response = await mfa_client.post("/mfa/email/send")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["method"] == "email"

    @pytest.mark.asyncio
    async def test_email_verify_success(self, mfa_client: AsyncClient):
        service = _get_mfa_service()
        user_id = mfa_client.headers.get("X-User-Id")
        from uuid import UUID
        uid = UUID(user_id)

        await mfa_client.post("/mfa/email/send")
        real_code = service._email_codes.get(uid)

        response = await mfa_client.post("/mfa/email/verify", json={"code": real_code or "654321"})
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["success"] is True


class TestMFAVerifyRoute:

    @pytest.mark.asyncio
    async def test_mfa_verify_invalid_session(self, mfa_client: AsyncClient):
        response = await mfa_client.post(
            "/mfa/verify",
            json={"mfa_session_id": "invalid", "code": "123456", "method": "totp"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


class TestMFABackupCodesRoutes:

    @pytest.mark.asyncio
    async def test_get_backup_codes_success(self, mfa_client: AsyncClient):
        response = await mfa_client.get("/mfa/backup-codes")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["backup_codes"]) == 10

    @pytest.mark.asyncio
    async def test_renew_backup_codes_success(self, mfa_client: AsyncClient):
        response = await mfa_client.post("/mfa/backup-codes/renew")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert len(data["backup_codes"]) == 10


class TestMFAAuthorization:

    @pytest.mark.asyncio
    async def test_mfa_endpoints_require_auth(self, client: AsyncClient):
        endpoints = [
            ("/mfa/totp/setup", "post"),
            ("/mfa/totp/verify", "post"),
            ("/mfa/sms/send", "post"),
            ("/mfa/email/send", "post"),
            ("/mfa/backup-codes", "get"),
            ("/mfa/backup-codes/renew", "post"),
        ]
        for path, method in endpoints:
            if method == "post":
                response = await client.post(path)
            else:
                response = await client.get(path)
            assert response.status_code == status.HTTP_401_UNAUTHORIZED, f"Failed for {path}"


class TestMFAValidation:

    @pytest.mark.asyncio
    async def test_totp_verify_invalid_code_format(self, mfa_client: AsyncClient):
        response = await mfa_client.post("/mfa/totp/verify", json={"code": "12345"})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_totp_verify_non_digit_code(self, mfa_client: AsyncClient):
        response = await mfa_client.post("/mfa/totp/verify", json={"code": "ABCDEF"})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_mfa_verify_invalid_method(self, mfa_client: AsyncClient):
        response = await mfa_client.post(
            "/mfa/verify",
            json={"mfa_session_id": "s", "code": "123456", "method": "invalid_method"},
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_mfa_verify_missing_fields(self, mfa_client: AsyncClient):
        response = await mfa_client.post("/mfa/verify", json={})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY