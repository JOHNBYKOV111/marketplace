"""
Unit tests for gRPC Client.

Tests cover:
- GRPCClient singleton initialization (initialize, close)
- GRPCClientError exceptions hierarchy
- _execute_grpc_call error handling (UNAVAILABLE, NOT_FOUND, timeout, other errors)
- User Service methods (notify_user_created, notify_user_deleted, notify_password_changed, get_user_profile, get_user_roles)
- Profile Service methods (update_profile)
- Mock mode when proto not available
- Singleton pattern
- Edge cases (service not initialized, exceptions, timeouts)
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import grpc
import pytest

from app.services.grpc_client import (
    GRPCClient,
    GRPCClientError,
    GRPCUnavailableError,
    GRPCUserNotFoundError,
    grpc_client,
    init_grpc_client,
    close_grpc_client,
)


class TestGRPCClientExceptions:
    """Tests for gRPC client exception hierarchy."""

    def test_grpc_client_error_base(self):
        exc = GRPCClientError("Test error")
        assert isinstance(exc, Exception)
        assert str(exc) == "Test error"

    def test_grpc_unavailable_error(self):
        exc = GRPCUnavailableError("Service unavailable")
        assert isinstance(exc, GRPCClientError)
        assert str(exc) == "Service unavailable"

    def test_grpc_user_not_found_error(self):
        exc = GRPCUserNotFoundError("User not found")
        assert isinstance(exc, GRPCClientError)
        assert str(exc) == "User not found"


class TestGRPCClientInitialization:
    """Tests for GRPCClient initialization and cleanup."""

    @pytest.fixture
    def grpc_client_instance(self):
        return GRPCClient()

    async def test_initialize_user_service_only(self, grpc_client_instance):
        import app.services.grpc_client as grpc_mod

        mock_chan_obj = AsyncMock()

        with patch.object(grpc_mod, "insecure_channel", return_value=mock_chan_obj) as mock_channel, \
             patch.object(grpc_mod, "HAS_USER_PROTO", True), \
             patch.object(grpc_mod, "HAS_PROFILE_PROTO", False), \
             patch.object(grpc_mod.settings, "USER_SERVICE_GRPC_URL", "localhost:50051"), \
             patch.object(grpc_mod.settings, "PROFILE_SERVICE_GRPC_URL", ""):

            await grpc_client_instance.initialize()
            mock_channel.assert_called_once_with("localhost:50051")

    async def test_initialize_profile_service_only(self, grpc_client_instance):
        import app.services.grpc_client as grpc_mod

        mock_chan_obj = AsyncMock()

        with patch.object(grpc_mod, "insecure_channel", return_value=mock_chan_obj) as mock_channel, \
             patch.object(grpc_mod, "HAS_USER_PROTO", False), \
             patch.object(grpc_mod, "HAS_PROFILE_PROTO", True), \
             patch.object(grpc_mod.settings, "USER_SERVICE_GRPC_URL", ""), \
             patch.object(grpc_mod.settings, "PROFILE_SERVICE_GRPC_URL", "localhost:50052"):

            await grpc_client_instance.initialize()
            mock_channel.assert_called_once_with("localhost:50052")

    async def test_initialize_both_services(self, grpc_client_instance):
        import app.services.grpc_client as grpc_mod

        mock_chan_obj = AsyncMock()

        with patch.object(grpc_mod, "insecure_channel", return_value=mock_chan_obj) as mock_channel, \
             patch.object(grpc_mod, "HAS_USER_PROTO", True), \
             patch.object(grpc_mod, "HAS_PROFILE_PROTO", True), \
             patch.object(grpc_mod.settings, "USER_SERVICE_GRPC_URL", "localhost:50051"), \
             patch.object(grpc_mod.settings, "PROFILE_SERVICE_GRPC_URL", "localhost:50052"):

            await grpc_client_instance.initialize()
            assert mock_channel.call_count == 2

    async def test_initialize_no_services(self, grpc_client_instance):
        import app.services.grpc_client as grpc_mod

        mock_chan_obj = AsyncMock()

        with patch.object(grpc_mod, "insecure_channel", return_value=mock_chan_obj) as mock_channel, \
             patch.object(grpc_mod, "HAS_USER_PROTO", False), \
             patch.object(grpc_mod, "HAS_PROFILE_PROTO", False), \
             patch.object(grpc_mod.settings, "USER_SERVICE_GRPC_URL", ""), \
             patch.object(grpc_mod.settings, "PROFILE_SERVICE_GRPC_URL", ""):

            await grpc_client_instance.initialize()
            mock_channel.assert_not_called()

    async def test_close_both_channels(self, grpc_client_instance):
        grpc_client_instance._user_service_channel = AsyncMock()
        grpc_client_instance._profile_service_channel = AsyncMock()

        await grpc_client_instance.close()

        grpc_client_instance._user_service_channel.close.assert_called_once()
        grpc_client_instance._profile_service_channel.close.assert_called_once()

    async def test_close_with_none_channels(self, grpc_client_instance):
        grpc_client_instance._user_service_channel = None
        grpc_client_instance._profile_service_channel = None

        await grpc_client_instance.close()


class TestExecuteGrpcCall:
    """Tests for _execute_grpc_call helper method."""

    @pytest.fixture
    def grpc_client_instance(self):
        return GRPCClient()

    async def test_execute_grpc_call_success(self, grpc_client_instance):
        mock_call = AsyncMock()
        mock_call.return_value = "response_data"

        result = await grpc_client_instance._execute_grpc_call(mock_call, "Test Service")

        assert result == "response_data"

    async def test_execute_grpc_call_unavailable_error(self, grpc_client_instance):
        mock_call = AsyncMock()
        mock_error = grpc.aio.AioRpcError(
            grpc.StatusCode.UNAVAILABLE, None, None, "Service unavailable"
        )
        mock_call.side_effect = mock_error

        with pytest.raises(GRPCUnavailableError) as exc_info:
            await grpc_client_instance._execute_grpc_call(mock_call, "Test Service")

        assert "Test Service is unavailable" in str(exc_info.value)

    async def test_execute_grpc_call_not_found_error(self, grpc_client_instance):
        mock_call = AsyncMock()
        mock_error = grpc.aio.AioRpcError(
            grpc.StatusCode.NOT_FOUND, None, None, "User not found"
        )
        mock_call.side_effect = mock_error

        with pytest.raises(GRPCUserNotFoundError):
            await grpc_client_instance._execute_grpc_call(mock_call, "Test Service")

    async def test_execute_grpc_call_other_grpc_error(self, grpc_client_instance):
        mock_call = AsyncMock()
        mock_error = grpc.aio.AioRpcError(
            grpc.StatusCode.PERMISSION_DENIED, None, None, "Access denied"
        )
        mock_call.side_effect = mock_error

        with pytest.raises(GRPCClientError):
            await grpc_client_instance._execute_grpc_call(mock_call, "Test Service")

    async def test_execute_grpc_call_timeout(self, grpc_client_instance):
        import asyncio

        async def slow_call():
            await asyncio.sleep(10)
            return "too late"

        with pytest.raises(GRPCClientError) as exc_info:
            await grpc_client_instance._execute_grpc_call(slow_call, "Test Service", timeout=0.01)

        assert "timed out" in str(exc_info.value)

    async def test_execute_grpc_call_generic_exception(self, grpc_client_instance):
        mock_call = AsyncMock()
        mock_call.side_effect = Exception("Connection refused")

        with pytest.raises(GRPCClientError) as exc_info:
            await grpc_client_instance._execute_grpc_call(mock_call, "Test Service")

        assert "Connection refused" in str(exc_info.value)


class TestUserServiceMethods:
    """Tests for User Service gRPC methods."""

    @pytest.fixture
    def grpc_client_instance(self):
        client = GRPCClient()
        client._user_service_stub = MagicMock()
        return client

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_notify_user_created_success(self, grpc_client_instance, user_id):
        mock_response = MagicMock()
        mock_response.success = True
        grpc_client_instance._user_service_stub.UserCreated = AsyncMock(return_value=mock_response)

        with patch("app.services.grpc_client.user_service_pb2") as mock_pb2:
            mock_pb2.UserCreatedRequest = MagicMock()

            result = await grpc_client_instance.notify_user_created(
                user_id=user_id,
                email="user@example.com",
                phone="+123456789",
                first_name="John",
                last_name="Doe",
            )

            assert result is True
            grpc_client_instance._user_service_stub.UserCreated.assert_called_once()

    async def test_notify_user_created_service_not_initialized(self, user_id):
        client = GRPCClient()
        client._user_service_stub = None

        with patch("app.services.grpc_client.HAS_USER_PROTO", True):
            result = await client.notify_user_created(user_id=user_id, email="test@example.com")

        assert result is False

    async def test_notify_user_created_grpc_error(self, grpc_client_instance, user_id):
        grpc_client_instance._user_service_stub.UserCreated = AsyncMock()
        grpc_client_instance._user_service_stub.UserCreated.side_effect = GRPCClientError("Connection failed")

        with patch("app.services.grpc_client.user_service_pb2") as mock_pb2:
            mock_pb2.UserCreatedRequest = MagicMock()

            result = await grpc_client_instance.notify_user_created(
                user_id=user_id, email="test@example.com"
            )

            assert result is False

    async def test_notify_user_deleted_success(self, grpc_client_instance, user_id):
        mock_response = MagicMock()
        mock_response.success = True
        grpc_client_instance._user_service_stub.UserDeleted = AsyncMock(return_value=mock_response)

        with patch("app.services.grpc_client.user_service_pb2") as mock_pb2:
            mock_pb2.UserDeletedRequest = MagicMock()

            result = await grpc_client_instance.notify_user_deleted(user_id=user_id)

            assert result is True

    async def test_notify_password_changed_success(self, grpc_client_instance, user_id):
        mock_response = MagicMock()
        mock_response.success = True
        grpc_client_instance._user_service_stub.PasswordChanged = AsyncMock(return_value=mock_response)

        with patch("app.services.grpc_client.user_service_pb2") as mock_pb2:
            mock_pb2.PasswordChangedRequest = MagicMock()

            result = await grpc_client_instance.notify_password_changed(user_id=user_id)

            assert result is True

    async def test_get_user_profile_success(self, grpc_client_instance, user_id):
        mock_response = MagicMock()
        mock_response.user_id = str(user_id)
        mock_response.first_name = "John"
        mock_response.last_name = "Doe"
        mock_response.email = "john@example.com"
        mock_response.phone = "+123456789"
        mock_response.is_active = True
        grpc_client_instance._user_service_stub.GetUser = AsyncMock(return_value=mock_response)

        with patch("app.services.grpc_client.user_service_pb2") as mock_pb2:
            mock_pb2.GetUserRequest = MagicMock()

            result = await grpc_client_instance.get_user_profile(user_id=user_id)

            assert result is not None
            assert result["user_id"] == str(user_id)
            assert result["first_name"] == "John"
            assert result["last_name"] == "Doe"
            assert result["email"] == "john@example.com"
            assert result["phone"] == "+123456789"
            assert result["is_active"] is True

    async def test_get_user_profile_not_found(self, grpc_client_instance, user_id):
        grpc_client_instance._user_service_stub.GetUser = AsyncMock()
        grpc_client_instance._user_service_stub.GetUser.side_effect = GRPCUserNotFoundError("User not found")

        with patch("app.services.grpc_client.user_service_pb2") as mock_pb2:
            mock_pb2.GetUserRequest = MagicMock()

            result = await grpc_client_instance.get_user_profile(user_id=user_id)

            assert result is None

    async def test_get_user_profile_service_not_initialized(self, user_id):
        client = GRPCClient()
        client._user_service_stub = None

        with patch("app.services.grpc_client.HAS_USER_PROTO", True):
            result = await client.get_user_profile(user_id=user_id)

        assert result is None

    async def test_get_user_roles_success(self, grpc_client_instance, user_id):
        mock_response = MagicMock()
        mock_response.roles = ["admin", "user", "moderator"]
        grpc_client_instance._user_service_stub.GetUserRoles = AsyncMock(return_value=mock_response)

        with patch("app.services.grpc_client.user_service_pb2") as mock_pb2:
            mock_pb2.GetUserRolesRequest = MagicMock()

            result = await grpc_client_instance.get_user_roles(user_id=user_id)

            assert result == ["admin", "user", "moderator"]

    async def test_get_user_roles_grpc_error(self, grpc_client_instance, user_id):
        grpc_client_instance._user_service_stub.GetUserRoles = AsyncMock()
        grpc_client_instance._user_service_stub.GetUserRoles.side_effect = GRPCClientError("Service error")

        with patch("app.services.grpc_client.user_service_pb2") as mock_pb2:
            mock_pb2.GetUserRolesRequest = MagicMock()

            result = await grpc_client_instance.get_user_roles(user_id=user_id)

            assert result == ["user"]

    async def test_get_user_roles_service_not_initialized(self, user_id):
        client = GRPCClient()
        client._user_service_stub = None

        with patch("app.services.grpc_client.HAS_USER_PROTO", True):
            result = await client.get_user_roles(user_id=user_id)

        assert result == ["user"]


class TestProfileServiceMethods:
    """Tests for Profile Service gRPC methods."""

    @pytest.fixture
    def grpc_client_instance(self):
        client = GRPCClient()
        client._profile_service_stub = MagicMock()
        return client

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_update_profile_success(self, grpc_client_instance, user_id):
        mock_response = MagicMock()
        mock_response.success = True
        grpc_client_instance._profile_service_stub.UpdateProfile = AsyncMock(return_value=mock_response)

        with patch("app.services.grpc_client.profile_service_pb2") as mock_pb2:
            mock_pb2.UpdateProfileRequest = MagicMock()

            result = await grpc_client_instance.update_profile(
                user_id=user_id,
                first_name="Jane",
                last_name="Smith",
                phone="+987654321",
                avatar_url="https://example.com/avatar.jpg",
            )

            assert result is True

    async def test_update_profile_minimal(self, grpc_client_instance, user_id):
        mock_response = MagicMock()
        mock_response.success = True
        grpc_client_instance._profile_service_stub.UpdateProfile = AsyncMock(return_value=mock_response)

        with patch("app.services.grpc_client.profile_service_pb2") as mock_pb2:
            mock_pb2.UpdateProfileRequest = MagicMock()

            result = await grpc_client_instance.update_profile(user_id=user_id)

            assert result is True

    async def test_update_profile_service_not_initialized(self, user_id):
        client = GRPCClient()
        client._profile_service_stub = None

        with patch("app.services.grpc_client.HAS_PROFILE_PROTO", True):
            result = await client.update_profile(user_id=user_id)

        assert result is False

    async def test_update_profile_grpc_error(self, grpc_client_instance, user_id):
        grpc_client_instance._profile_service_stub.UpdateProfile = AsyncMock()
        grpc_client_instance._profile_service_stub.UpdateProfile.side_effect = GRPCClientError("Update failed")

        with patch("app.services.grpc_client.profile_service_pb2") as mock_pb2:
            mock_pb2.UpdateProfileRequest = MagicMock()

            result = await grpc_client_instance.update_profile(user_id=user_id, first_name="Test")

            assert result is False


class TestSingletonAndLifespan:
    """Tests for singleton pattern and lifespan functions."""

    def test_grpc_client_singleton(self):
        from app.services.grpc_client import grpc_client as client1
        from app.services.grpc_client import grpc_client as client2

        assert client1 is client2
        assert isinstance(client1, GRPCClient)

    @patch.object(grpc_client, "initialize", AsyncMock())
    async def test_init_grpc_client(self):
        await init_grpc_client()
        grpc_client.initialize.assert_called_once()

    @patch.object(grpc_client, "close", AsyncMock())
    async def test_close_grpc_client(self):
        await close_grpc_client()
        grpc_client.close.assert_called_once()


class TestEdgeCases:
    """Tests for edge cases and error scenarios."""

    @pytest.fixture
    def grpc_client_instance(self):
        return GRPCClient()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_notify_user_created_with_none_optional_fields(self, grpc_client_instance, user_id):
        grpc_client_instance._user_service_stub = MagicMock()
        mock_response = MagicMock()
        mock_response.success = True
        grpc_client_instance._user_service_stub.UserCreated = AsyncMock(return_value=mock_response)

        with patch("app.services.grpc_client.user_service_pb2") as mock_pb2:
            mock_pb2.UserCreatedRequest = MagicMock()

            result = await grpc_client_instance.notify_user_created(
                user_id=user_id,
                email="test@example.com",
                phone=None,
                first_name=None,
                last_name=None,
            )

            assert result is True

    async def test_execute_grpc_call_with_empty_service_name(self, grpc_client_instance):
        mock_call = AsyncMock()
        mock_call.return_value = "response"

        result = await grpc_client_instance._execute_grpc_call(mock_call, "")

        assert result == "response"

    async def test_update_profile_with_all_none_fields(self, grpc_client_instance, user_id):
        grpc_client_instance._profile_service_stub = MagicMock()
        mock_response = MagicMock()
        mock_response.success = True
        grpc_client_instance._profile_service_stub.UpdateProfile = AsyncMock(return_value=mock_response)

        with patch("app.services.grpc_client.profile_service_pb2") as mock_pb2:
            mock_pb2.UpdateProfileRequest = MagicMock()

            result = await grpc_client_instance.update_profile(
                user_id=user_id,
                first_name=None,
                last_name=None,
                phone=None,
                avatar_url=None,
            )

            assert result is True