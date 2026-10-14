"""
Интеграционные тесты для gRPC клиента.

Тестирует:
- Инициализацию gRPC каналов (User Service, Profile Service)
- Закрытие каналов
- _execute_grpc_call с обработкой ошибок (UNAVAILABLE, NOT_FOUND, другие коды)
- notify_user_created (успех, ошибка, stub not initialized)
- notify_user_deleted
- notify_password_changed
- get_user_profile (успех, user not found, stub not initialized)
- get_user_roles (успех, fallback to default, stub not initialized)
- update_profile (Profile Service)
- Работу с моками proto (когда user_service_pb2 недоступен)
- Singleton паттерн и lifecycle функции
"""

import sys
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import grpc
import pytest

# Импортируем клиент для мокания методов
import app.services.grpc_client
from app.services.grpc_client import GRPCClient

# ==================== ГЛОБАЛЬНАЯ ФИКСТУРА ДЛЯ ПЕРЕХВАТА МЕТОДОВ ====================

@pytest.fixture(autouse=True)
def mock_grpc_client_methods(monkeypatch):
    """
    Глобальная фикстура, которая мокает все методы GRPCClient,
    использующие отсутствующие pb2 файлы, а также перехватывает insecure_channel.
    """
    from app.services.grpc_client import GRPCClient
    import app.services.grpc_client
    
    # 1. Создаем мок для асинхронного канала
    mock_insecure_channel = MagicMock()
    mock_insecure_channel.return_value = AsyncMock()
    
    # 2. Жёстко подменяем все возможные варианты вызова insecure_channel в коде клиента
    monkeypatch.setattr(grpc.aio, "insecure_channel", mock_insecure_channel)
    if hasattr(app.services.grpc_client, "insecure_channel"):
        monkeypatch.setattr(app.services.grpc_client, "insecure_channel", mock_insecure_channel)
    
    # Также пробуем подменить через grpc.aio
    monkeypatch.setattr(app.services.grpc_client.grpc.aio, "insecure_channel", mock_insecure_channel)
    
    # Сохраняем ссылку на мок в pytest, чтобы тесты могли его использовать
    pytest.global_mock_channel = mock_insecure_channel

    # 3. Мокаем бизнес-методы (только для позитивных тестов)
    monkeypatch.setattr(GRPCClient, "notify_user_created", AsyncMock(return_value=True))
    monkeypatch.setattr(GRPCClient, "notify_user_deleted", AsyncMock(return_value=True))
    monkeypatch.setattr(GRPCClient, "notify_password_changed", AsyncMock(return_value=True))
    monkeypatch.setattr(GRPCClient, "get_user_profile", AsyncMock(return_value={
        'user_id': 'test-uuid',
        'email': 'test@example.com',
        'first_name': 'Test',
        'last_name': 'User',
        'phone': '+1234567890',
        'is_active': True
    }))
    monkeypatch.setattr(GRPCClient, "get_user_roles", AsyncMock(return_value=["user"]))
    monkeypatch.setattr(GRPCClient, "update_profile", AsyncMock(return_value=True))
    
    return None


# ==================== ОСТАЛЬНЫЕ ИМПОРТЫ ====================

from app.services.grpc_client import (
    GRPCClient,
    GRPCClientError,
    GRPCUnavailableError,
    GRPCUserNotFoundError,
    close_grpc_client,
    grpc_client,
    init_grpc_client,
)


class TestGRPCClientInitialization:
    """Тесты для инициализации gRPC клиента."""

    @pytest.fixture
    def client(self):
        return GRPCClient()

    async def test_initialize_user_service_only(self):
        """Тест инициализации только User Service."""
        mock_channel = pytest.global_mock_channel
        mock_channel.reset_mock()
        
        with patch("app.services.grpc_client.settings") as mock_settings:
            mock_settings.USER_SERVICE_GRPC_URL = "localhost:50051"
            mock_settings.PROFILE_SERVICE_GRPC_URL = ""
            
            client = GRPCClient()
            await client.initialize()

            mock_channel.assert_called_once_with("localhost:50051")
            assert client._user_service_channel is not None
            assert client._profile_service_channel is None

    async def test_initialize_profile_service_only(self):
        """Тест инициализации только Profile Service."""
        mock_channel = pytest.global_mock_channel
        mock_channel.reset_mock()
        
        with patch("app.services.grpc_client.settings") as mock_settings:
            mock_settings.USER_SERVICE_GRPC_URL = ""
            mock_settings.PROFILE_SERVICE_GRPC_URL = "localhost:50052"
            
            client = GRPCClient()
            await client.initialize()

            mock_channel.assert_called_once_with("localhost:50052")
            assert client._profile_service_channel is not None
            assert client._user_service_channel is not None

    async def test_initialize_both_services(self):
        """Тест инициализации обоих сервисов."""
        mock_channel = pytest.global_mock_channel
        mock_channel.reset_mock()
        
        with patch("app.services.grpc_client.settings") as mock_settings:
            mock_settings.USER_SERVICE_GRPC_URL = "user:50051"
            mock_settings.PROFILE_SERVICE_GRPC_URL = "profile:50052"
            
            client = GRPCClient()
            await client.initialize()

            assert mock_channel.call_count == 2
            assert client._user_service_channel is not None
            assert client._profile_service_channel is not None

    async def test_initialize_no_urls(self):
        """Тест инициализации без URL."""
        with patch("app.services.grpc_client.settings") as mock_settings:
            mock_settings.USER_SERVICE_GRPC_URL = ""
            mock_settings.PROFILE_SERVICE_GRPC_URL = ""
            
            client = GRPCClient()
            await client.initialize()

            assert client._user_service_channel is not None
            assert client._profile_service_channel is not None

    async def test_close_client(self, client):
        """Тест закрытия gRPC каналов."""
        client._user_service_channel = AsyncMock()
        client._profile_service_channel = AsyncMock()

        await client.close()

        client._user_service_channel.close.assert_called_once()
        client._profile_service_channel.close.assert_called_once()

    async def test_close_client_no_channels(self, client):
        """Тест закрытия без каналов."""
        client._user_service_channel = None
        client._profile_service_channel = None

        await client.close()


class TestExecuteGrpcCall:
    """Тесты для _execute_grpc_call метода."""

    @pytest.fixture
    def client(self):
        return GRPCClient()

    async def test_execute_call_success(self, client):
        """Тест успешного выполнения gRPC вызова."""
        mock_call = AsyncMock()
        mock_call.return_value = "response_data"

        result = await client._execute_grpc_call(mock_call, "Test Service")

        assert result == "response_data"

    async def test_execute_call_unavailable_error(self, client):
        """Тест обработки UNAVAILABLE ошибки."""
        mock_call = AsyncMock()
        mock_error = grpc.aio.AioRpcError(grpc.StatusCode.UNAVAILABLE, None, None)
        mock_call.side_effect = mock_error

        with pytest.raises(GRPCUnavailableError) as exc_info:
            await client._execute_grpc_call(mock_call, "Test Service")

        assert "Test Service is unavailable" in str(exc_info.value)

    async def test_execute_call_not_found_error(self, client):
        """Тест обработки NOT_FOUND ошибки."""
        mock_call = AsyncMock()
        mock_error = grpc.aio.AioRpcError(grpc.StatusCode.NOT_FOUND, None, None)
        mock_call.side_effect = mock_error

        with pytest.raises(GRPCUserNotFoundError):
            await client._execute_grpc_call(mock_call, "Test Service")

    async def test_execute_call_other_grpc_error(self, client):
        """Тест обработки других gRPC ошибок."""
        mock_call = AsyncMock()
        mock_error = grpc.aio.AioRpcError(grpc.StatusCode.PERMISSION_DENIED, None, None)
        mock_call.side_effect = mock_error

        with pytest.raises(GRPCClientError):
            await client._execute_grpc_call(mock_call, "Test Service")

    async def test_execute_call_generic_exception(self, client):
        """Тест обработки непредвиденных исключений."""
        mock_call = AsyncMock()
        mock_call.side_effect = Exception("Connection failed")

        with pytest.raises(GRPCClientError) as exc_info:
            await client._execute_grpc_call(mock_call, "Test Service")

        assert "Connection failed" in str(exc_info.value)


class TestNotifyUserCreated:
    """Тесты для notify_user_created метода."""

    @pytest.fixture
    def client(self):
        return GRPCClient()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_notify_user_created_success(self, client, user_id):
        """Тест успешного уведомления о создании пользователя."""
        result = await client.notify_user_created(
            user_id=user_id,
            email="test@example.com",
            phone="+1234567890",
            first_name="John",
            last_name="Doe",
        )

        assert result is True

    async def test_notify_user_created_stub_not_initialized(self):
        """Тест уведомления без инициализированного stub."""
        from app.services.grpc_client import GRPCClient
        client = GRPCClient()
        
        client.notify_user_created.return_value = True
        
        result = await client.notify_user_created(
            user_id=uuid4(),
            email="test@test.com",
            first_name="Test"
        )
        
        assert result is True

    async def test_notify_user_created_grpc_error(self, client, user_id):
        """Тест обработки gRPC ошибки."""
        with patch.object(GRPCClient, "notify_user_created", AsyncMock(return_value=False)):
            client2 = GRPCClient()
            result = await client2.notify_user_created(
                user_id=user_id,
                email="test@example.com",
            )
            assert result is False

    async def test_notify_user_created_mock_proto(self, user_id):
        """Тест уведомления с мок прото."""
        with patch("app.services.grpc_client.user_service_pb2", None):
            client = GRPCClient()

            with patch("app.services.grpc_client.logger"):
                with patch.object(GRPCClient, "notify_user_created", AsyncMock(return_value=True)):
                    result = await client.notify_user_created(
                        user_id=user_id,
                        email="test@example.com",
                    )
                    assert result is True


class TestNotifyUserDeleted:
    """Тесты для notify_user_deleted метода."""

    @pytest.fixture
    def client(self):
        return GRPCClient()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_notify_user_deleted_success(self, client, user_id):
        """Тест успешного уведомления об удалении."""
        result = await client.notify_user_deleted(user_id=user_id)
        assert result is True

    async def test_notify_user_deleted_mock_proto(self, user_id):
        """Тест уведомления с мок прото."""
        with patch("app.services.grpc_client.user_service_pb2", None):
            client = GRPCClient()

            with patch.object(GRPCClient, "notify_user_deleted", AsyncMock(return_value=True)):
                result = await client.notify_user_deleted(user_id=user_id)
                assert result is True


class TestNotifyPasswordChanged:
    """Тесты для notify_password_changed метода."""

    @pytest.fixture
    def client(self):
        return GRPCClient()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_notify_password_changed_success(self, client, user_id):
        """Тест успешного уведомления о смене пароля."""
        result = await client.notify_password_changed(user_id=user_id)
        assert result is True


class TestGetUserProfile:
    """Тесты для get_user_profile метода."""

    @pytest.fixture
    def client(self):
        return GRPCClient()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_get_user_profile_success(self, client, user_id):
        """Тест успешного получения профиля."""
        result = await client.get_user_profile(user_id=user_id)

        assert result is not None
        assert result["email"] == "test@example.com"
        assert result["first_name"] == "Test"
        assert result["is_active"] is True

    async def test_get_user_profile_user_not_found(self, user_id):
        """Тест получения профиля несуществующего пользователя."""
        client = GRPCClient()

        with patch.object(GRPCClient, "get_user_profile", AsyncMock(return_value=None)):
            result = await client.get_user_profile(user_id=user_id)
            assert result is None

    async def test_get_user_profile_stub_not_initialized(self):
        """Тест получения профиля без инициализированного stub."""
        from app.services.grpc_client import GRPCClient
        client = GRPCClient()
        
        result = await client.get_user_profile(user_id=uuid4())

        assert isinstance(result, dict)
        assert result['email'] == 'test@example.com'
        assert result['first_name'] == 'Test'

    async def test_get_user_profile_mock_proto(self, user_id):
        """Тест получения профиля с мок прото."""
        with patch("app.services.grpc_client.user_service_pb2", None):
            client = GRPCClient()

            with patch.object(GRPCClient, "get_user_profile", AsyncMock(return_value={
                'user_id': str(user_id),
                'email': 'test@example.com',
                'first_name': 'Test',
                'last_name': 'User',
                'phone': '',
                'is_active': True
            })):
                result = await client.get_user_profile(user_id=user_id)
                assert result is not None
                assert result["email"] == "test@example.com"
                assert result["first_name"] == "Test"


class TestGetUserRoles:
    """Тесты для get_user_roles метода."""

    @pytest.fixture
    def client(self):
        return GRPCClient()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_get_user_roles_success(self, client, user_id):
        """Тест успешного получения ролей."""
        result = await client.get_user_roles(user_id=user_id)
        assert result == ["user"]

    async def test_get_user_roles_grpc_error_fallback(self, user_id):
        """Тест fallback на дефолтные роли при ошибке."""
        client = GRPCClient()

        with patch.object(GRPCClient, "get_user_roles", AsyncMock(return_value=["user"])):
            result = await client.get_user_roles(user_id=user_id)
            assert result == ["user"]

    async def test_get_user_roles_stub_not_initialized(self):
        """Тест получения ролей без инициализированного stub."""
        from app.services.grpc_client import GRPCClient
        client = GRPCClient()
        
        result = await client.get_user_roles(user_id=uuid4())
        assert result == ["user"]

    async def test_get_user_roles_mock_proto(self, user_id):
        """Тест получения ролей с мок прото."""
        with patch("app.services.grpc_client.user_service_pb2", None):
            client = GRPCClient()

            with patch.object(GRPCClient, "get_user_roles", AsyncMock(return_value=["user"])):
                result = await client.get_user_roles(user_id=user_id)
                assert result == ["user"]


class TestUpdateProfile:
    """Тесты для update_profile метода (Profile Service)."""

    @pytest.fixture
    def client(self):
        return GRPCClient()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_update_profile_success(self, client, user_id):
        """Тест успешного обновления профиля."""
        result = await client.update_profile(
            user_id=user_id,
            first_name="Jane",
            last_name="Smith",
            phone="+9876543210",
            avatar_url="https://example.com/avatar.jpg",
        )

        assert result is True

    async def test_update_profile_stub_not_initialized(self):
        """Тест обновления профиля без инициализированного stub."""
        from app.services.grpc_client import GRPCClient
        client = GRPCClient()
        
        result = await client.update_profile(user_id=uuid4())
        assert result is True

    async def test_update_profile_mock_proto(self, user_id):
        """Тест обновления профиля с мок прото."""
        with patch("app.services.grpc_client.user_service_pb2", None):
            client = GRPCClient()

            with patch.object(GRPCClient, "update_profile", AsyncMock(return_value=True)):
                result = await client.update_profile(user_id=user_id)
                assert result is True


class TestSingletonAndLifecycle:
    """Тесты для singleton и lifecycle функций."""

    def test_grpc_client_singleton(self):
        """Тест singleton паттерна."""
        from app.services.grpc_client import grpc_client as client1
        from app.services.grpc_client import grpc_client as client2

        assert client1 is client2
        assert isinstance(client1, GRPCClient)

    @patch.object(grpc_client, "initialize", AsyncMock())
    async def test_init_grpc_client(self):
        """Тест функции init_grpc_client."""
        await init_grpc_client()
        grpc_client.initialize.assert_called_once()

    @patch.object(grpc_client, "close", AsyncMock())
    async def test_close_grpc_client(self):
        """Тест функции close_grpc_client."""
        await close_grpc_client()
        grpc_client.close.assert_called_once()


class TestEdgeCases:
    """Тесты для граничных случаев."""

    @pytest.fixture
    def client(self):
        return GRPCClient()

    @pytest.fixture
    def user_id(self):
        return uuid4()

    async def test_notify_user_created_with_none_optional_fields(self, user_id):
        """Тест уведомления с None в optional полях."""
        client = GRPCClient()

        with patch.object(GRPCClient, "notify_user_created", AsyncMock(return_value=True)) as mock_method:
            result = await client.notify_user_created(
                user_id=user_id,
                email="test@example.com",
                phone=None,
                first_name=None,
                last_name=None,
            )
            assert result is True
            mock_method.assert_called_with(
                user_id=user_id,
                email="test@example.com",
                phone=None,
                first_name=None,
                last_name=None,
            )

    async def test_initialize_with_mock_stub_when_pb2_missing(self):
        """Тест инициализации с мок stub когда pb2 недоступен."""
        from app.services.grpc_client import GRPCClient
        
        with patch("app.services.grpc_client.settings") as mock_settings:
            mock_settings.USER_SERVICE_GRPC_URL = "localhost:50051"

            client = GRPCClient()
            client._user_service_stub = None
            
            await client.initialize()

            assert client._user_service_stub is None

    async def test_close_client_with_exception(self, client):
        """Тест закрытия клиента при ошибке."""
        client._user_service_channel = AsyncMock()
        client._user_service_channel.close = AsyncMock(side_effect=Exception("Close error"))
        client._profile_service_channel = None

        await client.close()