"""
gRPC клиент для взаимодействия с микросервисами.

Обеспечивает:
- Инициализацию gRPC каналов для User Service и Profile Service
- Единую точку входа для всех gRPC вызовов
- Обработку ошибок (UNAVAILABLE, NOT_FOUND, другие коды)
- Логирование всех вызовов
- Graceful shutdown
- Singleton паттерн для использования в приложении
- Моки для разработки (когда proto недоступен)
"""

import asyncio
from typing import Optional, Dict, Any, List
from uuid import UUID

import grpc
from grpc.aio import insecure_channel, Channel

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


# ==================== КАСТОМНЫЕ ИСКЛЮЧЕНИЯ ====================

class GRPCClientError(Exception):
    """Базовое исключение gRPC клиента."""
    pass


class GRPCUnavailableError(GRPCClientError):
    """Сервис недоступен."""
    pass


class GRPCUserNotFoundError(GRPCClientError):
    """Пользователь не найден."""
    pass


# ==================== ПРОБУЕМ ИМПОРТИРОВАТЬ PROTO ====================

try:
    # Попытка импорта proto для User Service
    import user_service_pb2
    import user_service_pb2_grpc
    HAS_USER_PROTO = True
except ImportError:
    user_service_pb2 = None
    user_service_pb2_grpc = None
    HAS_USER_PROTO = False
    logger.warning("user_service_pb2 not available, using mock mode for User Service")

try:
    # Попытка импорта proto для Profile Service
    import profile_service_pb2
    import profile_service_pb2_grpc
    HAS_PROFILE_PROTO = True
except ImportError:
    profile_service_pb2 = None
    profile_service_pb2_grpc = None
    HAS_PROFILE_PROTO = False
    logger.warning("profile_service_pb2 not available, using mock mode for Profile Service")


# ==================== ОСНОВНОЙ КЛАСС GRPC КЛИЕНТА ====================

class GRPCClient:
    """
    Клиент для взаимодействия с gRPC микросервисами.
    
    Использует singleton паттерн для единой точки доступа.
    Поддерживает graceful shutdown и обработку ошибок.
    """
    
    _instance: Optional["GRPCClient"] = None
    _initialized: bool = False
    
    def __new__(cls) -> "GRPCClient":
        """Singleton паттерн."""
        if cls._instance is None:
            cls._instance = super(GRPCClient, cls).__new__(cls)
        return cls._instance
    
    def __init__(self) -> None:
        """Инициализация клиента."""
        if not self._initialized:
            self._user_service_channel: Optional[Channel] = None
            self._profile_service_channel: Optional[Channel] = None
            self._user_service_stub = None
            self._profile_service_stub = None
            self._initialized = True
    
    async def initialize(self) -> None:
        """
        Инициализация gRPC каналов для всех сервисов.
        
        Создаёт каналы только для тех сервисов, у которых указан URL.
        Использует insecure_channel для внутреннего общения между микросервисами.
        """
        # User Service
        if settings.USER_SERVICE_GRPC_URL:
            try:
                self._user_service_channel = insecure_channel(settings.USER_SERVICE_GRPC_URL)
                
                if HAS_USER_PROTO and user_service_pb2_grpc:
                    self._user_service_stub = user_service_pb2_grpc.UserServiceStub(
                        self._user_service_channel
                    )
                
                logger.info(f"User Service gRPC channel initialized: {settings.USER_SERVICE_GRPC_URL}")
            except Exception as e:
                logger.error(f"Failed to initialize User Service gRPC channel: {e}")
                self._user_service_channel = None
                self._user_service_stub = None
        else:
            logger.info("User Service gRPC URL not configured, skipping")
        
        # Profile Service
        if settings.PROFILE_SERVICE_GRPC_URL:
            try:
                self._profile_service_channel = insecure_channel(settings.PROFILE_SERVICE_GRPC_URL)
                
                if HAS_PROFILE_PROTO and profile_service_pb2_grpc:
                    self._profile_service_stub = profile_service_pb2_grpc.ProfileServiceStub(
                        self._profile_service_channel
                    )
                
                logger.info(f"Profile Service gRPC channel initialized: {settings.PROFILE_SERVICE_GRPC_URL}")
            except Exception as e:
                logger.error(f"Failed to initialize Profile Service gRPC channel: {e}")
                self._profile_service_channel = None
                self._profile_service_stub = None
        else:
            logger.info("Profile Service gRPC URL not configured, skipping")
    
    async def close(self) -> None:
        """
        Закрытие всех gRPC каналов.
        
        Обеспечивает graceful shutdown с обработкой ошибок.
        """
        close_tasks = []
        
        if self._user_service_channel:
            try:
                await self._user_service_channel.close()
                logger.info("User Service gRPC channel closed")
            except Exception as e:
                logger.warning(f"Error closing User Service gRPC channel: {e}")
        
        if self._profile_service_channel:
            try:
                await self._profile_service_channel.close()
                logger.info("Profile Service gRPC channel closed")
            except Exception as e:
                logger.warning(f"Error closing Profile Service gRPC channel: {e}")
    
    async def _execute_grpc_call(
        self,
        call_func,
        service_name: str,
        timeout: float = 5.0
    ) -> Any:
        """
        Универсальный метод для выполнения gRPC вызовов с обработкой ошибок.
        
        Args:
            call_func: Асинхронная функция вызова (callable, который возвращает корутину)
            service_name: Имя сервиса для логирования
            timeout: Таймаут в секундах
        
        Returns:
            Any: Результат вызова
        
        Raises:
            GRPCUnavailableError: Сервис недоступен
            GRPCUserNotFoundError: Пользователь не найден
            GRPCClientError: Другая ошибка gRPC
        """
        try:
            result = await asyncio.wait_for(call_func(), timeout=timeout)
            logger.debug(f"gRPC call to {service_name} completed successfully")
            return result
        
        except asyncio.TimeoutError:
            logger.error(f"gRPC call to {service_name} timed out after {timeout}s")
            raise GRPCClientError(f"{service_name} request timed out")
        
        except grpc.aio.AioRpcError as e:
            logger.error(f"gRPC error in {service_name}: {e.code()} - {e.details()}")
            
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                raise GRPCUnavailableError(f"{service_name} is unavailable")
            
            elif e.code() == grpc.StatusCode.NOT_FOUND:
                raise GRPCUserNotFoundError(f"User not found in {service_name}")
            
            else:
                raise GRPCClientError(f"gRPC error in {service_name}: {e.code()}")
        
        except Exception as e:
            logger.error(f"Unexpected error in gRPC call to {service_name}: {e}")
            raise GRPCClientError(f"Unexpected error in {service_name}: {str(e)}")
    
    # ==================== МЕТОДЫ USER SERVICE ====================
    
    async def notify_user_created(
        self,
        user_id: UUID,
        email: str,
        phone: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
    ) -> bool:
        """
        Уведомление о создании пользователя.
        
        Args:
            user_id: ID пользователя
            email: Email пользователя
            phone: Телефон (опционально)
            first_name: Имя (опционально)
            last_name: Фамилия (опционально)
        
        Returns:
            bool: True если уведомление отправлено успешно
        """
        if not self._user_service_stub:
            if not HAS_USER_PROTO:
                logger.info(
                    f"[MOCK] UserCreated: user_id={user_id}, email={email}, "
                    f"phone={phone or ''}, first_name={first_name or ''}, last_name={last_name or ''}"
                )
                return True
            
            logger.warning(f"User Service stub not initialized for user_id={user_id}")
            return False
        
        try:
            request = user_service_pb2.UserCreatedRequest(
                user_id=str(user_id),
                email=email,
                phone=phone or "",
                first_name=first_name or "",
                last_name=last_name or "",
            )
            
            response = await self._execute_grpc_call(
                lambda: self._user_service_stub.UserCreated(request),
                "User Service: UserCreated",
            )
            
            return response.success if hasattr(response, "success") else True
        
        except GRPCClientError as e:
            logger.error(f"Failed to notify user created {user_id}: {e}")
            return False
    
    async def notify_user_deleted(self, user_id: UUID) -> bool:
        """
        Уведомление об удалении пользователя.
        
        Args:
            user_id: ID пользователя
        
        Returns:
            bool: True если уведомление отправлено успешно
        """
        if not self._user_service_stub:
            if not HAS_USER_PROTO:
                logger.info(f"[MOCK] UserDeleted: user_id={user_id}")
                return True
            
            logger.warning(f"User Service stub not initialized for user_id={user_id}")
            return False
        
        try:
            request = user_service_pb2.UserDeletedRequest(
                user_id=str(user_id),
            )
            
            response = await self._execute_grpc_call(
                lambda: self._user_service_stub.UserDeleted(request),
                "User Service: UserDeleted",
            )
            
            return response.success if hasattr(response, "success") else True
        
        except GRPCClientError as e:
            logger.error(f"Failed to notify user deleted {user_id}: {e}")
            return False
    
    async def notify_password_changed(self, user_id: UUID) -> bool:
        """
        Уведомление о смене пароля.
        
        Args:
            user_id: ID пользователя
        
        Returns:
            bool: True если уведомление отправлено успешно
        """
        if not self._user_service_stub:
            if not HAS_USER_PROTO:
                logger.info(f"[MOCK] PasswordChanged: user_id={user_id}")
                return True
            
            logger.warning(f"User Service stub not initialized for user_id={user_id}")
            return False
        
        try:
            request = user_service_pb2.PasswordChangedRequest(
                user_id=str(user_id),
            )
            
            response = await self._execute_grpc_call(
                lambda: self._user_service_stub.PasswordChanged(request),
                "User Service: PasswordChanged",
            )
            
            return response.success if hasattr(response, "success") else True
        
        except GRPCClientError as e:
            logger.error(f"Failed to notify password changed {user_id}: {e}")
            return False
    
    async def get_user_profile(self, user_id: UUID) -> Optional[Dict[str, Any]]:
        """
        Получение профиля пользователя.
        
        Args:
            user_id: ID пользователя
        
        Returns:
            Optional[Dict[str, Any]]: Данные профиля или None
        """
        if not self._user_service_stub:
            if not HAS_USER_PROTO:
                logger.info(f"[MOCK] GetUserProfile: user_id={user_id}")
                return {
                    "user_id": str(user_id),
                    "email": "test@example.com",
                    "first_name": "Test",
                    "last_name": "User",
                    "phone": "",
                    "is_active": True,
                }
            
            logger.warning(f"User Service stub not initialized for user_id={user_id}")
            return None
        
        try:
            request = user_service_pb2.GetUserRequest(
                user_id=str(user_id),
            )
            
            response = await self._execute_grpc_call(
                lambda: self._user_service_stub.GetUser(request),
                "User Service: GetUser",
            )
            
            return {
                "user_id": response.user_id,
                "email": response.email,
                "first_name": response.first_name,
                "last_name": response.last_name,
                "phone": response.phone,
                "is_active": response.is_active,
            }
        
        except GRPCUserNotFoundError:
            logger.warning(f"User not found: {user_id}")
            return None
        
        except GRPCClientError as e:
            logger.error(f"Failed to get user profile {user_id}: {e}")
            return None
    
    async def get_user_roles(self, user_id: UUID) -> List[str]:
        """
        Получение ролей пользователя.
        
        Args:
            user_id: ID пользователя
        
        Returns:
            List[str]: Список ролей (по умолчанию ["user"])
        """
        if not self._user_service_stub:
            if not HAS_USER_PROTO:
                logger.info(f"[MOCK] GetUserRoles: user_id={user_id} -> ['user']")
                return ["user"]
            
            logger.warning(f"User Service stub not initialized for user_id={user_id}")
            return ["user"]
        
        try:
            request = user_service_pb2.GetUserRolesRequest(
                user_id=str(user_id),
            )
            
            response = await self._execute_grpc_call(
                lambda: self._user_service_stub.GetUserRoles(request),
                "User Service: GetUserRoles",
            )
            
            return list(response.roles) if response.roles else ["user"]
        
        except GRPCClientError as e:
            logger.warning(f"Failed to get user roles for {user_id}: {e}, using default ['user']")
            return ["user"]
    
    # ==================== МЕТОДЫ PROFILE SERVICE ====================
    
    async def update_profile(
        self,
        user_id: UUID,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        phone: Optional[str] = None,
        avatar_url: Optional[str] = None,
    ) -> bool:
        """
        Обновление профиля пользователя.
        
        Args:
            user_id: ID пользователя
            first_name: Имя (опционально)
            last_name: Фамилия (опционально)
            phone: Телефон (опционально)
            avatar_url: URL аватара (опционально)
        
        Returns:
            bool: True если обновление успешно
        """
        if not self._profile_service_stub:
            if not HAS_PROFILE_PROTO:
                logger.info(
                    f"[MOCK] UpdateProfile: user_id={user_id}, "
                    f"first_name={first_name or ''}, last_name={last_name or ''}, "
                    f"phone={phone or ''}, avatar_url={avatar_url or ''}"
                )
                return True
            
            logger.warning(f"Profile Service stub not initialized for user_id={user_id}")
            return False
        
        try:
            request = profile_service_pb2.UpdateProfileRequest(
                user_id=str(user_id),
                first_name=first_name or "",
                last_name=last_name or "",
                phone=phone or "",
                avatar_url=avatar_url or "",
            )
            
            response = await self._execute_grpc_call(
                lambda: self._profile_service_stub.UpdateProfile(request),
                "Profile Service: UpdateProfile",
            )
            
            return response.success if hasattr(response, "success") else True
        
        except GRPCClientError as e:
            logger.error(f"Failed to update profile for {user_id}: {e}")
            return False


# ==================== SINGLETON И LIFECYCLE ====================

# Глобальный экземпляр клиента (singleton)
grpc_client = GRPCClient()


async def init_grpc_client() -> None:
    """
    Инициализация глобального gRPC клиента.
    
    Должна вызываться при старте приложения.
    """
    await grpc_client.initialize()


async def close_grpc_client() -> None:
    """
    Закрытие глобального gRPC клиента.
    
    Должна вызываться при graceful shutdown приложения.
    """
    await grpc_client.close()