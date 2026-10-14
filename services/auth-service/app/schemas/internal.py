from pydantic import BaseModel, ConfigDict
from typing import Optional, Any
from uuid import UUID


class BaseInternalModel(BaseModel):
    model_config = ConfigDict(extra="allow", from_attributes=True)


class CreateUserRequest(BaseInternalModel):
    user_id: UUID
    email_hash: str
    email: str
    password_hash: str
    phone: Optional[str] = None
    is_active: bool = True
    is_email_verified: bool = False
    metadata: Optional[dict] = None


class CreateUserResponse(BaseInternalModel):
    success: bool = True
    user_id: str
    message: str = "User created successfully"


class BlockUserRequest(BaseInternalModel):
    user_id: UUID
    reason: Optional[str] = None


class BlockUserResponse(BaseInternalModel):
    success: bool = True
    user_id: str
    revoked_sessions_count: int = 0
    message: str = "User blocked successfully"


class UnblockUserRequest(BaseInternalModel):
    user_id: UUID
    reason: Optional[str] = None


class UnblockUserResponse(BaseInternalModel):
    success: bool = True
    user_id: str
    message: str = "User unblocked successfully"


class DeleteUserRequest(BaseInternalModel):
    user_id: UUID
    except_session_id: Optional[str] = None


class DeleteUserResponse(BaseInternalModel):
    success: bool = True
    user_id: str
    revoked_sessions_count: int = 0
    message: str = "User deleted successfully"


class UpdatePasswordRequest(BaseInternalModel):
    user_id: UUID
    new_password_hash: str
    except_session_id: Optional[str] = None


class UpdatePasswordResponse(BaseInternalModel):
    success: bool = True
    user_id: str
    revoked_sessions_count: int = 0
    message: str = "Password updated successfully"


class RevokeAllSessionsRequest(BaseInternalModel):
    user_id: UUID
    except_session_id: Optional[str] = None
    reason: Optional[str] = None
    publish_event: bool = True


class RevokeAllSessionsResponse(BaseInternalModel):
    success: bool = True
    user_id: str
    revoked_sessions_count: int = 0
    message: str = "All sessions revoked successfully"


class UserExistsResponse(BaseInternalModel):
    user_id: str
    exists: bool = False
    email: Optional[str] = None
    phone: Optional[str] = None
    is_active: Optional[bool] = None
    is_email_verified: Optional[bool] = None


class SessionsCountResponse(BaseInternalModel):
    user_id: str
    active_sessions_count: int = 0


class ErrorResponse(BaseInternalModel):
    detail: str
    error_code: Optional[str] = None