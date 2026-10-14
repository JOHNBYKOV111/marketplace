"""
Схемы Pydantic для валидации данных.
"""

from app.schemas.common import (
    BaseSchema,
    PaginationParams,
    PaginatedResponse,
    MessageResponse,
    ErrorResponse,
    UUIDSchema,
)
from app.schemas.user import (
    UserBase,
    UserCreate,
    UserUpdate,
    UserResponse,
    UserListResponse,
)
from app.schemas.admin import (
    BlockRequest,
    UnblockRequest,
    AdminUserResponse,
    BlockResponse,
    UnblockResponse,
    AdminMetricsResponse,
)
from app.schemas.audit_log import (
    AuditLogCreate,
    AuditLogResponse,
    AuditLogListResponse,
    AuditActionsResponse,
)

__all__ = [
    # common
    "BaseSchema",
    "PaginationParams",
    "PaginatedResponse",
    "MessageResponse",
    "ErrorResponse",
    "UUIDSchema",
    # user
    "UserBase",
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "UserListResponse",
    # admin
    "BlockRequest",
    "UnblockRequest",
    "AdminUserResponse",
    "BlockResponse",
    "UnblockResponse",
    "AdminMetricsResponse",
    # audit
    "AuditLogCreate",
    "AuditLogResponse",
    "AuditLogListResponse",
    "AuditActionsResponse",
]