"""
User Pydantic schemas for validation and serialization.
Auth-related fields (email, is_active, is_email_verified, is_superuser)
are set at runtime from auth-service, not stored in user_db.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    """Schema for creating a user."""

    email: EmailStr = Field(..., description="User email")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User password",
    )


class UserUpdate(BaseModel):
    """Schema for updating a user."""

    email: Optional[EmailStr] = Field(None, description="New email")
    password: Optional[str] = Field(
        None,
        min_length=8,
        max_length=128,
        description="New password",
    )
    is_active: Optional[bool] = Field(None, description="Active status")
    is_email_verified: Optional[bool] = Field(None, description="Email verification status")
    is_superuser: Optional[bool] = Field(None, description="Superuser status")


class UserResponse(BaseModel):
    """Schema for user response. Auth fields set at runtime."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: Optional[str] = Field(None, description="User email (from auth-service)")
    first_name: Optional[str] = Field(None, description="First name")
    last_name: Optional[str] = Field(None, description="Last name")
    is_active: bool = Field(True, description="Active status (from auth-service)")
    is_email_verified: bool = Field(False, description="Email verification status (from auth-service)")
    is_superuser: bool = Field(False, description="Superuser status (from auth-service)")
    is_deleted: bool = Field(False, description="Soft delete flag")
    email_hash: Optional[str] = Field(None, description="SHA256 hash of email for lookups")
    created_at: Optional[datetime] = Field(None, description="Creation date")
    updated_at: Optional[datetime] = Field(None, description="Last update date")


class UserProfileResponse(BaseModel):
    """Schema for user profile response. Auth fields set at runtime."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(..., description="User ID")
    email: Optional[str] = Field(None, description="User email (from auth-service)")
    first_name: Optional[str] = Field(None, description="First name")
    last_name: Optional[str] = Field(None, description="Last name")
    username: Optional[str] = Field(None, max_length=100, description="Username")
    is_active: bool = Field(True, description="Active status (from auth-service)")
    is_email_verified: bool = Field(False, description="Email verification status (from auth-service)")
    is_superuser: bool = Field(False, description="Superuser status (from auth-service)")
    is_deleted: bool = Field(False, description="Soft delete flag")
    created_at: Optional[datetime] = Field(None, description="Creation date")
    updated_at: Optional[datetime] = Field(None, description="Last update date")
    last_login_at: Optional[datetime] = Field(None, description="Last login date")


class UserUpdateRequest(BaseModel):
    """Schema for user update request."""

    model_config = ConfigDict(extra="forbid")

    email: Optional[EmailStr] = Field(None, description="New email")
    first_name: Optional[str] = Field(None, max_length=100, description="First name")
    last_name: Optional[str] = Field(None, max_length=100, description="Last name")
    username: Optional[str] = Field(None, max_length=100, description="New username")
    is_active: Optional[bool] = Field(None, description="Active status")


class UserListResponse(BaseModel):
    """Schema for list of users."""

    items: list[UserResponse]
    total: int
    limit: int
    offset: int


class PasswordChangeRequest(BaseModel):
    """Schema for password change request."""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password",
    )


class PasswordChangeResponse(BaseModel):
    """Schema for password change response."""

    success: bool = Field(..., description="Operation success")
    message: str = Field(..., description="Result message")


class DeleteAccountRequest(BaseModel):
    """Schema for account deletion request."""

    password: str = Field(..., description="Password for confirmation")


class DeleteAccountResponse(BaseModel):
    """Schema for account deletion response."""

    success: bool = Field(..., description="Operation success")
    message: str = Field(..., description="Result message")
    user_id: UUID = Field(..., description="Deleted user ID")


class SessionInfoResponse(BaseModel):
    """Schema for session information."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(..., description="Session ID")
    user_id: UUID = Field(..., description="User ID")
    client_ip: Optional[str] = Field(None, description="Client IP")
    user_agent: Optional[str] = Field(None, description="User-Agent")
    created_at: datetime = Field(..., description="Creation date")
    expires_at: datetime = Field(..., description="Expiration date")
    is_active: bool = Field(..., description="Active status")
    last_used_at: Optional[datetime] = Field(None, description="Last used date")


class SessionListResponse(BaseModel):
    """Schema for list of sessions."""

    sessions: list[SessionInfoResponse] = Field(..., description="List of sessions")
    total: int = Field(..., description="Total number of sessions")