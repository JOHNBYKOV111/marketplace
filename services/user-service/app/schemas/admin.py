"""
Admin Pydantic schemas for request validation.
"""

from pydantic import BaseModel, Field


class BlockUserRequest(BaseModel):
    """Schema for blocking a user."""

    reason: str = Field(
        default="",
        description="Reason for blocking the user",
        max_length=500,
    )


class UnblockUserRequest(BaseModel):
    """Schema for unblocking a user."""

    reason: str = Field(
        default="",
        description="Reason for unblocking the user",
        max_length=500,
    )