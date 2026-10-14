"""
Audit log Pydantic schemas for serialization.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AuditLogItem(BaseModel):
    """Schema for a single audit log entry."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(..., description="Audit log ID")
    action: str = Field(..., description="Action performed")
    success: bool = Field(..., description="Whether the action succeeded")
    ip_address: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = Field(None, description="Client User-Agent")
    details: Optional[dict] = Field(None, description="Additional details")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    created_at: datetime = Field(..., description="When the action occurred")


class AuditLogListResponse(BaseModel):
    """Schema for paginated list of audit logs."""

    items: list[AuditLogItem] = Field(..., description="List of audit log entries")
    total: int = Field(..., description="Total number of records")
    limit: int = Field(..., description="Page size")
    offset: int = Field(..., description="Page offset")