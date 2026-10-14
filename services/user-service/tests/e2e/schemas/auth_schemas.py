from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict

class LoginResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: UUID
    email: str
    is_email_verified: bool = False
    requires_mfa: bool = False