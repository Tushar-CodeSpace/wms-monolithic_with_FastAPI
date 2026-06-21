from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr

# MFA sub-document
class MFASchema(BaseModel):
    enabled: bool = False
    secret: Optional[str] = None

class UserSchema(BaseModel):
    id: str = Field(alias="_id")
    name: str
    email: str
    password_hash: str
    roles: List[str] = Field(default=["user"])
    permissions: List[str] = Field(default=[])
    is_active: bool = True
    is_account_verified: bool = False
    last_login_at: Optional[datetime] = None
    failed_login_attempts: int = 0
    lockout_until: Optional[datetime] = None
    mfa: MFASchema = Field(default_factory=MFASchema)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    