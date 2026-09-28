from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    issuer: str
    account_name: str
    algorithm: str
    digits: int
    period: int
    created_at: datetime
    updated_at: datetime


class OtpOut(BaseModel):
    code: str
    expires_in: int


class ClientCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    role: str = Field(pattern="^(admin|otp)$")
    expires_at: datetime | None = None


class ClientCreated(BaseModel):
    id: str
    name: str
    role: str
    expires_at: datetime | None
    api_key: str


class ClientOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    role: str
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    event_type: str
    actor_client_id: str | None
    credential_id: str | None
    outcome: str
    request_id: str | None
    source_address: str | None
    metadata_json: str
    created_at: datetime

