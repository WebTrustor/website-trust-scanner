import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.site import SiteStatus


class SiteCreate(BaseModel):
    domain: str


class SiteDetail(BaseModel):
    id: uuid.UUID
    owner_id: uuid.UUID
    domain: str
    status: SiteStatus
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SiteVerificationInfo(BaseModel):
    domain: str
    txt_record_name: str
    txt_record_value: str
    status: SiteStatus
