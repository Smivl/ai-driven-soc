from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.db import session_scope
from app.services import tenants as tenant_service

router = APIRouter()


class TenantUpdate(BaseModel):
    min_level: int = Field(ge=0, le=15)


@router.get("/tenants")
def list_tenants():
    with session_scope() as session:
        return tenant_service.list_tenants(session)


@router.patch("/tenants/{group}")
def update_tenant(group: str, body: TenantUpdate):
    with session_scope() as session:
        updated = tenant_service.update_min_level(session, group, body.min_level)
        if updated is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        return updated
