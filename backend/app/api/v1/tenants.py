from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app import state
from app.api.deps import get_current_user, require_admin
from app.db import session_scope
from app.services import tenants as tenant_service

router = APIRouter()


class TenantUpdate(BaseModel):
    company: str | None = None
    description: str | None = None
    industry: str | None = None
    website: str | None = None
    phone: str | None = None
    address: str | None = None
    min_level: int | None = Field(default=None, ge=0, le=15)
    notify_level: int | None = Field(default=None, ge=0, le=15)
    window_size: int | None = Field(default=None, ge=1, le=200)


class ContactIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role: str | None = None
    email: str | None = None
    phone: str | None = None


class RecipientIn(BaseModel):
    user_id: int | None = None
    email: str | None = None


@router.get("/tenants", dependencies=[Depends(get_current_user)])
def list_tenants():
    with session_scope() as session:
        return tenant_service.list_tenants(session)


@router.get("/assessments", dependencies=[Depends(get_current_user)])
def get_assessments():
    """Per-tenant AI agent assessments, keyed by group. Read by the radar."""
    return state.get_assessments()


@router.patch("/tenants/{group}", dependencies=[Depends(require_admin)])
def update_tenant(group: str, body: TenantUpdate):
    with session_scope() as session:
        updated = tenant_service.update_tenant(session, group, body.model_dump(exclude_unset=True))
        if updated is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        return updated


# ── Contacts ────────────────────────────────────────────────────────────────
@router.post("/tenants/{group}/contacts", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
def add_contact(group: str, body: ContactIn):
    with session_scope() as session:
        contact = tenant_service.add_contact(session, group, **body.model_dump())
        if contact is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        return contact


@router.delete("/tenants/{group}/contacts/{contact_id}", dependencies=[Depends(require_admin)])
def delete_contact(group: str, contact_id: int):
    with session_scope() as session:
        if not tenant_service.delete_contact(session, group, contact_id):
            raise HTTPException(status_code=404, detail="contact not found")
        return {"deleted": contact_id}


# ── Notification recipients ──────────────────────────────────────────────────
@router.post("/tenants/{group}/recipients", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
def add_recipient(group: str, body: RecipientIn):
    with session_scope() as session:
        try:
            recipient = tenant_service.add_recipient(
                session, group, user_id=body.user_id, email=body.email
            )
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        if recipient is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        return recipient


@router.delete("/tenants/{group}/recipients/{recipient_id}", dependencies=[Depends(require_admin)])
def delete_recipient(group: str, recipient_id: int):
    with session_scope() as session:
        if not tenant_service.delete_recipient(session, group, recipient_id):
            raise HTTPException(status_code=404, detail="recipient not found")
        return {"deleted": recipient_id}
