"""Admin-only user management endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import get_current_user, require_admin
from app.db import session_scope
from app.services import users as user_service

router = APIRouter()


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=6, max_length=128)
    role: str = Field(default="analyst")
    email: str | None = None


class ActiveUpdate(BaseModel):
    is_active: bool


@router.get("/users", dependencies=[Depends(require_admin)])
def list_users():
    with session_scope() as session:
        return user_service.list_users(session)


@router.post("/users", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
def create_user(body: UserCreate):
    with session_scope() as session:
        try:
            return user_service.create_user(
                session,
                username=body.username,
                password=body.password,
                role=body.role,
                email=body.email,
            )
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch("/users/{username}/active", dependencies=[Depends(require_admin)])
def set_user_active(username: str, body: ActiveUpdate, admin: dict = Depends(require_admin)):
    if username == admin["username"] and not body.is_active:
        raise HTTPException(status_code=400, detail="You cannot deactivate yourself")
    with session_scope() as session:
        updated = user_service.set_active(session, username, body.is_active)
        if updated is None:
            raise HTTPException(status_code=404, detail="user not found")
        return updated
