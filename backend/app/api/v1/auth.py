from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.core.security import create_access_token
from app.db import session_scope
from app.services import users as user_service

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


@router.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest):
    with session_scope() as session:
        user = user_service.authenticate(session, body.username, body.password)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )
        token = create_access_token(subject=user.username, role=user.role)
        return TokenResponse(access_token=token, username=user.username, role=user.role)


@router.get("/auth/me")
def me(current_user: dict = Depends(get_current_user)):
    return current_user
