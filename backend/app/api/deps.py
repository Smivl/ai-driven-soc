"""FastAPI dependencies for authentication and authorization."""

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import settings
from app.core.security import decode_access_token
from app.db import session_scope
from app.services import users as user_service

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

_CREDENTIALS_EXC = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Resolve the bearer token to the active user record (as a dict)."""
    claims = decode_access_token(token)
    if not claims or not claims.get("sub"):
        raise _CREDENTIALS_EXC
    with session_scope() as session:
        user = user_service.get_by_username(session, claims["sub"])
        if user is None or not user.is_active:
            raise _CREDENTIALS_EXC
        return user_service._serialize(user)


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Allow only admins through."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )
    return current_user
