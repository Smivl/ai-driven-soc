"""User account service: seeding, authentication, and admin CRUD."""

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password, verify_password
from app.models.db import session_scope
from app.models.user import User

logger = logging.getLogger(__name__)

VALID_ROLES = {"admin", "analyst"}


def _serialize(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


def get_by_username(session: Session, username: str) -> User | None:
    return session.scalar(select(User).where(User.username == username))


def authenticate(session: Session, username: str, password: str) -> User | None:
    """Return the user if the credentials are valid and the account is active."""
    user = get_by_username(session, username)
    if user is None or not user.is_active:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_user(
    session: Session,
    username: str,
    password: str,
    role: str = "analyst",
    email: str | None = None,
) -> dict:
    """Create a user. Raises ValueError on bad role or duplicate username."""
    if role not in VALID_ROLES:
        raise ValueError(f"invalid role: {role!r}")
    if get_by_username(session, username) is not None:
        raise ValueError("username already exists")
    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        role=role,
    )
    session.add(user)
    session.flush()
    return _serialize(user)


def list_users(session: Session) -> list[dict]:
    users = session.scalars(select(User).order_by(User.username)).all()
    return [_serialize(u) for u in users]


def set_active(session: Session, username: str, is_active: bool) -> dict | None:
    user = get_by_username(session, username)
    if user is None:
        return None
    user.is_active = is_active
    session.flush()
    return _serialize(user)


def seed_admin_if_empty() -> None:
    """Create the bootstrap admin from settings when no users exist yet."""
    with session_scope() as session:
        if session.scalar(select(User).limit(1)) is not None:
            return
        create_user(
            session,
            username=settings.ADMIN_USERNAME,
            password=settings.ADMIN_PASSWORD,
            role="admin",
        )
        logger.info("Seeded bootstrap admin user %r", settings.ADMIN_USERNAME)
