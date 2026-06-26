"""SQLAlchemy engine/session plumbing for the tenant registry."""

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Provide a transactional session scope; commits on success, rolls back on error."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create tables if they don't exist. Models must be imported first."""
    from app.models import event, tenant, user  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=engine)
    _run_light_migrations()


def _run_light_migrations() -> None:
    """create_all() never ALTERs existing tables, so add new tenant columns
    idempotently (Postgres). Safe to run on every startup."""
    stmts = [
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS notify_level INTEGER NOT NULL DEFAULT 12",
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS window_size INTEGER NOT NULL DEFAULT 20",
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS description TEXT",
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS industry VARCHAR(120)",
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS website VARCHAR(255)",
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS phone VARCHAR(64)",
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS address VARCHAR(255)",
    ]
    with engine.begin() as conn:
        for stmt in stmts:
            conn.execute(text(stmt))
