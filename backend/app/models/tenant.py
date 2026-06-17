"""Tenant registry models: a company (Wazuh group), its agents, contacts, and
its notification recipient list."""

from datetime import datetime, timezone

from sqlalchemy import ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.config import settings
from app.db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(primary_key=True)
    company: Mapped[str] = mapped_column(String(120))
    group: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    # Minimum Wazuh rule level for this tenant's events to be detected/ingested.
    min_level: Mapped[int] = mapped_column(default=settings.MIN_ALERT_LEVEL)
    # Events at/above this level notify the tenant's recipient list.
    notify_level: Mapped[int] = mapped_column(default=12, server_default="12")

    # ── Tenant info ───────────────────────────────────────────────────────────
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    industry: Mapped[str | None] = mapped_column(String(120), nullable=True)
    website: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    address: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(default=_now, server_default=func.now())

    agents: Mapped[list["Agent"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan", order_by="Agent.name"
    )
    contacts: Mapped[list["TenantContact"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan", order_by="TenantContact.name"
    )
    recipients: Mapped[list["NotificationRecipient"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    # 3-digit Wazuh agent id, filled in once the agent is registered with Wazuh.
    wazuh_agent_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_now, server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="agents")


class TenantContact(Base):
    """A point of contact at the tenant company (not necessarily a SOC user)."""

    __tablename__ = "tenant_contacts"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(120))
    role: Mapped[str | None] = mapped_column(String(120), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_now, server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="contacts")


class NotificationRecipient(Base):
    """A destination on a tenant's notification list — either a SOC user (linked
    to the users table, email resolved from the account) or an external email."""

    __tablename__ = "notification_recipients"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_now, server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="recipients")
    user: Mapped["User"] = relationship()  # type: ignore[name-defined]  # noqa: F821
