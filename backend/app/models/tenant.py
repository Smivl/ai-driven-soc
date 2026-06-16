"""Tenant registry models: a company (Wazuh group) and its agents."""

from datetime import datetime, timezone

from sqlalchemy import ForeignKey, String, func
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
    created_at: Mapped[datetime] = mapped_column(default=_now, server_default=func.now())

    agents: Mapped[list["Agent"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan", order_by="Agent.name"
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
