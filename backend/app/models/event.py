"""Archived SOC events — the durable record of fully-processed events.

The pipeline holds live events in an in-memory store (app.state, capped/evicted).
Once an event reaches EXPLAINED it is the final, enriched record, so we persist a
copy here for history/archival. Key fields are columns (for filtering); the full
event dict is kept verbatim in `data` so nothing is lost.
"""

from datetime import datetime, timezone

from sqlalchemy import Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ArchivedEvent(Base):
    __tablename__ = "archived_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)

    # ── Tenant attribution ────────────────────────────────────────────────────
    group: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(120), nullable=True)

    # ── Queryable summary fields ──────────────────────────────────────────────
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(120), nullable=True)
    event_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rule_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    wazuh_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    label: Mapped[str | None] = mapped_column(String(40), index=True, nullable=True)
    status: Mapped[str | None] = mapped_column(String(20), index=True, nullable=True)

    # Log-reported time of the event (string, multiple formats upstream).
    event_timestamp: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # ── Full fidelity copy + bookkeeping ──────────────────────────────────────
    data: Mapped[dict] = mapped_column(JSONB)
    archived_at: Mapped[datetime] = mapped_column(
        default=_now, server_default=func.now(), index=True
    )
