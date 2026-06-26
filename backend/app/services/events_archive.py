"""Archive service: persist fully-processed events and query the history."""

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db import session_scope
from app.models.event import ArchivedEvent

logger = logging.getLogger(__name__)


def _as_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def archive_event(event_dict: dict) -> None:
    """Persist (insert or update) a finished event keyed by event_id.

    Safe to call from a pipeline worker thread — manages its own session and
    swallows nothing silently except logging, so the pipeline keeps running.
    """
    event_id = event_dict.get("event_id")
    if not event_id:
        return
    try:
        with session_scope() as session:
            row = session.scalar(
                select(ArchivedEvent).where(ArchivedEvent.event_id == event_id)
            )
            fields = dict(
                group=event_dict.get("group"),
                agent_name=event_dict.get("agent_name"),
                source_ip=event_dict.get("source_ip"),
                destination_ip=event_dict.get("destination_ip"),
                user=event_dict.get("user"),
                event_type=event_dict.get("event_type"),
                rule_id=event_dict.get("rule_id"),
                rule_description=event_dict.get("rule_description"),
                wazuh_level=_as_int(event_dict.get("wazuh_level")),
                severity=_as_int(event_dict.get("severity")),
                label=event_dict.get("label"),
                status=event_dict.get("status"),
                event_timestamp=event_dict.get("timestamp"),
                data=event_dict,
            )
            if row is None:
                session.add(ArchivedEvent(event_id=event_id, **fields))
            else:
                for key, value in fields.items():
                    setattr(row, key, value)
    except Exception as e:  # archival must never crash the pipeline
        logger.warning("archive_event failed for %s: %s", event_id, e)


def list_archived(
    session: Session,
    limit: int = 100,
    offset: int = 0,
    group: str | None = None,
    label: str | None = None,
    min_severity: int | None = None,
) -> list[dict]:
    """Return archived events newest-first, with optional filters + pagination."""
    stmt = select(ArchivedEvent).order_by(ArchivedEvent.archived_at.desc())
    if group:
        stmt = stmt.where(ArchivedEvent.group == group)
    if label:
        stmt = stmt.where(ArchivedEvent.label == label)
    if min_severity is not None:
        stmt = stmt.where(ArchivedEvent.severity >= min_severity)
    stmt = stmt.limit(limit).offset(offset)
    return [row.data for row in session.scalars(stmt).all()]


def get_archived(session: Session, event_id: str) -> dict | None:
    row = session.scalar(
        select(ArchivedEvent).where(ArchivedEvent.event_id == event_id)
    )
    return row.data if row else None
