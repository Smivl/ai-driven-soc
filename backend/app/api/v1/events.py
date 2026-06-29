# Endpoints for reading events: the live ones from memory and the saved history
# from the archive, plus resolving and clearing live events.

from fastapi import APIRouter, Depends, HTTPException

from app.services import state
from app.api.deps import get_current_user
from app.models.db import session_scope
from app.services import events_archive

router = APIRouter()


@router.get("/events", dependencies=[Depends(get_current_user)])
def get_events(limit: int = 100):
    """Live events from the in-memory pipeline store (recent, capped)."""
    return state.get_events(limit=limit)


@router.post("/events/{event_id}/resolve", dependencies=[Depends(get_current_user)])
def resolve_event(event_id: str):
    if not state.resolve_event(event_id):
        raise HTTPException(status_code=404, detail="event not found")
    # Mirror the resolution into the archive if the event was already persisted.
    archived = state.get_event(event_id)
    if archived is not None:
        events_archive.archive_event(archived)
    return {"event_id": event_id, "status": "resolved"}


@router.delete("/events", dependencies=[Depends(get_current_user)])
def clear_events():
    """Clear the live in-memory store. Archived events are NOT affected."""
    state.clear_events()
    return {"cleared": True}


# ── Archive (durable history in Postgres) ──────────────────────────────────────
@router.get("/events/archive", dependencies=[Depends(get_current_user)])
def list_archived_events(
    limit: int = 100,
    offset: int = 0,
    group: str | None = None,
    label: str | None = None,
    min_severity: int | None = None,
):
    with session_scope() as session:
        return events_archive.list_archived(
            session,
            limit=limit,
            offset=offset,
            group=group,
            label=label,
            min_severity=min_severity,
        )


@router.get("/events/archive/{event_id}", dependencies=[Depends(get_current_user)])
def get_archived_event(event_id: str):
    with session_scope() as session:
        event = events_archive.get_archived(session, event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="event not found in archive")
        return event
