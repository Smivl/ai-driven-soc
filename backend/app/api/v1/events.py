from fastapi import APIRouter, HTTPException
from app import state

router = APIRouter()


@router.get("/events")
def get_events(limit: int = 100):
    return state.get_events(limit=limit)


@router.post("/events/{event_id}/resolve")
def resolve_event(event_id: str):
    if not state.resolve_event(event_id):
        raise HTTPException(status_code=404, detail="event not found")
    return {"event_id": event_id, "status": "resolved"}


@router.delete("/events")
def clear_events():
    state.clear_events()
    return {"cleared": True}
