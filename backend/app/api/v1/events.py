from fastapi import APIRouter
from app import state

router = APIRouter()


@router.get("/events")
def get_events(limit: int = 100):
    return state.get_events(limit=limit)
