from fastapi import APIRouter
from app import state

router = APIRouter()


@router.get("/alerts")
def get_alerts(limit: int = 100):
    return state.get_alerts(limit=limit)
