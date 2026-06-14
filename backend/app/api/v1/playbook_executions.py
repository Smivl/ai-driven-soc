from fastapi import APIRouter
from app import state

router = APIRouter()


@router.get("/playbook-executions")
def get_playbook_executions(limit: int = 100):
    return state.get_playbook_executions(limit=limit)
