from fastapi import APIRouter
from app import state

router = APIRouter()


@router.get("/playbook-executions")
def get_executions(limit: int = 100):
    return state.get_executions(limit=limit)


@router.delete("/playbook-executions")
def clear_executions():
    state.clear_executions()
    return {"cleared": True}
