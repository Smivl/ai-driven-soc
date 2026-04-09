import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app import state
from app.api.v1.events import router as events_router
from ingestion.main_loop import run_pipeline_once
from ingestion.wazuh_client import WazuhClient
from log_evaluation.severity_scoring import load_blacklist, train_model

_stop = threading.Event()


def _pipeline_worker() -> None:
    blacklist = load_blacklist()
    model = train_model(blacklist)
    client = WazuhClient()
    while not _stop.is_set():
        results = run_pipeline_once(client, model, blacklist, batch_size=10)
        state.add_events(results)
        _stop.wait(timeout=15)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _stop.clear()
    t = threading.Thread(target=_pipeline_worker, daemon=True)
    t.start()
    yield
    _stop.set()
    t.join(timeout=10)


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(events_router, prefix=settings.API_V1_STR)


@app.get("/health")
async def health_check():
    return {"status": "ok", "version": settings.VERSION}
