import queue
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.v1.auth import router as auth_router
from app.api.v1.events import router as events_router
from app.api.v1.playbooks import router as playbooks_router
from ingestion.pipeline_concurrent import explain_worker, ingest_worker, score_worker
from ingestion.wazuh_client import WazuhClient
from log_evaluation.severity_scoring import load_blacklist, train_model

_stop = threading.Event()


@asynccontextmanager
async def lifespan(app: FastAPI):
    cache: dict = {}
    cache_lock = threading.Lock()
    pq12: queue.PriorityQueue = queue.PriorityQueue()
    pq23: queue.PriorityQueue = queue.PriorityQueue()

    blacklist = load_blacklist()
    model = train_model(blacklist)
    client = WazuhClient()

    _stop.clear()
    threads = [
        threading.Thread(
            target=ingest_worker,
            args=(client, cache, cache_lock, pq12, _stop),
            daemon=True,
        ),
        threading.Thread(
            target=score_worker,
            args=(model, blacklist, cache, cache_lock, pq12, pq23, _stop),
            daemon=True,
        ),
        threading.Thread(
            target=explain_worker,
            args=(cache, cache_lock, pq23, _stop),
            daemon=True,
        ),
    ]
    for t in threads:
        t.start()

    yield

    _stop.set()
    for t in threads:
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

app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(events_router, prefix=settings.API_V1_STR)
app.include_router(playbooks_router, prefix=settings.API_V1_STR)


@app.get("/health")
async def health_check():
    return {"status": "ok", "version": settings.VERSION}
