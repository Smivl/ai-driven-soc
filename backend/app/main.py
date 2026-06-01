import queue
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.v1.auth import router as auth_router
from app.api.v1.events import router as events_router
from backend.ingestion.pipeline_concurrent import explain_worker, ingest_worker, score_worker
from backend.ingestion.wazuh_client import WazuhClient

from backend.log_evaluation.correlator import Correlator
from backend.log_evaluation.ml_category import load_and_train_category
from backend.log_evaluation.rule_individual import load_blacklist, load_tor_exits

_stop = threading.Event()


@asynccontextmanager
async def lifespan(app: FastAPI):
    cache: dict = {}
    cache_lock = threading.Lock()
    pq12: queue.PriorityQueue = queue.PriorityQueue()
    pq23: queue.PriorityQueue = queue.PriorityQueue()

    blacklist = load_blacklist()
    torexitslist = load_tor_exits()
    category_vectorizer, category_model = load_and_train_category()

    correlator = Correlator(active_alerts={})

    client = WazuhClient()

    _stop.clear()
    threads = [
        threading.Thread(
            target=ingest_worker,
            args=(category_model, category_vectorizer, client, cache, cache_lock, pq12, _stop),
            daemon=True,
        ),
        threading.Thread(
            target=score_worker,
            args=( correlator, blacklist, torexitslist, cache, cache_lock, pq12, pq23, _stop),
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


@app.get("/health")
async def health_check():
    return {"status": "ok", "version": settings.VERSION}