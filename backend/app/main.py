import queue
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.v1.auth import router as auth_router
from app.api.v1.events import router as events_router
from app.api.v1.tenants import router as tenants_router
from app.api.v1.users import router as users_router
from app.models.db import init_db
from app.services import tenants as tenant_service
from app.services import users as user_service
from app.pipeline_concurrent import assess_worker, explain_worker, ingest_worker, score_worker
from app.ingestion.wazuh_client import WazuhClient
from app.log_evaluation.severity_scoring import load_blacklist, load_tor_exits

_stop = threading.Event()


@asynccontextmanager
async def lifespan(app: FastAPI):
    cache: dict = {}
    cache_lock = threading.Lock()
    pq12: queue.PriorityQueue = queue.PriorityQueue()
    pq23: queue.PriorityQueue = queue.PriorityQueue()

    blacklist = load_blacklist()
    tor_exits = load_tor_exits()
    client = WazuhClient()

    # Tenant registry: create tables, seed from yaml (first run), register agents
    # in Wazuh, and warm the per-tenant threshold cache. Resilient to DB/Wazuh hiccups.
    try:
        init_db()
        user_service.seed_admin_if_empty()
        tenant_service.bootstrap(client)
    except Exception as e:
        print(f"[startup] registry bootstrap failed: {e}")

    _stop.clear()
    threads = [
        threading.Thread(
            target=ingest_worker,
            args=(client, cache, cache_lock, pq12, _stop,
                  settings.INGEST_POLL_SECONDS, settings.INGEST_BATCH_SIZE),
            daemon=True,
        ),
        threading.Thread(
            target=score_worker,
            args=(tor_exits, blacklist, cache, cache_lock, pq12, pq23, _stop),
            daemon=True,
        ),
        threading.Thread(
            target=explain_worker,
            args=(cache, cache_lock, pq23, _stop),
            daemon=True,
        ),
        threading.Thread(
            target=assess_worker,
            args=(_stop,),
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
app.include_router(tenants_router, prefix=settings.API_V1_STR)
app.include_router(users_router, prefix=settings.API_V1_STR)


@app.get("/health")
async def health_check():
    return {"status": "ok", "version": settings.VERSION}
