import threading
import queue
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app import state
from app.api.v1.events import router as events_router

from ingestion.wazuh_client import WazuhClient
from log_evaluation.severity_scoring import load_blacklist, train_model
from log_evaluation.soc_event import SOCevent, Scoring, PipelineStatus
from ingestion.normalizer import normalize_event
from ingestion.explanation import generate_explanation

_stop = threading.Event()

"""
    States are divided into seperate threads. 
    
    - Thread 1 : is responsible for receiving the logs and normalization.
    - Thread 2 : is responsible for scoring the events
    - Thread 3 : is responsible for explaining the events
    (- Thread 4 : will be responsible for responding to the events)

    Implementing two seperate priority queues to decide which event the threads should take.
    Events are stored in the Wazuh Indexer and the event_ID's are stored in the queues.
"""


# ── Priority levels ───────────────────────────────────────────────────────

PRIORITY_CRITICAL   = 0   # processed first (lowest number = highest priority)
PRIORITY_SUSPICIOUS = 1
PRIORITY_BENIGN     = 2

def _get_priority_wazuh(event: SOCevent) -> int:
    mapping = {
        Scoring.CRITICAL:   PRIORITY_CRITICAL,
        Scoring.MALICIOUS:  PRIORITY_CRITICAL,
        Scoring.SUSPICIOUS: PRIORITY_SUSPICIOUS,
        Scoring.BENIGN:     PRIORITY_BENIGN,
    }
    return mapping.get(event.wazuh_level, PRIORITY_BENIGN)

def _get_priority_ml(event: SOCevent) -> int:
    # Invert severity since PriorityQueue gives lowest number first
    return 100 - (event.severity or 0)

# ── Shared state ──────────────────────────────────────────────────────────

_stop            = threading.Event()
_ingest_queue    = queue.PriorityQueue()  # (priority, doc_id, event) — ingestion -> scorer
_explain_queue   = queue.PriorityQueue()  # (priority, doc_id, event) — scorer -> explainer

# ── Thread 1: Ingestion + Normalization ───────────────────────────────────
# Fast operations, polling Wazuh every 15s

def _ingestion_worker(client: WazuhClient) -> None:
    while not _stop.is_set():
        try:
            for alert in client.get_recent_alerts(limit=10):
                event    = normalize_event(alert)   # fast normalization of the event
                doc_id   = client.store_soc_event(event)  # store in indexer
                priority = _get_priority_wazuh(event)           # get the priority of the Wazuh scoring for the queue
                _ingest_queue.put((priority, doc_id, event))
        except Exception as e:
            print("Ingestion error: %s", e)
        _stop.wait(timeout=15)

# ── Thread 2: Scoring ─────────────────────────────────────────────────────
# Fast ML inference, drains ingest_queue and feeds explain_queue

def _scoring_worker(client: WazuhClient, model, blacklist: set) -> None:
    while not _stop.is_set():
        try:
            priority, doc_id, event = _ingest_queue.get(timeout=1)
            scored = _get_priority_ml(model, blacklist, event)
            client.update_soc_event(doc_id, PipelineStatus.SCORED,
                severity = scored.severity,
                label    = scored.label.value if scored.label else None,
            )
            _explain_queue.put((priority, doc_id, scored))  # pass scored event forward
            _ingest_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print("Scoring error: %s", e)

# ── Thread 3: Explanation ─────────────────────────────────────────────────
# Slow LLM call — isolated so it never blocks ingestion or scoring

def _explanation_worker(client: WazuhClient) -> None:
    while not _stop.is_set():
        try:
            priority, doc_id, event = _explain_queue.get(timeout=1)
            explanation = generate_explanation(event)
            client.update_soc_event(doc_id, PipelineStatus.EXPLAINED,
                explanation = explanation
            )
            state.add_events([event])         # only add to state when fully processed
            _explain_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print("Explanation error: %s", e)

# ── Lifespan ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    client    = WazuhClient()
    blacklist = load_blacklist()
    model     = train_model(blacklist)

    _stop.clear()

    threads = [
        threading.Thread(target=_ingestion_worker,   args=(client,),                  daemon=True),
        threading.Thread(target=_scoring_worker,     args=(client, model, blacklist),  daemon=True),
        threading.Thread(target=_explanation_worker, args=(client,),                   daemon=True),
    ]
    for t in threads:
        t.start()

    yield

    _stop.set()
    for t in threads:
        t.join(timeout=10)

# ── Lifespan ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    client    = WazuhClient()
    blacklist = load_blacklist()
    model     = train_model(blacklist)

    _stop.clear()

    threads = [
        threading.Thread(target=_ingestion_worker,   args=(client,),                  daemon=True),
        threading.Thread(target=_scoring_worker,     args=(client, model, blacklist),  daemon=True),
        threading.Thread(target=_explanation_worker, args=(client,),                   daemon=True),
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

app.include_router(events_router, prefix=settings.API_V1_STR)


@app.get("/health")
async def health_check():
    return {"status": "ok", "version": settings.VERSION}
