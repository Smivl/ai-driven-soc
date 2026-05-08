import queue
import threading
import uuid

from ingestion.explanation import generate_explanation
from ingestion.normalizerfixed import normalize_wazuh_alert
from ingestion.playbooks import run_playbooks
from ingestion.wazuh_client import WazuhClient
from log_evaluation.log_dataclass import PipelineStatus, SOCevent
from log_evaluation.severity_scoring import score_event
from app import state


def ingest_worker(
    client: WazuhClient,
    cache: dict,
    cache_lock: threading.Lock,
    pq12: queue.PriorityQueue,
    stop: threading.Event,
    poll_seconds: int = 15,
    batch_size: int = 10,
) -> None:
    while not stop.is_set():
        try:
            alerts = client.get_recent_alerts(limit=batch_size)
            for alert in alerts:
                wazuh_id = alert.pop("_wazuh_id", None)
                event: SOCevent = normalize_wazuh_alert(alert)
                event.event_id = wazuh_id or str(uuid.uuid4())
                if state.get_event(event.event_id) is not None:
                    continue  # already in pipeline, skip re-ingestion
                with cache_lock:
                    cache[event.event_id] = event
                state.upsert_event(event.return_dict())
                print("Event ID %s\nFrequency: %s\nTimeframe: %s", event.event_id,event.frequency, event.timeframe)
                pq12.put((-(event.wazuh_level or 0), event.event_id))
        except Exception as e:
            print(f"[ingest_worker] error: {e}")
        stop.wait(timeout=poll_seconds)


def score_worker(
    model,
    blacklist: set,
    cache: dict,
    cache_lock: threading.Lock,
    pq12: queue.PriorityQueue,
    pq23: queue.PriorityQueue,
    stop: threading.Event,
) -> None:
    while not stop.is_set():
        try:
            _, event_id = pq12.get(timeout=1)
        except queue.Empty:
            continue
        try:
            with cache_lock:
                event = cache.get(event_id)
            if event is None:
                continue
            score_event(model, blacklist, event)
            state.upsert_event(event.return_dict())
            avg_priority = -((event.wazuh_level or 0) + (event.severity or 0)) / 2
            pq23.put((avg_priority, event_id))
        except Exception as e:
            print(f"[score_worker] error: {e}")


def explain_worker(
    cache: dict,
    cache_lock: threading.Lock,
    pq23: queue.PriorityQueue,
    stop: threading.Event,
) -> None:
    while not stop.is_set():
        try:
            _, event_id = pq23.get(timeout=1)
        except queue.Empty:
            continue
        try:
            with cache_lock:
                event = cache.get(event_id)
            if event is None:
                continue
            explanation_input = {
                "event_type": event.event_type,
                "message": event.raw_log,
                "user": event.user,
                "source_ip": event.source_ip,
            }
            event.explanation = generate_explanation(explanation_input, event.severity or 0)
            event.status = PipelineStatus.EXPLAINED
            state.upsert_event(event.return_dict())
            for execution in run_playbooks(event):
                state.add_execution(execution)
            with cache_lock:
                cache.pop(event_id, None)
        except Exception as e:
            print(f"[explain_worker] error: {e}")
