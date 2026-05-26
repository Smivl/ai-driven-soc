import queue
import threading
import uuid

from ingestion.explanation import generate_explanation
from ingestion.normalizerfixed import normalize_wazuh_alert
from ingestion.wazuh_client import WazuhClient
from log_evaluation.log_dataclass import PipelineStatus, SOCevent
from log_evaluation.rule_sequence import ThreatEngine
from app import state
# Instant warning is raised when the individual scoring is over 70
INDIVIDUAL_ALERT_THRESHOLD = 70

def ingest_worker(
    category_model,
    category_vectorizer,
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
                event: SOCevent = normalize_wazuh_alert(category_model,category_vectorizer,alert,category_model)
                event.event_id = wazuh_id or str(uuid.uuid4())
                if state.get_event(event.event_id) is not None:
                    continue  # already in pipeline, skip re-ingestion
                with cache_lock:
                    cache[event.event_id] = event
                state.upsert_event(event.return_dict())
                print(f"Event ID {event.event_id}\nLevel: {event.wazuh_level}\nMitre ID: {event.mitre_id}\nTactic: {event.mitre_tactic}\nTechnique: {event.mitre_technique}\n")
                pq12.put((-(event.wazuh_level or 0), event.event_id))
        except Exception as e:
            print(f"[ingest_worker] error: {e}")
        stop.wait(timeout=poll_seconds)


def score_worker(
    threat_engine: ThreatEngine,
    blacklist: set,
    torexitslist: set,
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

            """
               Using a ML version of the sequence attack detection, 
               in order to find alerts rule-based detection cannot raise
            """

            # ----- Score event  --------------------------------------------
            SOCevent.score_event(event, blacklist, torexitslist)

            # Maybe if critical, we send over to explain worker, but also include in the sequence detection

            # ----- Put the event in sequence detection, also when warning is raised -----------------
           threat_engine.add_event()

            # ----- Compare the ML Mitre to Wazuh Mitre -----------------


            # ----- Generate a alert object, either because severity score is really high or it is a sequence attack 


            # (----- Feedback loop for ML? -----------------)


            state.upsert_event(event.return_dict()) # Instead of seperate logs, continue with the alerts for LLM
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
            with cache_lock:
                cache.pop(event_id, None)
        except Exception as e:
            print(f"[explain_worker] error: {e}")
