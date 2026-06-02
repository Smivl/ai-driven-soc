import queue
import threading
import datetime
import uuid

from backend.ingestion.explanation import generate_explanation
from backend.ingestion.normalizerfixed import normalize_wazuh_alert
from backend.ingestion.wazuh_client import WazuhClient
from backend.log_evaluation.log_dataclass import PipelineStatus, SOCevent
from backend.log_evaluation.correlator import Correlator
from backend.log_evaluation.classes.alert import score_rules, Alert
from app import state
# Instant warning is raised when the individual scoring is over 70
INDIVIDUAL_ALERT_THRESHOLD = 70

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
            logs = client.get_recent_alerts(limit=batch_size)
            for log in logs:
                wazuh_id = log.pop("_wazuh_id", None)
                event: SOCevent = normalize_wazuh_alert(log)
                event.event_id = wazuh_id or str(uuid.uuid4())
                if state.get_event(event.event_id) is not None:
                    continue  # already in pipeline, skip re-ingestion
                with cache_lock:
                    cache[event.event_id] = event
                state.upsert_event(event.return_dict())

                client.store_soc_event(event, doc_id=event.event_id) # Store the normalized event back to OpenSearch with the same ID

                print(f"Event ID {event.event_id}\nLevel: {event.wazuh_level}\nMitre ID: {event.mitre_id}\nTactic: {event.mitre_tactic}\nTechnique: {event.mitre_technique}\n")
                pq12.put((-(event.wazuh_level or 0), event.event_id))
        except Exception as e:
            print(f"[ingest_worker] error: {e}")
        stop.wait(timeout=poll_seconds)


def score_worker(
    client: WazuhClient,
    correlator: Correlator,
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

            # Run the static rules on the individual log
            event.score_rules(blacklist, torexitslist)

            # Correlate the event into an Alert 
            assigned_alert: Alert = correlator.correlate_event(event)

            # Calculate the live aggregate 0-100 severity UI score for the Alert
            ui_severity_score = assigned_alert.score(blacklist, torexitslist)

            client.update_soc_event( # Update the individual SOCevent with its severity score and assigned Alert ID 
                doc_id=event.event_id,
                new_status=PipelineStatus.EVALUATED,
                severity=event.severity,
                alert_id=assigned_alert.alert_id  
            )

            event.status = PipelineStatus.EVALUATED
            event.alert_id = assigned_alert.alert_id
            state.upsert_event(event.return_dict())
            
            # Periodically handle alert timeouts and status updates in correlator
            now = datetime.datetime.now()
            timeout_delta = datetime.timedelta(minutes=30)
            expired_alerts = correlator.update_alerts(current_time=now, alert_timeout=timeout_delta)

            for alert in expired_alerts:
                # Update status to cold/archived
                alert.status = "archived" 
                client.store_soc_alert(alert) 
                print(f"[Archive] Alert {alert.alert_id} expired from memory and committed to OpenSearch.")

            #  Pass the Alert ID forward to the LLM Explainer instead of single logs
            pq23.put((-ui_severity_score, assigned_alert.alert_id))
        except Exception as e:
            print(f"[score_worker] error: {e}")


def explain_worker(
    client: WazuhClient,
    correlator: Correlator,  # Passed down to resolve Alert instances directly from RAM memory maps
    cache: dict,
    cache_lock: threading.Lock,
    pq23: queue.PriorityQueue,
    stop: threading.Event,
) -> None:
    while not stop.is_set():
        try:
            _, alert_id = pq23.get(timeout=1)
        except queue.Empty:
            continue
        try:
            # Retrieve the composite Alert container from correlator engine index
            alert: Alert = correlator.active_alerts.get(alert_id)
            if alert is None:
                continue

            # Run the single-behavior prompt template built for dedicated vectors
            explanation = generate_explanation(alert)

            #NOTE: I want the explaination to be stored in postgreSQL, but it should eb easy to find alert ID from an event ID from opensearch
            
            # Commit the LLM triage text back to persistence for UI consumption
            state.update_alert_explanation(alert_id, explanation)
            print(f"[Explain] Generated behavioral triage summary for Alert {alert_id}")
 
            # Evict historical constituent events out of cache now that lifecycle analysis is finalized
            with cache_lock:
                for event in alert.events:
                    cache.pop(event.event_id, None)
                    
        except Exception as e:
            print(f"[explain_worker] error: {e}")