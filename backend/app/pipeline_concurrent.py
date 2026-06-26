import queue
import threading
import uuid
from datetime import datetime, timezone

from app.log_evaluation.explanation import fallback_recommendation, generate_analysis
from app.log_evaluation.normalizer import normalize_wazuh_alert
from app.tenants.tenant_agent import assess_window
from app.ingestion.wazuh_client import WazuhClient
from app.log_evaluation.socevent import PipelineStatus, SOCevent
from app.log_evaluation.severity_scoring import  score_rules
from app.services import state
from app.services import events_archive
from app.services import notifications
from app.services import tenants as tenant_service
from app import perf_trace


def ingest_worker(
    client: WazuhClient,
    cache: dict,
    cache_lock: threading.Lock,
    pq12: queue.PriorityQueue,
    stop: threading.Event,
    poll_seconds: int = 15,
    batch_size: int = 10,
) -> None:
    # Watermark: only ingest alerts at/after this time. Initialised to startup,
    # so a restart begins fresh and won't re-pull alerts already in OpenSearch.
    since = datetime.now(timezone.utc).isoformat()
    while not stop.is_set():
        try:
            # Query at the lowest threshold any tenant uses; filter per-tenant below.
            alerts = client.get_significant_alerts(
                min_level=tenant_service.floor_min_level(),
                limit=batch_size, since=since, ascending=True,
            )
            for alert in alerts:
                # Advance the watermark for every fetched alert (oldest-first),
                # so we always move forward even past already-seen ones.
                ts = alert.get("@timestamp") or alert.get("timestamp")
                if ts and ts > since:
                    since = ts
                wazuh_id = alert.pop("_wazuh_id", None)
                event: SOCevent = normalize_wazuh_alert(alert, group_resolver=client.get_agent_group)
                event.event_id = wazuh_id or str(uuid.uuid4())
                # Per-tenant threshold: drop alerts below this tenant's min_level.
                if (event.wazuh_level or 0) < tenant_service.min_level_for(event.group):
                    continue
                if state.get_event(event.event_id) is not None:
                    continue  # already in pipeline, skip re-ingestion
                with cache_lock:
                    cache[event.event_id] = event
                state.upsert_event(event.return_dict())
                perf_trace.record("received", event.event_id, event.source_ip)  # T4
                print(f"Event ID {event.event_id}\nLevel: {event.wazuh_level}\nMitre ID: {event.mitre_id}\nTactic: {event.mitre_tactic}\nTechnique: {event.mitre_technique}\n")
                pq12.put((-(event.wazuh_level or 0), event.event_id))
        except Exception as e:
            print(f"[ingest_worker] error: {e}")
        stop.wait(timeout=poll_seconds)


def score_worker(
    tor_exits: set,
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
            score_rules(event, blacklist, tor_exits)
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
            analysis_input = {
                "event_type": event.event_type,
                "rule_id": event.rule_id,
                "rule_description": event.rule_description,
                "message": event.raw_log,
                "user": event.user,
                "source_ip": event.source_ip,
                "group": event.group,
                "agent_name": event.agent_name,
                "label": event.label,
                "mitre_id": event.mitre_id,
                "mitre_tactic": event.mitre_tactic,
                "mitre_technique": event.mitre_technique,
                "wazuh_level": event.wazuh_level,
                "trigger_logs": event.trigger_logs,
            }
            try:
                explanation, action = generate_analysis(analysis_input, event.severity or 0)
            except Exception as e:
                print(f"[explain_worker] analysis error: {e}")
                explanation, action = None, fallback_recommendation(analysis_input)
            event.explanation = explanation
            event.recommended_action = action
            event.status = PipelineStatus.EXPLAINED
            event_dict = event.return_dict()
            state.upsert_event(event_dict)
            perf_trace.record("explained", event.event_id, event.source_ip)  # T5
            # Event is fully processed — persist it to Postgres for the archive.
            events_archive.archive_event(event_dict)
            # Alert the tenant's recipient list if it meets their threshold.
            notifications.maybe_notify(event_dict)
            with cache_lock:
                cache.pop(event_id, None)
        except Exception as e:
            print(f"[explain_worker] error: {e}")


def assess_worker(stop: threading.Event, interval: int = 20) -> None:
    """Per-tenant AI agent: periodically assess each tenant's sliding window of
    events and publish an overall threat status that the radar reads.

    Only re-runs the model for a tenant whose window actually changed, so idle
    tenants don't burn Ollama calls.
    """
    last_sig: dict[str, tuple] = {}
    while not stop.is_set():
        try:
            for group, window in tenant_service.group_windows().items():
                events = state.get_events_by_group(group, limit=window)
                max_level = max((e.get("wazuh_level") or 0 for e in events), default=0)
                sig = (window, len(events), events[-1].get("event_id") if events else None, max_level)
                if sig == last_sig.get(group):
                    continue
                result = assess_window(group, events)
                result.update({
                    "window": window,
                    "events": len(events),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                })
                state.set_assessment(group, result)
                last_sig[group] = sig
        except Exception as e:
            print(f"[assess_worker] error: {e}")
        stop.wait(interval)
