from collections import deque
import threading
from typing import Optional

events: dict[str, dict] = {}
alerts: dict[str, dict] = {}
playbook_executions: deque = deque(maxlen=500)
_lock = threading.Lock()


def upsert_event(event_dict: dict) -> None:
    with _lock:
        events[event_dict["event_id"]] = event_dict


def get_event(event_id: str) -> Optional[dict]:
    with _lock:
        return events.get(event_id)


def upsert_alert(alert_dict: dict) -> None:
    with _lock:
        alerts[alert_dict["alert_id"]] = alert_dict


def get_alerts(limit: int = 100) -> list[dict]:
    with _lock:
        all_alerts = list(alerts.values())
    all_alerts.sort(key=lambda a: a.get("last_seen") or "", reverse=True)
    return all_alerts[:limit]


def update_alert_explanation(alert_id: str, explanation: str) -> None:
    with _lock:
        if alert_id in alerts:
            alerts[alert_id]["explanation"] = explanation


def add_playbook_executions(execs: list[dict]) -> None:
    with _lock:
        playbook_executions.extend(execs)


def get_playbook_executions(limit: int = 100) -> list[dict]:
    with _lock:
        return list(playbook_executions)[-limit:]


def add_events(new_events: list[dict]) -> None:
    with _lock:
        for e in new_events:
            eid = e.get("event_id", "")
            if eid:
                events[eid] = e


def get_events(limit: int = 100) -> list[dict]:
    with _lock:
        return list(events.values())[-limit:]
