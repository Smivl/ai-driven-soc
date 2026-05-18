from datetime import datetime, timezone
from uuid import uuid4

from log_evaluation.log_dataclass import Scoring, SOCevent


def _is_external_ip(ip: str | None) -> bool:
    if not ip:
        return False
    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168.", "127.", "::1")
    return not any(ip.startswith(p) for p in private_prefixes)


_PLAYBOOKS = [
    {
        "id": "pb1",
        "name": "Auto-Isolate on Ransomware",
        "condition": lambda e: (e.severity or 0) >= 50,
        "action": lambda e: f"Isolation logged: host contacted by {e.source_ip or 'unknown'}",
    },
    {
        "id": "pb2",
        "name": "Brute Force Lockout",
        "condition": lambda e: (e.event_type or "").lower() in ("pam", "sshd", "authentication") and (e.severity or 0) >= 20,
        "action": lambda e: f"Locked user '{e.user or 'unknown'}' — brute force from {e.source_ip or 'unknown'}",
    },
    {
        "id": "pb3",
        "name": "Critical Alert Ticket",
        "condition": lambda e: (e.severity or 0) >= 25,
        "action": lambda e: f"Ticket created: {e.event_type or 'unknown'} severity {e.severity} from {e.source_ip or 'unknown'}",
    },
    {
        "id": "pb4",
        "name": "Geo-Anomaly Alert",
        "condition": lambda e: _is_external_ip(e.source_ip) and (e.severity or 0) >= 20,
        "action": lambda e: f"Geo-anomaly alert: {e.source_ip} is external, severity {e.severity}",
    },
    {
        "id": "pb5",
        "name": "Port Scan Blocklist",
        "condition": lambda e: (e.event_type or "").lower() in ("apache", "web", "http") and (e.severity or 0) >= 20,
        "action": lambda e: f"Logged block: {e.source_ip or 'unknown'} flagged for suspicious web activity",
    },
]


def run_playbooks(event: SOCevent) -> list[dict]:
    executions = []
    for pb in _PLAYBOOKS:
        try:
            if pb["condition"](event):
                executions.append({
                    "id": str(uuid4()),
                    "playbookId": pb["id"],
                    "clientId": "all",
                    "triggeredBy": event.event_type or "unknown",
                    "sourceIp": event.source_ip or "unknown",
                    "startedAt": datetime.now(timezone.utc).isoformat(),
                    "status": "completed",
                    "action": pb["action"](event),
                })
        except Exception:
            pass
    return executions
