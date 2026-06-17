"""Per-tenant AI assessment agent.

Where the radar's per-event severity looks at alerts one at a time, this agent
looks at a *sliding window* of a tenant's recent events together and judges the
tenant's overall state — catching coordinated / low-and-slow activity that any
single event would understate.

Uses the same Ollama model as the per-event explainer, with a different prompt
and JSON output. Falls back to a deterministic heuristic when Ollama is down so
the radar always has a status.
"""

import json
import logging

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2"
MAX_EVENTS = 40  # hard cap on evidence sent to the model

logger = logging.getLogger(__name__)

# Canonical statuses the radar understands.
STATUSES = ("secured", "at-risk", "under-attack")

# Map model / synonym output onto the canonical statuses.
_STATUS_ALIASES = {
    "secured": "secured", "secure": "secured", "safe": "secured", "benign": "secured",
    "normal": "secured", "ok": "secured", "low": "secured",
    "at-risk": "at-risk", "at_risk": "at-risk", "atrisk": "at-risk", "risk": "at-risk",
    "suspicious": "at-risk", "elevated": "at-risk", "medium": "at-risk", "warning": "at-risk",
    "under-attack": "under-attack", "under_attack": "under-attack", "underattack": "under-attack",
    "attack": "under-attack", "compromised": "under-attack", "critical": "under-attack",
    "breach": "under-attack", "high": "under-attack",
}


def _normalize_status(value) -> str | None:
    if not isinstance(value, str):
        return None
    key = value.strip().lower().replace(" ", "-")
    return _STATUS_ALIASES.get(key) or _STATUS_ALIASES.get(key.replace("-", "_"))


def _event_line(e: dict) -> str:
    mitre = ", ".join(e.get("mitre_id") or []) or "-"
    return (
        f"- [L{e.get('wazuh_level')}] {e.get('rule_description') or e.get('event_type') or 'event'}"
        f" | src={e.get('source_ip') or '-'} user={e.get('user') or '-'}"
        f" host={e.get('agent_name') or '-'} mitre={mitre} at={e.get('last_seen') or e.get('timestamp') or '-'}"
    )


def _build_prompt(group: str, events: list[dict]) -> str:
    window = events[-MAX_EVENTS:]
    levels = [e.get("wazuh_level") or 0 for e in window]
    src_ips = {e.get("source_ip") for e in window if e.get("source_ip")}
    users = {e.get("user") for e in window if e.get("user")}
    hosts = {e.get("agent_name") for e in window if e.get("agent_name")}
    stats = (
        f"events={len(window)} max_level={max(levels) if levels else 0} "
        f"distinct_source_ips={len(src_ips)} distinct_users={len(users)} distinct_hosts={len(hosts)}"
    )
    lines = "\n".join(_event_line(e) for e in window) or "(no events)"

    return f"""You are a senior SOC analyst assessing the OVERALL security state of one tenant
("{group}") from a sliding window of its most recent security events.

Judge the tenant as a whole, not any single alert. Weigh coordination signals:
repeated source IPs, escalation in severity over time, multiple hosts/users hit,
recon followed by exploitation, and bursts of activity. A few isolated low-level
alerts is "secured"; correlated or escalating activity is "at-risk" or
"under-attack" even if individual levels look modest.

AGGREGATE: {stats}

EVENTS (oldest to newest):
{lines}

Respond with ONLY a JSON object, no prose:
{{"status": "secured" | "at-risk" | "under-attack",
  "risk_score": <integer 0-100>,
  "summary": "<one or two sentences on the tenant's state and why>"}}"""


def _heuristic(events: list[dict]) -> dict:
    """Deterministic fallback when the model is unavailable."""
    levels = [e.get("wazuh_level") or 0 for e in events]
    max_level = max(levels) if levels else 0
    if max_level >= 12:
        status, score = "under-attack", min(100, 60 + max_level * 2)
    elif max_level >= 7:
        status, score = "at-risk", 30 + max_level * 2
    else:
        status, score = "secured", min(25, max_level * 3)
    return {
        "status": status,
        "risk_score": int(score),
        "summary": "Heuristic assessment (AI agent unavailable): based on peak event severity.",
        "ai": False,
    }


def assess_window(group: str, events: list[dict]) -> dict:
    """Assess a tenant's window of events. Always returns a usable dict."""
    if not events:
        return {"status": "secured", "risk_score": 0, "summary": "No active events.", "ai": False}
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": _build_prompt(group, events),
                "stream": False,
                "format": "json",
            },
            timeout=60,
        )
        response.raise_for_status()
        data = json.loads(response.json()["response"])
        status = _normalize_status(data.get("status"))
        if status is None:
            raise ValueError(f"unrecognised status: {data.get('status')!r}")
        score = data.get("risk_score")
        score = int(score) if isinstance(score, (int, float)) else 0
        return {
            "status": status,
            "risk_score": max(0, min(100, score)),
            "summary": (data.get("summary") or "").strip() or "AI assessment.",
            "ai": True,
        }
    except Exception as e:
        logger.warning("assess_window fell back to heuristic for %s: %s", group, e)
        return _heuristic(events)
