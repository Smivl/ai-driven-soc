# This file asks a local LLM (Ollama) to explain an event in plain words and to
# suggest a response. If the model is not running or replies badly, we fall back
# to a fixed suggestion so the event always gets some recommended action.

import re
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2"
MAX_LOGS = 20  # most log lines we hand to the model as evidence


def fallback_recommendation(event: dict) -> str:
    """Pick a fixed recommended action for when the LLM is not available.

    Looks at the MITRE tactic, event type and Wazuh level to choose the closest
    matching advice, so the action field is never left empty.
    """
    tactics = " ".join(event.get("mitre_tactic") or []).lower()
    etype = (event.get("event_type") or "").lower()
    desc = (event.get("rule_description") or "").lower()
    level = event.get("wazuh_level") or 0
    blob = f"{tactics} {etype} {desc}"

    if "brute" in blob or "authentication_fail" in blob or "credential" in tactics:
        return ("Isolate the affected host and reset the targeted account's credentials. "
                "Block the source IP and review other login attempts from it.")
    if "web" in blob or "sql" in blob or "injection" in blob:
        return ("Inspect the web server logs for exploitation, take the affected endpoint offline "
                "if confirmed, and patch the vulnerable component.")
    if "malware" in blob or "ransom" in blob or "virus" in blob:
        return ("Quarantine the host immediately, capture a forensic image, and run a full "
                "anti-malware scan before reconnecting it to the network.")
    if level >= 12:
        return ("Treat as a critical incident: isolate the host, preserve evidence, and escalate "
                "to the on-call responder.")
    return ("Investigate the source IP and affected user, correlate with surrounding events, and "
            "escalate if the activity is unexpected.")


def _mitre_ref(event: dict) -> str:
    ids = ", ".join(event.get("mitre_id") or [])
    tactics = ", ".join(event.get("mitre_tactic") or [])
    techniques = ", ".join(event.get("mitre_technique") or [])
    if not (ids or tactics or techniques):
        return "none"
    parts = [p for p in (ids, tactics, techniques) if p]
    return " / ".join(parts)


def _build_prompt(event: dict, severity: int) -> str:
    # Lay out the event details and its raw logs as the instructions we send to
    # the model, including the exact section headers we expect back.
    logs = event.get("trigger_logs") or []
    if not logs and event.get("message"):
        logs = [event["message"]]
    log_block = "\n".join(logs[:MAX_LOGS]) if logs else "(no raw logs available)"

    return f"""You are a SOC analyst for real-time alert triage.

You receive:
1. SOCevent (authoritative: severity, MITRE, classification)
2. full_log_sequence (supporting evidence)

---

SOURCE OF TRUTH:
SOCevent is authoritative. Logs are context only.

---

SOCevent:
- Alert: {event.get("rule_description") or event.get("event_type")}
- Rule ID: {event.get("rule_id")}
- Wazuh level: {event.get("wazuh_level")}
- Severity (ML 0-100): {severity}
- Classification: {event.get("label")}
- MITRE: {_mitre_ref(event)}
- Tenant: {event.get("group")}
- Host/agent: {event.get("agent_name")}
- Source IP: {event.get("source_ip")}
- User: {event.get("user")}

full_log_sequence:
{log_block}

---

TASK:
1. Describe what happened in plain security terms
2. Infer attacker intent (high-level only)
3. Identify attack type
4. Provide immediate response actions

---

RULES:
- Do not repeat SOCevent fields (severity, rule_id, MITRE, etc.) verbatim
- Do not invent tools, malware, or MITRE IDs
- Use logs only for behavioral context
- Use operational SOC language only

---

OUTPUT FORMAT (use these exact headers):

ATTACK SUMMARY:
3-4 sentences max covering the incident description, attacker intent, and the key log behavior pattern. Include the MITRE reference from SOCevent if available; otherwise omit it.

SOC RESPONSE:
2 sentences: first the containment action, then the investigation action.
"""


def generate_analysis(event: dict, severity: int) -> tuple[str | None, str]:
    """Ask the LLM to explain an event and return its explanation and action.

    Sends the event and its logs to Ollama and reads back the attack summary and
    the suggested response. If anything goes wrong the explanation comes back as
    None and the action falls back to a fixed suggestion.
    """
    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": _build_prompt(event, severity), "stream": False},
            timeout=60,
        )
        response.raise_for_status()
        text = response.json()["response"].strip()
        return _parse_sections(text, event)
    except Exception:
        return None, fallback_recommendation(event)


# Header that begins the response/action section (tolerant of model variation).
_RESPONSE_HDR = re.compile(r"^\s*#*\s*(SOC RESPONSE|RESPONSE|ACTION)\b.*?:?\s*$", re.I | re.M)
_SUMMARY_HDR = re.compile(r"^\s*#*\s*(ATTACK SUMMARY|SUMMARY|EXPLANATION)\b.*?:?\s*$", re.I | re.M)


def _clean(text: str | None) -> str | None:
    if not text:
        return None
    # Drop leading bullet/numbered markers per line and collapse blank lines.
    lines = [re.sub(r"^\s*[-*\d.]+\s*", "", ln).strip() for ln in text.splitlines()]
    cleaned = " ".join(ln for ln in lines if ln).strip()
    return cleaned or None


def _parse_sections(text: str, event: dict) -> tuple[str | None, str]:
    """Split the model output into (explanation, recommended_action)."""
    resp = _RESPONSE_HDR.search(text)
    summary = _SUMMARY_HDR.search(text)

    explanation: str | None
    action: str | None
    if resp:
        start = summary.end() if summary else 0
        explanation = _clean(text[start:resp.start()])
        action = _clean(text[resp.end():])
    elif summary:
        explanation = _clean(text[summary.end():])
        action = None
    else:
        # Model ignored the format — treat the whole thing as the summary.
        explanation = _clean(text)
        action = None

    return explanation, (action or fallback_recommendation(event))


# Backwards-compatible helper (explanation only).
def generate_explanation(event: dict, severity: int) -> str | None:
    return generate_analysis(event, severity)[0]
