import requests
import datetime
from backend.log_evaluation.classes.alert import Alert
from backend.log_evaluation.classes.soc_event import SOCevent


OLLAMA_URL = "http://localhost:11434/api/generate"

def generate_single_behavior_explanation(alert: Alert) -> str:
    # 1. Capture the single threat context metrics
    # Since this is one focused alert, we summarize the common vectors
    ip_list = ", ".join(alert.source_ips) if alert.source_ips else "Internal/Local"
    user_list = ", ".join(alert.users) if alert.users else "Unknown/System"
    mitre_list = ", ".join(alert.mitre_id) if alert.mitre_id else "Unclassified Behavior"

    # 2. Extract a snapshot of the logs causing this behavior
    # We take a small chronological sample or the full list if it's brief
    sorted_events = sorted(alert.events, key=lambda e: e.timestamp if e.timestamp else datetime.min)
    
    timeline_lines = []
    for i, ev in enumerate(sorted_events[:15], 1):  # Cap at 15 logs to prevent prompt bloating
        timeline_lines.append(
            f"  - Log [{ev.timestamp}] | Dst: {ev.destination_ip}:{ev.port} | Message: {ev.raw_log}"
        )
    timeline_str = "\n".join(timeline_lines)

    # 3. The Focused, Single-Alert SOC Prompt
    prompt = f"""
    You are a SOC Tier-1 Triage Analyst. Your task is to investigate a single, high-density security alert focused on a specific malicious behavior.

    === ALERT PROFILE ===
    - Primary Indicator: {mitre_list}
    - Attacking Source IP(s): {ip_list}
    - Target User Account(s): {user_list}
    - Total Event Volume: {alert.event_count} occurrences
    
    === RAW LOG EVIDENCE (Chronological Sample) ===
    {timeline_str}

    === INVESTIGATION REQUIREMENT ===
    Provide a highly concise, 3-part technical assessment of this specific behavior. Use clean Markdown formatting:

    1. **Behavioral Assessment**: In 2 sentences, explain exactly what type of activity this raw log pattern indicates (e.g., "This pattern indicates an aggressive credential stuffing or brute-force attack targeting the SSH daemon from an external source.").
    2. **Fidelity Verification**: State whether this looks like a True Positive (active malicious intent) or a False Positive (such as an administrative script or user who forgot their password). Point to a specific detail in the log sample that supports your conclusion.
    3. **Targeted Triage Steps**: Give exactly 2 immediate, technical steps to mitigate this specific vector (e.g., "Block source IP on perimeter firewall," or "Reset user credentials and verify MFA logs").

    Keep the response extremely direct, technical, and limited to 200-250 words total. No intro or outro fluff.
    """

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": "llama3.2",
                "prompt": prompt,
                "stream": False
            },
            timeout=30
        )
        response.raise_for_status()
        return response.json()["response"]
    except Exception as e:
        return f"[ERROR] Failed to execute single-alert triage analysis: {e}"