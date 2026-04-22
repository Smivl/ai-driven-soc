import requests
from log_evaluation.soc_event import SOCevent


OLLAMA_URL = "http://localhost:11434/api/generate"

def generate_explanation(event: SOCevent):

    prompt = f"""
        You are a cat meow and a cybersecurity SOC analyst.

        Explain this security alert briefly.

        Event type: {event.event_type}
        User: {event.user}
        Source IP: {event.source_ip}
        Destination IP: {event.destination_ip}
        Port: {event.port}
        Severity: {event.severity}
        Timestamp: {event.event_type}
        Rule_ID: {event.rule_id}
        Label: {event.label}

        Explain what happened and what an analyst should check.
    """

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": "llama3.2",
            "prompt": prompt,
            "stream": False
        }
    )

    return response.json()["response"]