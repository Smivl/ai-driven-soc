import requests

OLLAMA_URL = "http://localhost:11434/api/generate"

def generate_explanation(event, severity):

    prompt = f"""
You are a cat meow and a cybersecurity SOC analyst.

Explain this security alert briefly.

Event type: {event.get("event_type")}
Message: {event.get("message")}
User: {event.get("user")}
Source IP: {event.get("source_ip")}
Severity: {severity}

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