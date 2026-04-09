from explanation import generate_explanation

event = {
    "event_type": "failed_login",
    "message": "Failed login attempt for admin",
    "user": "admin",
    "source_ip": "192.168.1.10"
}

severity = 3

explanation = generate_explanation(event, severity)

print("\n--- LLM Explanation ---\n")
print(explanation)