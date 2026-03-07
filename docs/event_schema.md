# Normalized Event Schema

All incoming logs will be converted into a unified schema so different log sources can be processed consistently.

## Fields

| Field       | Type           | Description |
|-------------|----------------|-------------|
timestamp     | string.        | Event timestamp (ISO 8601 format) |
source_ip     | string.        | IP address that initiated the event |
destination_ip| string         | Target IP address |
event_type    | string         | Type of security event |
user          | string         | User involved in the event (if applicable) |
severity      | int            | Risk score (0–100) |
message       | string         | Human-readable description of the event |
source        | string         | Source system (firewall, auth, cloud, etc.) |
context       | object         | Original raw log data |

---

## Example Event

```json
{
  "timestamp": "2026-03-07T12:00:00",
  "source_ip": "192.168.1.5",
  "destination_ip": "10.0.0.2",
  "event_type": "failed_login",
  "user": "admin",
  "severity": 0,
  "message": "Multiple failed login attempts",
  "source": "auth_server",
  "context": {
    "failed_attempts": 5
  }
}