# tests/wazuh_client_test.py
"""
Simple test — inject 2 fake alerts and read them back.
"""
import subprocess
import time
import sys
import os

###### source .venv/bin/activate
##### python -m tests.wazuh_client_test

# So Python can find wazuh_client.py
sys.path.append(os.path.join(os.path.dirname(__file__), "../../services/ingestion"))

from services.soc.ingestion.wazuh_client import WazuhClient


def inject_fake_log(log_line: str):
    """Write a fake log line directly into the Wazuh container."""
    subprocess.run([
        "docker", "exec", "single-node-wazuh.manager-1",
        "bash", "-c",
        f'echo "{log_line}" >> /var/ossec/logs/active-responses.log'
    ])
    print(f"  Injected: {log_line[:70]}")


def test_fetch_alerts():
    print("=" * 50)
    print("  Wazuh Client — Simple Test")
    print("=" * 50)

    # ── 1. Connect ────────────────────────────────
    print("\n1. Connecting to Wazuh...")
    client = WazuhClient()
    token = client._authenticate()
    print(f"   Token received: {token[:20]}...")

    # ── 2. Inject 2 test alerts ───────────────────
    print("\n2. Injecting 2 fake alerts...")

    inject_fake_log(
        "Jan 15 10:23:45 server sshd[1234]: "
        "Failed password for admin from 192.168.1.105 port 4444 ssh2"
    )

    inject_fake_log(
        "Jan 15 10:24:00 server sshd[1234]: "
        "Failed password for root from 192.168.1.105 port 4444 ssh2"
    )

    # ── 3. Wait for Wazuh to process them ─────────
    print("\n3. Waiting for Wazuh to process logs (5 seconds)...")
    time.sleep(5)

    # ── 4. Fetch and display ───────────────────────
    print("\n4. Fetching recent alerts...")
    alerts = client.get_recent_alerts(limit=5)

    print(f"\n   Found {len(alerts)} alerts:\n")
    for alert in alerts:
        level = alert.get("rule", {}).get("level", "?")
        desc  = alert.get("rule", {}).get("description", "no description")
        ts    = alert.get("timestamp", "no timestamp")
        src   = alert.get("data", {}).get("srcip", "unknown ip")
        print(f"   [{level}] {desc}")
        print(f"         src: {src} | {ts}")
        print()

    print("=" * 50)
    print("  Test complete")
    print("  Check dashboard: https://localhost")
    print("=" * 50)


if __name__ == "__main__":
    test_fetch_alerts()