"""
Pipeline integration test
─────────────────────────
Flow:
    1. Inject synthetic Wazuh alerts directly into OpenSearch (wazuh-alerts-* index)
    2. Retrieve them via WazuhClient.get_recent_alerts()
    3. Normalize each with normalize_wazuh_alert()
    4. Feed into a simple correlator that groups by source IP + MITRE tactic
    5. Print a summary of every Alert produced

Run from your project root:
    python -m tests.test_pipeline          (if inside a package)
    python tests/test_pipeline.py          (direct)
"""

###### source .venv/bin/activate
##### python -m backend.test

import logging
import sys
import uuid
from datetime import datetime, timezone, timedelta

import requests
import urllib3

# ── Path fix so we can run the file directly ─────────────────────────────────
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.log_evaluation.classes.soc_event import SOCevent
from backend.ingestion.wazuh_client import WazuhClient
from backend.ingestion.normalizer import normalize_wazuh_alert
from backend.log_evaluation.classes.alert import Alert   # your Alert dataclass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("test_pipeline")

# ─────────────────────────────────────────────────────────────────────────────
# 1.  SYNTHETIC TEST LOGS
#     Three logs that "belong together": brute-force → success → privilege esc.
#     All share the same source IP so the correlator groups them.
# ─────────────────────────────────────────────────────────────────────────────
BASE_TIME = datetime.now(timezone.utc)

TEST_ALERTS = [
    {
        "_description": "SSH brute-force attempt",
        "timestamp": (BASE_TIME - timedelta(seconds=30)).isoformat(),
        "full_log": "Failed password for root from 10.0.0.99 port 22 ssh2",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "sshd: Multiple authentication failures",
            "groups": ["authentication_failed", "ssh"],
            "mitre": {
                "id":        ["T1110"],
                "tactic":    ["Credential Access"],
                "technique": ["Brute Force"],
            },
        },
        "data":  {"srcip": "10.0.0.99", "dstport": "22"},
        "agent": {"ip": "192.168.1.10"},
    },
    {
        "_description": "SSH login success after brute-force",
        "timestamp": (BASE_TIME - timedelta(seconds=20)).isoformat(),
        "full_log": "Accepted password for root from 10.0.0.99 port 22 ssh2",
        "rule": {
            "id": "5715",
            "level": 8,
            "description": "sshd: Authentication success",
            "groups": ["authentication_success", "ssh"],
            "mitre": {
                "id":        ["T1078"],
                "tactic":    ["Defense Evasion", "Persistence", "Privilege Escalation"],
                "technique": ["Valid Accounts"],
            },
        },
        "data":  {"srcip": "10.0.0.99", "dstport": "22"},
        "agent": {"ip": "192.168.1.10"},
    },
    {
        "_description": "Privilege escalation via sudo",
        "timestamp": BASE_TIME.isoformat(),
        "full_log": "sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
        "rule": {
            "id": "5402",
            "level": 12,
            "description": "Successful sudo to ROOT executed",
            "groups": ["sudo", "privilege_escalation"],
            "mitre": {
                "id":        ["T1548"],
                "tactic":    ["Privilege Escalation"],
                "technique": ["Abuse Elevation Control Mechanism"],
            },
        },
        "data":  {"srcip": "10.0.0.99", "dstport": ""},
        "agent": {"ip": "192.168.1.10"},
    },
    {
        "_description": "Unrelated event — different source IP",
        "timestamp": BASE_TIME.isoformat(),
        "full_log": "Failed password for admin from 172.16.0.5 port 443 https",
        "rule": {
            "id": "5710",
            "level": 6,
            "description": "sshd: Authentication failure",
            "groups": ["authentication_failed"],
            "mitre": {
                "id":        ["T1110"],
                "tactic":    ["Credential Access"],
                "technique": ["Brute Force"],
            },
        },
        "data":  {"srcip": "172.16.0.5", "dstport": "443"},
        "agent": {"ip": "192.168.1.20"},
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 2.  INJECT directly into OpenSearch  (wazuh-alerts-* index)
# ─────────────────────────────────────────────────────────────────────────────
def inject_test_alerts(client: WazuhClient) -> list[str]:
    """
    POST each synthetic alert directly to OpenSearch.
    Returns the list of doc_ids injected so we can clean up afterwards.
    """
    doc_ids = []

    for alert in TEST_ALERTS:
        doc_id   = f"test-{uuid.uuid4()}"
        payload  = {k: v for k, v in alert.items() if not k.startswith("_")}
        # Add @timestamp so OpenSearch sorts correctly
        payload["@timestamp"] = payload.get("timestamp", BASE_TIME.isoformat())

        log.info("Injecting: [%s] %s", alert["_description"], doc_id)

        r = requests.put(
            f"{client.indexer_url}/wazuh-alerts-test/_doc/{doc_id}",
            auth=(client.indexer_user, client.indexer_pass),
            json=payload,
            verify=client.verify,
            timeout=15,
        )
        r.raise_for_status()
        doc_ids.append(doc_id)
        log.debug("  → stored: %s", r.json().get("result"))

    # OpenSearch needs a moment to make newly indexed docs searchable
    import time
    log.info("Waiting 1 s for OpenSearch to index...")
    time.sleep(1)

    return doc_ids


# ─────────────────────────────────────────────────────────────────────────────
# 3.  RETRIEVE  from OpenSearch
# ─────────────────────────────────────────────────────────────────────────────
def retrieve_test_alerts(client: WazuhClient, doc_ids: list[str]) -> list[dict]:
    """Fetch only the docs we just injected by their IDs."""
    r = requests.post(
        f"{client.indexer_url}/wazuh-alerts-test/_search",
        auth=(client.indexer_user, client.indexer_pass),
        json={
            "size": len(doc_ids),
            "query": {"ids": {"values": doc_ids}},
            "sort": [{"@timestamp": {"order": "asc"}}],
        },
        verify=client.verify,
        timeout=15,
    )
    r.raise_for_status()
    hits = r.json().get("hits", {}).get("hits", [])
    log.info("Retrieved %d / %d alerts from OpenSearch", len(hits), len(doc_ids))
    return [hit["_source"] for hit in hits]


# ─────────────────────────────────────────────────────────────────────────────
# 4.  NORMALIZE
# ─────────────────────────────────────────────────────────────────────────────
def run_normalization(raw_alerts: list[dict]) -> list[SOCevent]:
    events = []
    for i, raw in enumerate(raw_alerts):
        log.info("Normalizing alert %d / %d  rule_id=%s",
                 i + 1, len(raw_alerts), raw.get("rule", {}).get("id"))
        event = normalize_wazuh_alert(raw)
        log.debug(
            "  src=%-15s  mitre_id=%-10s  tactic=%s",
            event.source_ip,
            event.mitre_id,
            event.mitre_tactic,
        )
        events.append(event)
    return events


# ─────────────────────────────────────────────────────────────────────────────
# 5.  SIMPLE CORRELATOR
#     Groups events into Alerts by source IP.
#     Within the same source IP group, separate Alerts are created if there is
#     a gap of more than `TIME_WINDOW_SECONDS` between consecutive events.
# ─────────────────────────────────────────────────────────────────────────────
TIME_WINDOW_SECONDS = 300   # 5-minute window — tune to your needs

def _parse_ts(ts) -> datetime:
    """Safely coerce a timestamp (str or datetime) to a UTC-aware datetime."""
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def correlate(events: list[SOCevent]) -> list[Alert]:
    """
    Naive but illustrative correlator:
      - Primary key  : source_ip  (None → its own bucket)
      - Secondary key: time window (new Alert if gap > TIME_WINDOW_SECONDS)
    """
    # Sort by timestamp first so the time-window logic works
    sorted_events = sorted(events, key=lambda e: _parse_ts(e.timestamp))

    # bucket_key → Alert
    open_alerts: dict[str, Alert] = {}

    for event in sorted_events:
        src  = event.source_ip or "unknown"
        ts   = _parse_ts(event.timestamp)

        existing = open_alerts.get(src)

        if existing is None:
            # No open alert for this source IP yet
            log.debug("CORRELATOR  NEW alert for src=%s", src)
            open_alerts[src] = Alert.new_alert(event)

        else:
            gap = (ts - _parse_ts(existing.last_seen)).total_seconds()
            if gap <= TIME_WINDOW_SECONDS:
                log.debug("CORRELATOR  ADD to alert %s  (gap=%.0fs)  src=%s",
                          existing.alert_id[:8], gap, src)
                existing.add_event(event)
            else:
                # Gap too large → close old alert, open fresh one
                log.debug("CORRELATOR  ROTATE alert for src=%s  (gap=%.0fs > %ds)",
                          src, gap, TIME_WINDOW_SECONDS)
                open_alerts[src] = Alert.new_alert(event)

    return list(open_alerts.values())


# ─────────────────────────────────────────────────────────────────────────────
# 6.  PRINT SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
def print_summary(alerts: list[Alert]) -> None:
    sep = "─" * 60
    print(f"\n{'═' * 60}")
    print(f"  CORRELATION RESULT  —  {len(alerts)} alert(s) produced")
    print(f"{'═' * 60}")

    for i, alert in enumerate(alerts, 1):
        print(f"\n{sep}")
        print(f"  Alert #{i}  id={alert.alert_id}")
        print(f"{sep}")
        print(f"  Events       : {alert.event_count}")
        print(f"  First seen   : {alert.first_seen}")
        print(f"  Last seen    : {alert.last_seen}")
        print(f"  Source IPs   : {alert.source_ips}")
        print(f"  Dest IPs     : {alert.destination_ips}")
        print(f"  MITRE IDs    : {alert.mitre_id}")
        print(f"  Tactics      : {alert.mitre_tactic}")
        print(f"  Techniques   : {alert.mitre_technique}")
        print(f"  Status       : {alert.status}")
        print()
        for j, ev in enumerate(alert.events, 1):
            print(f"    [{j}] rule={ev.rule_id:<6}  level={ev.wazuh_level:<3}"
                  f"  src={str(ev.source_ip):<15}  type={ev.event_type}")
            print(f"         log: {(ev.raw_log or '')[:80]}")

    print(f"\n{'═' * 60}\n")


# ─────────────────────────────────────────────────────────────────────────────
# 7.  CLEANUP  (removes the test index so it doesn't pollute Wazuh)
# ─────────────────────────────────────────────────────────────────────────────
def cleanup(client: WazuhClient) -> None:
    log.info("Cleaning up test index wazuh-alerts-test ...")
    r = requests.delete(
        f"{client.indexer_url}/wazuh-alerts-test",
        auth=(client.indexer_user, client.indexer_pass),
        verify=client.verify,
        timeout=15,
    )
    if r.status_code == 404:
        log.warning("Index not found — already deleted?")
    else:
        r.raise_for_status()
        log.info("Test index deleted: %s", r.json().get("acknowledged"))


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    log.info("=== Pipeline test START ===")

    client = WazuhClient()

    # ── Step 1: Inject ────────────────────────────────────────────────────────
    log.info("── Step 1: Injecting %d synthetic alerts ──", len(TEST_ALERTS))
    doc_ids = inject_test_alerts(client)

    try:
        # ── Step 2: Retrieve ──────────────────────────────────────────────────
        log.info("── Step 2: Retrieving from OpenSearch ──")
        raw_alerts = retrieve_test_alerts(client, doc_ids)

        if not raw_alerts:
            log.error("No alerts retrieved — check your OpenSearch connection / credentials")
            return

        # ── Step 3: Normalize ─────────────────────────────────────────────────
        log.info("── Step 3: Normalizing %d alerts ──", len(raw_alerts))
        events = run_normalization(raw_alerts)

        # ── Step 4: Correlate ─────────────────────────────────────────────────
        log.info("── Step 4: Correlating events (window=%ds) ──", TIME_WINDOW_SECONDS)
        alerts = correlate(events)

        # ── Step 5: Summary ───────────────────────────────────────────────────
        print_summary(alerts)

    finally:
        # Always clean up even if something blows up mid-test
        cleanup(client)

    log.info("=== Pipeline test END ===")


if __name__ == "__main__":
    main()