"""
    Rule-based scoring for sequences of security events
        Based on sequences of catagorized log
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import  List, Optional

from backend.log_evaluation.soc_event import SOCevent
from backend.log_evaluation.mitre_rules import RULES

# Sourced from:
#   MITRE ATT&CK  https://attack.mitre.org
#   Inspiration from https://github.com/mccleod1290/security-log-analyzer

###### source .venv/bin/activate
##### python -m backend.log_evaluation.rule_sequence

# ── Alert ─────────────────────────────────────────────────────────────────────

@dataclass
class Alert:        
    label:      str
    mitre:      str
    source_ip:  str
    count:      int
    window_s:   int
    triggered_at: datetime

    def render(self) -> str:
        tag = "ALERT"
        lines = [
            f"[{tag}] {self.label} ({self.mitre})",
            f"  IP      : {self.source_ip}",
            f"  Count   : {self.count} events in {self.window_s}s",
            f"  At      : {self.triggered_at.isoformat()}",
        ]
        return "\n".join(lines)


# ── Engine ────────────────────────────────────────────────────────────────────

class ThreatEngine:
    def __init__(self):
        # (ip, category) -> deque of timestamps
        self._windows: dict[tuple, deque] = defaultdict(deque)
        # track fired rules to avoid duplicate alerts in same window
        self._fired= {}


    def process(self, event: SOCevent) -> List[Alert]:
        if not event.source_ip or not event.label or not event.timestamp:
            return []

        now = _parse_ts(event.timestamp)
        ip  = event.source_ip
        cat = event.label

        # Push event into its window
        self._windows[(ip, cat)].append(now)

        alerts = []
        for rule in RULES:
            alert = self.check_rule(rule, ip, now)
            alerts.append(alert)

        return alerts

    def check_rule(self, rule: dict, ip: str, now: datetime) -> Optional[Alert]:
        window_s = rule["window_s"]
        cutoff   = now - timedelta(seconds=window_s)
        rule_key = (ip, rule["id"])

        if "multi_category" in rule:
            return self.check_multi_rule(rule, ip, now, cutoff, rule_key)
        else:
            return self.check_single_rule(rule, ip, now, cutoff, rule_key)

    def check_single_rule(self, rule: dict, ip: str, now: datetime, cutoff: datetime, rule_key: tuple) -> Optional[Alert]:
        cat       = rule["category"] # pulls the category it checking for now
        threshold = rule["threshold"] # how many times this category must pass for a possible attack
        dq        = self._windows[(ip, cat)]

        # Trim stale events
        while dq and dq[0] < cutoff:
            dq.popleft()

        # Count is simply how many events from this IP in this category are within the window
        count = len(dq)

        # Optional: port diversity guard
        if "min_unique_ports" in rule:
            # We don't track ports in the window here — that would need event storage.
            # Simple heuristic: connection-failed bursts without port data still fire.
            pass

        if count < threshold:
            return None

        if rule_key in self._fired:
            return None
        
        self._fired[rule_key] = now
        return Alert(
                    label=rule["label"],
                    mitre=rule["mitre"],
                    source_ip=ip,
                    count=count,
                    window_s=rule["window_s"],
                    triggered_at=now,
                )

    def check_multi_rule(self, rule: dict, ip: str, now: datetime, cutoff: datetime, rule_key: tuple) -> Optional[Alert]:
        total = 0

        for cat, sub_threshold in rule["multi_category"].items():
            dq = self._windows[(ip, cat)]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) < sub_threshold:
                return None          # all categories must hit their threshold
            total += len(dq)

         # Multi-rules are always confirmed — no weak state
        if rule_key in self._fired:
            return None
        self._fired[rule_key] = now

        return Alert(
            label=rule["label"],
            mitre=rule["mitre"],
            source_ip=ip,
            count=total,
            window_s=rule["window_s"],
            triggered_at=now,
        )


# ── Timestamp parser ──────────────────────────────────────────────────────────

def _parse_ts(ts) -> datetime:
    if isinstance(ts, datetime):
        return ts
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse timestamp: {ts!r}")


# ── Quick smoke test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    from datetime import datetime, timedelta
    from backend.log_evaluation.soc_event import SOCevent

    engine = ThreatEngine()
    base = datetime(2024, 1, 15, 2, 0, 0)

    alerts_list = []

    # Simulate 25 auth failures in 20 seconds from one I
    for i in range(25):
        ev = SOCevent(
            source_ip="10.0.0.99",
            label="authentication-failed",
            timestamp=(base + timedelta(seconds=i * 0.1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            raw_log="Failed password for root",
        )
        alerts = engine.process(ev)
        for a in alerts:
            if a:
                alerts_list.append(a)
    
        # Test 2: exfiltration — file reads + network traffic from same IP
    for i in range(10):
        ev = SOCevent(
            source_ip="10.0.0.55",
            label="file-read",
            timestamp=(base + timedelta(seconds=i * 5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            raw_log="File read by process",
        )
        alerts = engine.process(ev)
        for a in alerts:
            if a:
                alerts_list.append(a)

    for i in range(10):
        ev = SOCevent(
            source_ip="10.0.0.55",
            label="network-traffic",
            timestamp=(base + timedelta(seconds=i * 5 + 1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            raw_log="Outbound connection established",
        )
        alerts = engine.process(ev)
        for a in alerts:
            if a:
                alerts_list.append(a)


    for a in alerts_list:
        print(a.render())
        print()
    
    