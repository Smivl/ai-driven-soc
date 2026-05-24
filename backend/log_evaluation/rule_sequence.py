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

import pandas as pd
import lightgbm as lgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Sourced from:
#   MITRE ATT&CK  https://attack.mitre.org
#   Inspiration from https://github.com/mccleod1290/security-log-analyzer

###### source .venv/bin/activate
##### python -m backend.log_evaluation.rule_sequence

# ── Alert ─────────────────────────────────────────────────────────────────────

@dataclass
class Alert:        
    label:          str
    mitre:          str
    source_ip:      str
    count:          int
    window_s:       int
    triggered_at:   datetime
    sequence:       List[SOCevent] = field(default_factory=list)

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
        while dq and dq[0][0] < cutoff:
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

        sequence_events = []
        for cat, sub_threshold in rule["multi_category"].items():
            dq = self._windows[(ip, cat)]
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if len(dq) < sub_threshold:
                return None
            total += len(dq)
            sequence_events.extend(ev for _, ev in dq)  # collect events

        # sort by timestamp
        sequence_events.sort(key=lambda e: e.timestamp)

        return Alert(
            label=rule["label"],
            mitre=rule["mitre"],
            source_ip=ip,
            count=total,
            window_s=rule["window_s"],
            triggered_at=now,
            sequence=sequence_events,
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

# ── Machine Learning part ──────────────────────────────────────────────────────────

def load_and_train_sequence(data_dir: str = "data"):

    path = f"{data_dir}/attack_sequences.csv"  # .py → .csv
    df   = pd.read_csv(path, on_bad_lines='skip')  # df not dfs, single file
    
    print(f"\nTotal: {len(df)} rows")

    sequences = df["sequence"]   # this is your X — the category string
    labels    = df["label"]      # this is your y

    X_train, X_test, y_train, y_test = train_test_split(
        sequences, labels, test_size=0.2, random_state=42  # sequences not logs
    )

    vectorizer = TfidfVectorizer(max_features=1000)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec  = vectorizer.transform(X_test)

    model = lgb.LGBMClassifier(n_estimators=100, verbose=-1)
    model.fit(X_train_vec, y_train)

    X_test_vec = vectorizer.transform(X_test)
    # convert to DataFrame to keep feature names
    X_test_df = pd.DataFrame(X_test_vec.toarray(), columns=vectorizer.get_feature_names_out())
    acc = accuracy_score(y_test, model.predict(X_test_df))
    print(f"Accuracy: {acc:.3f}")

    return vectorizer, model

# ── Quick smoke test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    from datetime import datetime, timedelta
    from backend.log_evaluation.soc_event import SOCevent

    vectorizer, model = load_and_train_sequence()

    # Test sequences
    test_cases = [
        # Brute force — many auth failures
        "authentication-failed authentication-failed authentication-failed "
        "authentication-failed authentication-failed authentication-failed "
        "authentication-failed authentication-failed authentication-failed "
        "authentication-failed authentication-failed authentication-failed "
        "authentication-failed authentication-failed authentication-failed "
        "authentication-failed authentication-failed authentication-failed "
        "authentication-failed authentication-failed authentication-failed ",

        # Exfiltration — file reads + network
        "file-read file-read file-read file-read file-read file-read "
        "file-read file-read network-traffic network-traffic network-traffic "
        "network-traffic file-write file-write",

        # Benign
        "authentication-success http-request-success file-read "
        "connection-opened user-session-open process-info",
    ]

    for seq in test_cases:
        X    = vectorizer.transform([seq])
        X_df = pd.DataFrame(X.toarray(), columns=vectorizer.get_feature_names_out())
        probs = model.predict_proba(X_df)[0]

        print(f"Sequence: {seq[:60]}...")
        for label, prob in sorted(zip(model.classes_, probs), key=lambda x: -x[1]):
            bar = "█" * int(prob * 20)
            print(f"  {label:<25} {prob:.0%}  {bar}")
        print()

    

    
    