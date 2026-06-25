"""
    Rule-based scoring for sequences of security events
        Based on sequences of catagorized log
    THIS FILE IS NOT IMPLEMENTED AND FINISHED IN THE CURRENT PIPELINE AND IS EXPORTED FROM A DIFFERENT BRANCH
"""


from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import  List, Optional

from backend.app.log_evaluation.socevent import SOCevent


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
    
# ── Machine Learning init ──────────────────────────────────────────────────────────

def load_and_train_sequence(data_dir: str = "data"):

    path = f"{data_dir}/attack_sequences.csv"  # .py → .csv
    df   = pd.read_csv(path, on_bad_lines='skip')  # df not dfs, single file
    
    print(f"\nTotal: {len(df)} rows")

    sequences = df["sequence"]   # this is your X — the category string
    labels    = df["label"]      # this is your y

    X_train, X_test, y_train, y_test = train_test_split(
        sequences, labels, test_size=0.2, random_state=42  # sequences not logs
    )

    vectorizer = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1,3)
    )
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


# ── Engine ────────────────────────────────────────────────────────────────────

class ThreatEngine:

    # different sliding windows to check for attacks
    WINDOWS = [
        {"name": "fast",   "seconds": 30}, # half a minute
        {"name": "medium", "seconds": 300}, # 5 min
        {"name": "slow",   "seconds": 1800}, # 30 min
    ]
    MIN_EVENTS = 5 

    def __init__(self,vectorizer,model):
        self.vectorizer = vectorizer
        self.model = model
        # ip -> deque of (timestamp, event) — one deque per IP, all windows share it
        self.buffer: dict[str, deque] = defaultdict(deque)


    def add_event(self, event: SOCevent) -> List[Alert]:
        if not event.source_ip or not event.category or not event.timestamp:
            return []

        now = _parse_ts(event.timestamp)
        ip  = event.source_ip

        # Add to buffer
        self.buffer[ip].append((now, event))

        max_cutoff = now - timedelta(seconds=self.WINDOWS[-1]["seconds"])
        while self.buffer[ip] and self.buffer[ip][0][0] < max_cutoff:
            self.buffer[ip].popleft()

        # Run ML on each window
        alerts = []
        for window in self.WINDOWS:
            cutoff  = now - timedelta(seconds=window["seconds"])
            in_window = [e for ts, e in self.buffer[ip] if ts >= cutoff]

            if len(in_window) < self.MIN_EVENTS:
                continue   # not enough events yet

            seq_text = " ".join(e.category for e in in_window if e.category)
            ml_label, ml_conf = self._predict(seq_text)

            if ml_label == "benign" or ml_conf < 0.70:
                continue   # not confident enough

            alerts.append(Alert(
                label         = ml_label,
                mitre         = "ML",
                source_ip     = ip,
                count         = len(in_window),
                window_s      = window["seconds"],
                triggered_at  = now,
                sequence      = in_window,
            ))

        return alerts

    def _predict(self, seq_text: str) -> tuple[str, float]:
        X     = self.vectorizer.transform([seq_text])
        X_df  = pd.DataFrame(X.toarray(), columns=self.vectorizer.get_feature_names_out())
        probs = self.model.predict_proba(X_df)[0]
        label = self.model.classes_[probs.argmax()]
        conf  = float(probs.max())
        return label, conf
        

        

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



    

    
    
    
    