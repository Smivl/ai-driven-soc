"""
Lightweight, env-gated latency trace tap.

Off by default — zero overhead unless SOC_PERF_TRACE=1. When enabled, the
pipeline records a timestamped line per event as it crosses key stages, so the
end-to-end latency harness (benchmarks/e2e_latency.py) can reconstruct:

    T4  = "received"  — ingest_worker created the SOCevent (alert reached the SOC)
    T5  = "explained" — explain_worker finished (fully enriched / dashboard-visible)

Each record carries the event's `marker` (the injected log's user field, e.g.
LOG-000123) so the harness can correlate back to the log it sent (T1) and the
Wazuh alert timestamp (T2).
"""

import json
import os
import threading
import time
from datetime import datetime, timezone

_ENABLED = os.getenv("SOC_PERF_TRACE") == "1"
_PATH = os.getenv("SOC_PERF_TRACE_FILE", "/tmp/soc_perf_trace.jsonl")
_lock = threading.Lock()


def enabled() -> bool:
    return _ENABLED


def record(stage: str, event_id: str | None, marker: str | None) -> None:
    """Append one stage crossing. No-op unless tracing is enabled."""
    if not _ENABLED:
        return
    rec = {
        "stage": stage,
        "event_id": event_id,
        "marker": marker,
        "ts": datetime.now(timezone.utc).isoformat(),
        "mono": time.time(),  # wall-clock epoch seconds, for delta math
    }
    try:
        with _lock, open(_PATH, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass  # tracing must never disturb the pipeline
