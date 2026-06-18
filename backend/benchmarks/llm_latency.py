"""
Separate LLM latency test (per "Performance testing.pdf", test 2).

For each alert it records:
    T1  LLM request sent
    T2  LLM explanation completed

Runs the real explanation path (Ollama) on recent Wazuh alerts. No backend
server required.

    python -m benchmarks.llm_latency --count 100

Writes a CSV (Alert ID, T1, T2, duration) plus a summary to benchmarks/reports/.
Each call takes seconds, so 100 alerts ≈ several minutes; lower --count to
sample faster (the PDF allows fewer).
"""

import argparse
import csv
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from ingestion.explanation import generate_analysis
from ingestion.normalizerfixed import normalize_wazuh_alert
from ingestion.wazuh_client import WazuhClient

REPORT_DIR = Path(__file__).parent / "reports"


def _samples(count: int) -> list[dict]:
    """Recent alerts, normalised into the dict shape generate_analysis expects."""
    raw = WazuhClient().get_recent_alerts(limit=min(count, 500))
    out = []
    for a in raw:
        try:
            ev = normalize_wazuh_alert(a, group_resolver=lambda _i: "companyB")
        except Exception:
            continue
        d = ev.return_dict()
        d["message"] = d.get("raw_log")
        out.append(d)
    if not out:
        return out
    # Cycle if we need more iterations than we have distinct alerts.
    return [out[i % len(out)] for i in range(count)]


def main() -> None:
    ap = argparse.ArgumentParser(description="Standalone LLM explanation latency test.")
    ap.add_argument("--count", type=int, default=100)
    args = ap.parse_args()

    samples = _samples(args.count)
    if not samples:
        print("No sample alerts available (is Wazuh reachable / are there alerts?).")
        return
    print(f"Measuring LLM explanation latency over {len(samples)} alerts...")

    rows = []
    for i, d in enumerate(samples, 1):
        t1 = time.time()
        generate_analysis(d, d.get("severity") or 0)
        t2 = time.time()
        rows.append((f"Alert-{i:03d}", t1, t2))
        print(f"  Alert-{i:03d}: {(t2 - t1):.2f}s")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = REPORT_DIR / f"llm_latency_{ts}.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Alert ID", "T1 LLM Request Sent", "T2 LLM Explanation Completed",
                    "duration (ms)"])
        for aid, t1, t2 in rows:
            w.writerow([aid,
                        datetime.fromtimestamp(t1, tz=timezone.utc).isoformat(),
                        datetime.fromtimestamp(t2, tz=timezone.utc).isoformat(),
                        round((t2 - t1) * 1000, 1)])

    durs = sorted((t2 - t1) * 1000 for _a, t1, t2 in rows)
    p95 = durs[min(len(durs) - 1, int(round(0.95 * (len(durs) - 1))))]
    print(f"\n  n={len(durs)}  mean={statistics.fmean(durs):.0f}ms  "
          f"median={statistics.median(durs):.0f}ms  p95={p95:.0f}ms  max={durs[-1]:.0f}ms")
    print(f"  table → {path}")


if __name__ == "__main__":
    main()
