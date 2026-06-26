"""
End-to-end latency test (per "Performance testing.pdf", test 1).

For each load level it injects uniquely-tagged logs that every fire the custom
honeytoken rule (level 13 — so every log alerts, satisfying "threshold = 1"),
then reconstructs per-log timestamps:

    T1  Log sent            — when the harness emitted the log (host clock)
    T2  Wazuh alert         — alert @timestamp from the indexer
    T4  SOC received        — ingest_worker created the SOCevent (perf trace)
    T5  Dashboard visible   — explain_worker finished, fully enriched (perf trace)

Correlation key is a unique source IP per log (198.18.x.y), which survives into
both the Wazuh alert (data.srcip) and our SOCevent (source_ip).

PREREQUISITES
  * Wazuh manager running with the custom datavault rule installed.
  * The SOC backend running WITH tracing enabled, e.g.:
      SOC_PERF_TRACE=1 INGEST_POLL_SECONDS=2 INGEST_BATCH_SIZE=5000 \
        uv run uvicorn app.main:app
    (Ollama running too, or T5 falls back to a heuristic and is still recorded.)

USAGE
    python -m tests.benchmarks.e2e_latency --test all
    python -m tests.benchmarks.e2e_latency --test baseline
    python -m tests.benchmarks.e2e_latency --test saturation --max-drain 60

Writes one CSV per test plus a Markdown summary to benchmarks/reports/.
Note: T5 includes the LLM stage (~seconds/event, single worker) so at higher
loads T5 coverage will be partial — that gap is itself the headline finding.
"""

import argparse
import csv
import json
import re
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from backend.app.ingestion.feeder import setup_tenants
from backend.app.tenants.tenants import DEFAULT_TENANTS_PATH, load_tenants
from backend.app.ingestion.wazuh_client import WazuhClient
from backend.app.ingestion.wazuh_injector import inject_batch, wrap

import os

CONTAINER = "single-node-wazuh.manager-1"
TRACE_FILE = os.getenv("SOC_PERF_TRACE_FILE", "/tmp/soc_perf_trace.jsonl")
REPORT_DIR = Path(__file__).parent / "reports"
RULE_ID = "100110"  # custom honeytoken rule — every test log trips this (level 13)

# (rate logs/sec, duration sec) per the PDF.
TESTS = {
    "baseline": (1, 10),
    "low": (10, 10),
    "medium": (100, 10),
    "saturation": (1000, 5),
}


def ip_for(idx: int) -> str:
    # 198.18.0.0/15 is the IETF benchmarking range — safe + plenty of addresses.
    return f"198.18.{idx // 254}.{idx % 254 + 1}"


def make_line(agent, idx: int) -> tuple[str, str, str]:
    log_id = f"LOG-{idx:05d}"
    ip = ip_for(idx)
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    raw = (f"{ts} {agent.name} datavault[2211]: action=download user=bench "
           f"src={ip} object=/vault/honeytoken/aws_keys.csv status=ok")
    return log_id, ip, wrap(agent.agent_id, agent.name, raw,
                            location="/var/log/datavault/access.log")


_TZ = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_wazuh_ts(s: str) -> float:
    s = s.replace("Z", "+00:00")
    s = _TZ.sub(r"\1:\2", s)  # +0000 -> +00:00
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc).timestamp()


def collect_t2(client: WazuhClient, since_iso: str, ips: set[str]) -> dict[str, float]:
    query = {"bool": {"must": [
        {"term": {"rule.id": RULE_ID}},
        {"range": {"@timestamp": {"gte": since_iso}}},
    ]}}
    try:
        hits = client._search_alerts(query, limit=len(ips) + 2000)
    except Exception as e:
        print(f"   [warn] could not query Wazuh alerts: {e}")
        return {}
    out: dict[str, float] = {}
    for h in hits:
        ip = h.get("data", {}).get("srcip")
        if ip in ips and ip not in out:
            out[ip] = parse_wazuh_ts(h.get("@timestamp") or h.get("timestamp"))
    return out


def read_trace(ips: set[str]) -> dict[str, dict]:
    res: dict[str, dict] = {}
    try:
        with open(TRACE_FILE) as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("marker") in ips:
                    res.setdefault(rec["marker"], {})[rec["stage"]] = rec["mono"]
    except FileNotFoundError:
        pass
    return res


def inject_schedule(triples: list[tuple[str, str, str]], rate: int) -> dict[str, float]:
    """Send logs at `rate`/sec in one-second batches; return {ip: T1 epoch}."""
    t1: dict[str, float] = {}
    pace = (1.0 / rate) if rate > 1 else 0.0
    for start in range(0, len(triples), rate):
        batch = triples[start:start + rate]
        t0 = time.time()
        for j, (_lid, ip, _line) in enumerate(batch):
            t1[ip] = t0 + (j / rate if rate > 1 else 0.0)
        inject_batch([t[2] for t in batch], CONTAINER, pace_seconds=pace)
        elapsed = time.time() - t0
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)
    return t1


def run_test(name: str, rate: int, duration: int, agent, idx_start: int,
             max_drain: int) -> int:
    total = rate * duration
    print(f"\n=== {name.upper()} — {rate} log/s × {duration}s = {total} logs ===")
    triples = [make_line(agent, idx_start + i) for i in range(total)]
    ips = {ip for _l, ip, _ in triples}

    since = datetime.now(timezone.utc).isoformat()
    print(f"   injecting {total} logs at {rate}/s ...")
    t1 = inject_schedule(triples, rate)
    print("   done; draining (collecting T2/T4/T5)...")

    client = WazuhClient()
    t2: dict[str, float] = {}
    trace: dict[str, dict] = {}
    deadline = time.time() + max_drain
    while time.time() < deadline:
        time.sleep(3)
        t2 = collect_t2(client, since, ips)
        trace = read_trace(ips)
        n_t2 = len(t2)
        n_t4 = sum("received" in v for v in trace.values())
        n_t5 = sum("explained" in v for v in trace.values())
        print(f"     coverage  T2={n_t2}/{total}  T4={n_t4}/{total}  T5={n_t5}/{total}")
        if n_t2 >= total and n_t4 >= total and n_t5 >= total:
            break

    rows = []
    for log_id, ip, _ in triples:
        rows.append({
            "log_id": log_id, "ip": ip,
            "T1": t1.get(ip),
            "T2": t2.get(ip),
            "T4": trace.get(ip, {}).get("received"),
            "T5": trace.get(ip, {}).get("explained"),
        })
    _write_csv(name, rows)
    _summarise(name, rows, total)
    return idx_start + total


def _iso(e):
    return datetime.fromtimestamp(e, tz=timezone.utc).isoformat() if e else ""


def _write_csv(name: str, rows: list[dict]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = REPORT_DIR / f"e2e_{name}_{ts}.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Log ID", "T1 Log Sent", "T2 Wazuh Alert", "T4 SOC Received",
                    "T5 Dashboard Visible", "dT2-T1 (ms)", "dT4-T1 (ms)", "dT5-T1 (ms)"])
        for r in rows:
            d2 = round((r["T2"] - r["T1"]) * 1000, 1) if r["T1"] and r["T2"] else ""
            d4 = round((r["T4"] - r["T1"]) * 1000, 1) if r["T1"] and r["T4"] else ""
            d5 = round((r["T5"] - r["T1"]) * 1000, 1) if r["T1"] and r["T5"] else ""
            w.writerow([r["log_id"], _iso(r["T1"]), _iso(r["T2"]), _iso(r["T4"]),
                        _iso(r["T5"]), d2, d4, d5])
    print(f"   table → {path}")


def _stats(deltas: list[float]) -> str:
    if not deltas:
        return "n=0"
    d = sorted(deltas)
    p95 = d[min(len(d) - 1, int(round(0.95 * (len(d) - 1))))]
    return (f"n={len(d)} mean={statistics.fmean(d):.0f} median={statistics.median(d):.0f} "
            f"p95={p95:.0f} max={d[-1]:.0f} (ms)")


def _summarise(name: str, rows: list[dict], total: int) -> None:
    def deltas(a, b):
        return [(r[b] - r[a]) * 1000 for r in rows if r[a] and r[b]]
    print(f"   coverage: T2 {sum(1 for r in rows if r['T2'])}/{total}, "
          f"T4 {sum(1 for r in rows if r['T4'])}/{total}, "
          f"T5 {sum(1 for r in rows if r['T5'])}/{total}")
    print(f"   T1→T2 (Wazuh detect): {_stats(deltas('T1','T2'))}")
    print(f"   T1→T4 (SOC ingest)  : {_stats(deltas('T1','T4'))}")
    print(f"   T1→T5 (end-to-end)  : {_stats(deltas('T1','T5'))}")


def main() -> None:
    ap = argparse.ArgumentParser(description="End-to-end latency load tests.")
    ap.add_argument("--test", choices=[*TESTS, "all"], default="baseline")
    ap.add_argument("--max-drain", type=int, default=45,
                    help="Max seconds to wait per test for T2/T4/T5 to arrive.")
    args = ap.parse_args()

    if not Path(TRACE_FILE).exists():
        print(f"[warn] trace file {TRACE_FILE} not found — is the backend running "
              f"with SOC_PERF_TRACE=1? T4/T5 will be empty.")

    tenants = load_tenants(DEFAULT_TENANTS_PATH)
    setup_tenants(WazuhClient(), tenants)
    agent = next(t for t in tenants if t.group == "companyB").agents[-1]

    names = list(TESTS) if args.test == "all" else [args.test]
    idx = 0
    for name in names:
        rate, duration = TESTS[name]
        idx = run_test(name, rate, duration, agent, idx, args.max_drain)

    print(f"\nReports in {REPORT_DIR}")


if __name__ == "__main__":
    main()
