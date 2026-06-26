"""
Performance evaluation harness for the AI-Driven SOC pipeline.

    python -m benchmarks.perf_eval

Measures, for presentation:
  * Startup costs        — blacklist load, ML model training
  * Per-component speed   — normalizer, ML scoring, DB archive write/query,
                            LLM explanation (Ollama), AI tenant assessment (Ollama)
  * SIEM latency          — Wazuh detect + index time for an injected event
  * Resource usage        — CPU / memory of the Wazuh + Postgres containers and Ollama
  * Bottleneck + throughput — derived from the per-component timings

Writes a JSON + Markdown report to benchmarks/reports/. Each section degrades
gracefully (skips with a note) if its dependency is unavailable.
"""

import json
import platform
import statistics
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPORT_DIR = Path(__file__).parent / "reports"
CONTAINERS = [
    "single-node-wazuh.manager-1",
    "single-node-wazuh.indexer-1",
    "soc-postgres",
]


# ── timing helpers ─────────────────────────────────────────────────────────────
def stats_ms(samples: list[float]) -> dict:
    """Summarise a list of durations (seconds) as millisecond statistics."""
    if not samples:
        return {}
    ms = sorted(s * 1000 for s in samples)
    p95 = ms[min(len(ms) - 1, int(round(0.95 * (len(ms) - 1))))]
    return {
        "n": len(ms),
        "min_ms": round(ms[0], 3),
        "mean_ms": round(statistics.fmean(ms), 3),
        "median_ms": round(statistics.median(ms), 3),
        "p95_ms": round(p95, 3),
        "max_ms": round(ms[-1], 3),
    }


def bench(fn, iters: int) -> dict:
    samples = []
    for _ in range(iters):
        t = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t)
    return stats_ms(samples)


def _timed(fn):
    t = time.perf_counter()
    out = fn()
    return out, time.perf_counter() - t


# ── sections ───────────────────────────────────────────────────────────────────
def section_startup(report: dict):
    from log_evaluation.severity_scoring import load_blacklist, train_model

    print("• Startup costs (blacklist load, model training)...")
    try:
        blacklist, t_bl = _timed(load_blacklist)
    except Exception as e:
        print(f"    blacklist load failed: {e}")
        blacklist, t_bl = set(), 0.0
    model, t_tr = _timed(lambda: train_model(blacklist))
    report["startup"] = {
        "blacklist_load_s": round(t_bl, 3),
        "blacklist_size": len(blacklist),
        "model_train_s": round(t_tr, 3),
    }
    print(f"    blacklist: {t_bl:.2f}s ({len(blacklist)} entries) | model train: {t_tr:.2f}s")
    return model, blacklist


def _sample_events(limit: int):
    """Pull recent Wazuh alerts and normalise them into SOCevents for benchmarks."""
    from ingestion.normalizerfixed import normalize_wazuh_alert
    from ingestion.wazuh_client import WazuhClient

    try:
        raw = WazuhClient().get_recent_alerts(limit=limit)
    except Exception as e:
        print(f"    could not pull sample alerts: {e}")
        return [], []
    events = []
    for a in raw:
        try:
            events.append(normalize_wazuh_alert(a, group_resolver=lambda _i: "companyB"))
        except Exception:
            continue
    return raw, events


def section_components(report: dict, model, blacklist):
    from ingestion.normalizerfixed import normalize_wazuh_alert
    from log_evaluation.severity_scoring import score_event

    print("• Component micro-benchmarks...")
    raw, events = _sample_events(100)
    if not raw:
        report["components"] = {"error": "no sample alerts available (is Wazuh reachable?)"}
        return events
    print(f"    using {len(raw)} sample alerts")

    # Normalizer
    report.setdefault("components", {})
    report["components"]["normalizer"] = bench(
        lambda: [normalize_wazuh_alert(a, group_resolver=lambda _i: "companyB") for a in raw],
        iters=20,
    )
    # divide by batch size to get per-event numbers
    norm = report["components"]["normalizer"]
    if norm:
        per = {k: (round(v / len(raw), 4) if k.endswith("_ms") else v) for k, v in norm.items()}
        report["components"]["normalizer_per_event"] = per

    # ML scoring (per event)
    if events:
        i = {"v": 0}
        def score_one():
            ev = events[i["v"] % len(events)]
            i["v"] += 1
            score_event(model, blacklist, ev)
        report["components"]["ml_scoring"] = bench(score_one, iters=min(300, len(events) * 5))

    return events


def section_db(report: dict):
    print("• Database (archive write + query)...")
    try:
        from sqlalchemy import delete
        from app.db import init_db, session_scope
        from app.models.event import ArchivedEvent
        from app.services import events_archive
    except Exception as e:
        report["database"] = {"error": str(e)}
        print(f"    skipped: {e}")
        return

    try:
        init_db()
        prefix = f"perfbench-{uuid.uuid4().hex[:8]}"
        i = {"v": 0}
        def write_one():
            n = i["v"]; i["v"] += 1
            events_archive.archive_event({
                "event_id": f"{prefix}-{n}", "group": "companyB", "agent_name": "bench",
                "source_ip": "203.0.113.9", "wazuh_level": 10, "severity": 55,
                "label": "malicious", "status": "explained",
                "rule_description": "perf benchmark event",
            })
        report["database"] = {"archive_write": bench(write_one, iters=100)}

        with session_scope() as s:
            report["database"]["query_recent_100"] = bench(
                lambda: events_archive.list_archived(s, limit=100), iters=30
            )
        # cleanup
        with session_scope() as s:
            s.execute(delete(ArchivedEvent).where(ArchivedEvent.event_id.like(f"{prefix}-%")))
        w = report["database"]["archive_write"]
        print(f"    archive write: {w.get('mean_ms')} ms/event (mean)")
    except Exception as e:
        report["database"] = {"error": str(e)}
        print(f"    skipped: {e}")


def section_llm(report: dict, events):
    print("• LLM stages (Ollama) — this is the slow part, few iterations...")
    from ingestion.explanation import generate_analysis
    from ingestion.tenant_agent import assess_window

    # Explanation: a handful of single-event analyses
    expl_samples = []
    for ev in events[:3]:
        d = ev.return_dict()
        d["message"] = d.get("raw_log")
        _, dt = _timed(lambda: generate_analysis(d, d.get("severity") or 0))
        expl_samples.append(dt)
    report.setdefault("llm", {})["explanation_per_event"] = stats_ms(expl_samples)
    if expl_samples:
        print(f"    explanation: {statistics.fmean(expl_samples):.2f}s/event (n={len(expl_samples)})")

    # Tenant assessment: a few window assessments
    if events:
        window = [e.return_dict() for e in events[:20]]
        assess_samples = []
        for _ in range(3):
            _, dt = _timed(lambda: assess_window("companyB", window))
            assess_samples.append(dt)
        report["llm"]["assessment_per_window"] = stats_ms(assess_samples)
        print(f"    assessment: {statistics.fmean(assess_samples):.2f}s/window (n={len(assess_samples)}, "
              f"window={len(window)})")


def section_siem_latency(report: dict):
    print("• SIEM detect + index latency (inject one event, poll until indexed)...")
    try:
        from ingestion.wazuh_client import WazuhClient
        from ingestion.wazuh_injector import inject_batch, wrap
    except Exception as e:
        report["siem_latency"] = {"error": str(e)}
        return
    try:
        client = WazuhClient()
        marker = f"198.18.{int(time.time()) % 250}.{uuid.uuid4().int % 250}"
        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        line = wrap("004", "companyB-app01",
                    f"{ts} companyB-app01 datavault[2211]: action=download user=bench "
                    f"src={marker} object=/vault/honeytoken/aws_keys.csv status=ok",
                    location="/var/log/datavault/access.log")
        t0 = time.perf_counter()
        inject_batch([line], CONTAINERS[0])
        found, waited = False, 0.0
        while waited < 25:
            time.sleep(0.5); waited = time.perf_counter() - t0
            hits = client.get_significant_alerts(min_level=7, group="companyB", limit=20)
            if any(h.get("data", {}).get("srcip") == marker for h in hits):
                found = True
                break
        report["siem_latency"] = {"detect_index_s": round(waited, 2) if found else None,
                                  "found": found}
        print(f"    detect+index: {'%.2fs' % waited if found else 'not seen within 25s'}")
    except Exception as e:
        report["siem_latency"] = {"error": str(e)}
        print(f"    skipped: {e}")


def section_resources(report: dict):
    print("• Resource usage (docker stats + Ollama process)...")
    res = {"containers": [], "ollama": None}
    try:
        out = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}"],
            capture_output=True, text=True, timeout=30,
        ).stdout
        for ln in out.strip().splitlines():
            parts = ln.split("|")
            if len(parts) == 4 and any(c in parts[0] for c in ("wazuh", "soc-postgres")):
                res["containers"].append({
                    "name": parts[0], "cpu": parts[1], "mem": parts[2], "mem_pct": parts[3],
                })
    except Exception as e:
        res["containers_error"] = str(e)
    # Ollama (host process)
    try:
        ps = subprocess.run(["ps", "-axo", "pcpu,pmem,rss,comm"], capture_output=True, text=True).stdout
        cpu = mem = rss = 0.0
        for ln in ps.splitlines():
            if "ollama" in ln.lower():
                f = ln.split(None, 3)
                cpu += float(f[0]); mem += float(f[1]); rss += float(f[2])
        if rss:
            res["ollama"] = {"cpu_pct": round(cpu, 1), "mem_pct": round(mem, 1),
                             "rss_mb": round(rss / 1024, 1)}
    except Exception as e:
        res["ollama_error"] = str(e)
    report["resources"] = res
    for c in res["containers"]:
        print(f"    {c['name']:<32} CPU {c['cpu']:>7}  MEM {c['mem']}")
    if res["ollama"]:
        print(f"    {'ollama (host)':<32} CPU {res['ollama']['cpu_pct']}%   RSS {res['ollama']['rss_mb']} MB")


def section_analysis(report: dict):
    """Derive the bottleneck + throughput estimate from component timings."""
    comp = report.get("components", {})
    llm = report.get("llm", {})
    stages = {}
    if comp.get("normalizer_per_event"):
        stages["normalize"] = comp["normalizer_per_event"]["mean_ms"]
    if comp.get("ml_scoring"):
        stages["ml_score"] = comp["ml_scoring"]["mean_ms"]
    if llm.get("explanation_per_event"):
        stages["llm_explain"] = llm["explanation_per_event"]["mean_ms"]

    analysis = {"stage_mean_ms": stages}
    if stages:
        bottleneck = max(stages, key=stages.get)
        analysis["bottleneck"] = bottleneck
        # Single-worker throughput is gated by the slowest stage.
        slowest_ms = stages[bottleneck]
        analysis["throughput_events_per_min_single_worker"] = round(60000 / slowest_ms, 1) if slowest_ms else None
        fast = sum(v for k, v in stages.items() if k != "llm_explain")
        analysis["non_llm_pipeline_ms_per_event"] = round(fast, 3)
    report["analysis"] = analysis
    if stages:
        print(f"\n  Bottleneck: {analysis['bottleneck']} "
              f"(~{analysis['throughput_events_per_min_single_worker']} events/min single-worker)")


# ── report output ──────────────────────────────────────────────────────────────
def write_report(report: dict) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    (REPORT_DIR / f"perf_{ts}.json").write_text(json.dumps(report, indent=2))
    md = _markdown(report)
    md_path = REPORT_DIR / f"perf_{ts}.md"
    md_path.write_text(md)
    return md_path


def _row(d: dict) -> str:
    return (f"{d.get('mean_ms','-')} | {d.get('median_ms','-')} | "
            f"{d.get('p95_ms','-')} | {d.get('max_ms','-')} | {d.get('n','-')}")


def _markdown(r: dict) -> str:
    L = [f"# SOC pipeline performance report", "",
         f"- Generated: {r['meta']['generated']}",
         f"- Host: {r['meta']['platform']}", ""]
    s = r.get("startup", {})
    if s:
        L += ["## Startup", "",
              f"- Blacklist load: **{s.get('blacklist_load_s')}s** ({s.get('blacklist_size')} IPs)",
              f"- ML model training: **{s.get('model_train_s')}s**", ""]
    L += ["## Component latency (ms)", "",
          "| Stage | mean | median | p95 | max | n |", "|---|---|---|---|---|---|"]
    comp = r.get("components", {})
    if comp.get("normalizer_per_event"):
        L.append(f"| Normalizer (per event) | {_row(comp['normalizer_per_event'])} |")
    if comp.get("ml_scoring"):
        L.append(f"| ML scoring (per event) | {_row(comp['ml_scoring'])} |")
    db = r.get("database", {})
    if db.get("archive_write"):
        L.append(f"| DB archive write | {_row(db['archive_write'])} |")
    if db.get("query_recent_100"):
        L.append(f"| DB query (100 rows) | {_row(db['query_recent_100'])} |")
    llm = r.get("llm", {})
    if llm.get("explanation_per_event"):
        L.append(f"| LLM explanation (per event) | {_row(llm['explanation_per_event'])} |")
    if llm.get("assessment_per_window"):
        L.append(f"| AI assessment (per window) | {_row(llm['assessment_per_window'])} |")
    L.append("")
    sl = r.get("siem_latency", {})
    if sl.get("detect_index_s") is not None:
        L += [f"## SIEM latency", "", f"- Wazuh detect + index: **{sl['detect_index_s']}s**", ""]
    a = r.get("analysis", {})
    if a.get("bottleneck"):
        L += ["## Bottleneck & throughput", "",
              f"- **Bottleneck stage:** {a['bottleneck']}",
              f"- Single-worker throughput (gated by bottleneck): **{a.get('throughput_events_per_min_single_worker')} events/min**",
              f"- Non-LLM pipeline cost: {a.get('non_llm_pipeline_ms_per_event')} ms/event", ""]
    res = r.get("resources", {})
    if res.get("containers"):
        L += ["## Resource usage", "", "| Component | CPU | Memory |", "|---|---|---|"]
        for c in res["containers"]:
            L.append(f"| {c['name']} | {c['cpu']} | {c['mem']} |")
        if res.get("ollama"):
            o = res["ollama"]
            L.append(f"| ollama (host) | {o['cpu_pct']}% | {o['rss_mb']} MB |")
        L.append("")
    return "\n".join(L)


def main() -> None:
    print("=" * 64)
    print("  AI-Driven SOC — performance evaluation")
    print("=" * 64)
    report = {"meta": {
        "generated": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }}

    model, blacklist = section_startup(report)
    events = section_components(report, model, blacklist)
    section_db(report)
    section_siem_latency(report)
    section_llm(report, events)
    section_resources(report)
    section_analysis(report)

    path = write_report(report)
    print("=" * 64)
    print(f"  Report written to: {path}")
    print(f"                     {path.with_suffix('.json')}")
    print("=" * 64)


if __name__ == "__main__":
    main()
