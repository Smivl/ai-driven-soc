import argparse
import time
from dataclasses import asdict
from pathlib import Path
import sys

# Allow imports from sibling folders without requiring package installation.
_THIS_DIR = Path(__file__).resolve().parent
_SOC_DIR = _THIS_DIR.parent
sys.path.insert(0, str(_THIS_DIR))
sys.path.insert(0, str(_SOC_DIR / "log_evaluation"))

from explanation import generate_explanation
from normalizerfixed import normalize_wazuh_alert
from wazuh_client import WazuhClient
from severity_scoring import load_blacklist, train_model, score_event
from log_dataclass import SOCevent


def _to_soc_event(normalized: dict) -> SOCevent:
    raw = normalized.get("raw", {})
    raw_data = raw.get("data", {}) if isinstance(raw, dict) else {}

    port = raw_data.get("dstport") or raw_data.get("srcport") or 0
    level = normalized.get("level", 0)

    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 0

    try:
        level = int(level)
    except (TypeError, ValueError):
        level = 0

    return SOCevent(
        source_ip=normalized.get("source_ip") or "0.0.0.0",
        destination_ip=normalized.get("destination_ip") or "0.0.0.0",
        port=port,
        user=normalized.get("user"),
        event_type=normalized.get("event_type"),
        timestamp=normalized.get("timestamp"),
        raw_log=normalized.get("message"),
        wazuh_level=level,
        rule_id=(raw.get("rule", {}) or {}).get("id") if isinstance(raw, dict) else None,
    )


def run_pipeline_once(client: WazuhClient, model, blacklist: set, batch_size: int) -> list[dict]:
    alerts = client.get_recent_alerts(limit=batch_size)
    results = []

    for alert in alerts:
        normalized = normalize_wazuh_alert(alert)
        event = _to_soc_event(normalized)
        scored = score_event(model, blacklist, event)

        explanation_input = {
            "event_type": scored.event_type,
            "message": scored.raw_log,
            "user": scored.user,
            "source_ip": scored.source_ip,
        }
        explanation = generate_explanation(explanation_input, scored.severity)

        results.append(
            {
                "timestamp": scored.timestamp,
                "event_type": scored.event_type,
                "source_ip": scored.source_ip,
                "severity": scored.severity,
                "label": scored.label.value if scored.label else None,
                "explanation": explanation,
                "event": asdict(scored),
            }
        )

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run end-to-end SOC processing loop.")
    parser.add_argument("--poll-seconds", type=int, default=15, help="Delay between loop iterations")
    parser.add_argument("--batch-size", type=int, default=10, help="Number of alerts to fetch each iteration")
    parser.add_argument("--once", action="store_true", help="Run one iteration and exit")
    args = parser.parse_args()

    print("Initializing pipeline resources...")
    blacklist = load_blacklist()
    model = train_model(blacklist)
    client = WazuhClient()
    print("Pipeline ready.")

    iteration = 0
    try:
        while True:
            iteration += 1
            start = time.time()
            print(f"\nLoop {iteration}: fetching and processing up to {args.batch_size} alerts")

            results = run_pipeline_once(client, model, blacklist, args.batch_size)
            print(f"Processed {len(results)} alerts")

            for item in results[:3]:
                print(
                    f"  [{item['severity']:>3}] {item['event_type']} | "
                    f"{item['source_ip']} | {item['explanation'][:100]}"
                )

            elapsed = time.time() - start
            print(f"Loop {iteration} complete in {elapsed:.2f}s")

            if args.once:
                break

            sleep_time = max(0, args.poll_seconds - elapsed)
            if sleep_time:
                time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("\nStopping pipeline loop.")


if __name__ == "__main__":
    main()
