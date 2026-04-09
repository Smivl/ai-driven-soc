import csv
import json
from datetime import datetime, timezone


def normalize_event(raw_log, source="csv_dataset"):
    return {
        "timestamp": raw_log.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source_ip": raw_log.get("src_ip") or raw_log.get("source_ip"),
        "destination_ip": raw_log.get("dst_ip") or raw_log.get("destination_ip"),
        "event_type": raw_log.get("event_type", "unknown"),
        "user": raw_log.get("user"),
        "severity": 0,
        "message": raw_log.get("message", ""),
        "source": source,
        "context": raw_log
    }


def process_csv(input_file, output_file):

    normalized_events = []

    with open(input_file, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            event = normalize_event(row)
            normalized_events.append(event)

    with open(output_file, "w") as outfile:
        json.dump(normalized_events, outfile, indent=2)

    print(f"Normalized {len(normalized_events)} events")


if __name__ == "__main__":

    process_csv(
        input_file="data/SIEVE_00_100K.csv",
        output_file="data/normalized_events.json"
    )