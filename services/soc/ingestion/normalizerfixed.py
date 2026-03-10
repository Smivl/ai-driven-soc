import csv
import json
import re
from datetime import datetime, timezone



_IP_RE   = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

# Matches the most common syslog-style timestamps in the dataset
_TS_PATTERNS = [
    # 2018-06-27T23:47:31
    (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'), '%Y-%m-%dT%H:%M:%S'),
    # date=1981-08-26 time=03:09:47
    (re.compile(r'date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2})'), None),
    # Jan 02 21:10:59  /  Mar 04 03:12:48
    (re.compile(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'), '%b %d %H:%M:%S'),
    # [Thu Dec 17 02:47:06 1992]
    (re.compile(r'\[(?:\w{3}\s+)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\]'), '%b %d %H:%M:%S %Y'),
    # [Time 1998.05.04 10:45:30 +05]
    (re.compile(r'\[Time\s+(\d{4}\.\d{2}\.\d{2}\s+\d{2}:\d{2}:\d{2})'), '%Y.%m.%d %H:%M:%S'),
    # 19:32:06  (time only — treat as today)
    (re.compile(r'^(\d{2}:\d{2}:\d{2})\s'), '%H:%M:%S'),
    # TRACE ... 2024-12-08 07:35:01
    (re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'), '%Y-%m-%d %H:%M:%S'),
    # At 20:53:08 23/11/1982
    (re.compile(r'At\s+(\d{2}:\d{2}:\d{2})\s+(\d{2}/\d{2}/\d{4})'), None),
    # [12/Aug/1978:23:24:34 ]
    (re.compile(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'), '%d/%b/%Y:%H:%M:%S'),
]

# User extraction patterns, tried in order
_USER_PATTERNS = [
    re.compile(r'account=(\S+)'),                          # account=kristenmcgrath
    re.compile(r'for user (\S+)'),                         # session closed for user X
    re.compile(r'session (?:opened|closed) for user (\S+)'),
    re.compile(r'for (\w+)\s+from\s+\d'),                  # Accepted password for X from IP
    re.compile(r'\] user (\w+):'),                         # [client IP] user X:
    re.compile(r'user (\w+)'),                             # generic fallback
    re.compile(r'\(([^)]+@[^)]+)\)'),                      # (user@host)
    re.compile(r'by \(uid=\d+\).*?user (\S+)'),
]


def _parse_timestamp(log: str) -> str:
    """Extract and normalise a timestamp from the raw log string."""
    for pattern, fmt in _TS_PATTERNS:
        m = pattern.search(log)
        if not m:
            continue
        try:
            if fmt is None:
                # Special multi-group cases
                if pattern.pattern.startswith('date='):
                    dt = datetime.strptime(f"{m.group(1)} {m.group(2)}", '%Y-%m-%d %H:%M:%S')
                elif 'At' in pattern.pattern:
                    dt = datetime.strptime(f"{m.group(2)} {m.group(1)}", '%d/%m/%Y %H:%M:%S')
                else:
                    continue
            else:
                raw = m.group(1)
                dt = datetime.strptime(raw, fmt)
                # Syslog lines without a year default to the current year
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue

    return datetime.now(timezone.utc).isoformat()


def _parse_ips(log: str) -> tuple[str | None, str | None]:
    """Return (source_ip, destination_ip) extracted from the log string."""
    ips = _IP_RE.findall(log)
    src = ips[0] if len(ips) > 0 else None
    dst = ips[1] if len(ips) > 1 else None
    return src, dst


def _parse_user(log: str) -> str | None:
    for pattern in _USER_PATTERNS:
        m = pattern.search(log)
        if m:
            return m.group(1)
    return None


def normalize_event(row: dict, source: str = "csv_dataset") -> dict:
   
    raw_log = row.get("log", "")
    category = row.get("category", "unknown")

    src_ip, dst_ip = _parse_ips(raw_log)

    return {
        "timestamp":       _parse_timestamp(raw_log),
        "event_type":      category,
        "source_ip":       src_ip,
        "destination_ip":  dst_ip,
        "user":            _parse_user(raw_log),
        "severity":        0,           # filled in later by severity_scoring
        "message":         raw_log,
        "source":          source,
        "raw":             row,         # original CSV row preserved
    }


def process_csv(input_file: str, output_file: str) -> int:
    """Normalize the full CSV and write a JSON file. Returns the event count."""
    normalized_events = []

    with open(input_file, newline='', encoding="utf-8") as csvfile:
        for row in csv.DictReader(csvfile):
            normalized_events.append(normalize_event(row))

    with open(output_file, "w", encoding="utf-8") as outfile:
        json.dump(normalized_events, outfile, indent=2)

    print(f"Normalized {len(normalized_events)} events → {output_file}")
    return len(normalized_events)


if __name__ == "__main__":
    process_csv(
        input_file="data/SIEVE_00_100K.csv",
        output_file="data/normalized_events.json",
    )
