import csv
import json
import os
import re
import sys
from datetime import datetime, timezone

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.log_evaluation.socevent import SOCevent, PipelineStatus



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

def extract_trigger_logs(alert: dict) -> list[str]:
    """Return the raw logs that triggered an alert.

    Wazuh embeds the causal logs in-band: ``full_log`` is the line that tripped
    the rule, and ``previous_output`` holds the earlier contributing lines for a
    correlation/frequency rule (newline-delimited string, occasionally a list).
    Returns them de-duplicated, triggering line first.
    """
    logs: list[str] = []

    full_log = alert.get("full_log")
    if full_log:
        logs.append(full_log)

    prev = alert.get("previous_output")
    if isinstance(prev, str):
        logs.extend(prev.split("\n"))
    elif isinstance(prev, list):
        logs.extend(prev)

    # Strip blanks and de-dupe while preserving order.
    seen: set[str] = set()
    result: list[str] = []
    for line in logs:
        line = (line or "").strip()
        if line and line not in seen:
            seen.add(line)
            result.append(line)
    return result


def _trigger_time_range(trigger_logs: list[str], fallback: str) -> tuple[str, str]:
    """Return (first_seen, last_seen) ISO timestamps across the triggering logs.

    Parses each log's own timestamp with _parse_timestamp; falls back to the
    alert timestamp when there are no parseable trigger logs. ISO strings sort
    chronologically, so min/max give the range directly.
    """
    times = [_parse_timestamp(log) for log in trigger_logs if log]
    if not times:
        return fallback, fallback
    return min(times), max(times)


def normalize_wazuh_alert(alert: dict, group_resolver=None) -> SOCevent:
    """Normalize a raw Wazuh alert into a SOCEvent dataclass.

    If ``group_resolver`` is given (a callable ``agent_id -> group``), the
    event's tenant/group is resolved from the agent id.
    """
    rule     = alert.get("rule", {})
    data     = alert.get("data", {})
    full_log = alert.get("full_log", "")
    agent    = alert.get("agent", {})

    # Try to get source IP from data first, fall back to parsing the raw log
    src_ip = data.get("srcip")
    if not src_ip and full_log:
        parsed_src, _ = _parse_ips(full_log)
        src_ip = parsed_src

    # Try to get destination IP from agent info
    _, dst_ip = _parse_ips(full_log) if full_log else (None, None)

    agent_id = agent.get("id")
    group = group_resolver(agent_id) if (group_resolver and agent_id) else None

    timestamp = alert.get("timestamp") or datetime.now(timezone.utc).isoformat()
    triggers = extract_trigger_logs(alert)
    first_seen, last_seen = _trigger_time_range(triggers, timestamp)

    return SOCevent(
        # Tenant attribution
        agent_id       = agent_id,
        agent_name     = agent.get("name"),
        group          = group,

        # From the raw log
        source_ip      = src_ip,
        destination_ip = dst_ip or alert.get("agent", {}).get("ip"),
        port           = int(data.get("dstport", 0)) or None,
        user           = _parse_user(full_log) if full_log else None,
        event_type     = rule.get("groups", ["unknown"])[0],
        timestamp      = timestamp,
        first_seen     = first_seen,
        last_seen      = last_seen,
        raw_log        = full_log or rule.get("description", ""),

        # From Wazuh
        wazuh_level     = rule.get("level"),
        rule_id         = rule.get("id"),
        rule_description= rule.get("description"),
        frequency       = int(rule["frequency"]) if rule.get("frequency") is not None else None,
        timeframe       = rule.get("timeframe"),
        mitre_id        = rule.get("mitre", {}).get("id"),
        mitre_tactic    = rule.get("mitre", {}).get("tactic"),
        mitre_technique = rule.get("mitre", {}).get("technique"),
        trigger_logs    = triggers,

        # Pipeline status
        status         = PipelineStatus.NORMALIZED
    )


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

