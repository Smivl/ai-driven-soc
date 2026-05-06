"""
    Rule-based scoring for individual security events
    Uses: Wazuh level, source/destination IP, port, and keyword matching
"""

import ipaddress
import requests

from backend.log_evaluation.soc_event import SOCevent

###### source .venv/bin/activate
##### python -m backend.log_evaluation.rule_scoring

# ---- Threat intelligence loading -----------------------------------------------------------------------

def load_blacklist() -> set:
    """Download a real IP blacklist from FireHOL"""
    url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    r   = requests.get(url)
    ips = set()
    for line in r.text.splitlines():
        if line and not line.startswith("#"):
            ips.add(line.strip())
    return ips

def load_tor_exits() -> set:
    """Download up-to-date Tor exit node list (updated hourly)."""
    url = "https://raw.githubusercontent.com/alireza-rezaee/tor-nodes/main/latest.exits.csv"
    r   = requests.get(url)
    r.raise_for_status()
    exits = set()
    for line in r.text.splitlines():
        if line and not line.startswith("fingerprint"):
            parts = line.split(",")
            if len(parts) >= 2:
                ip = parts[1].strip()
                if ":" not in ip:
                    exits.add(ip)
    print(f"Loaded {len(exits)} known Tor exit nodes")
    return exits

# ---- Individual rule scores -----------------------------------------------------------------------

def wazuh_rule_score(level: int) -> int:
    if level >= 12: return 30
    if level >= 8:  return 20
    if level >= 4:  return 10
    return 0

def source_ip_score(ip: str, blacklist: set, tor_exits: set) -> int:
    try:
        is_private = ipaddress.ip_address(ip).is_private
    except ValueError:
        is_private = False
    return (
        int(ip in blacklist)    * 40 +  # known malicious — hard boost
        int(ip in tor_exits)    * 15 +  # anonymization
        int(not is_private)     * 5     # external IP
    )

def destination_ip_score(ip: str) -> int:
    try:
        is_private = ipaddress.ip_address(ip).is_private
    except ValueError:
        is_private = False
    is_core = ip.startswith("10.0.0.") or ip.startswith("192.168.1.1")
    return int(is_private) * 3 + int(is_core) * 5

def port_score(port: int) -> int:
    sensitive_ports = {22, 23, 3306, 5432, 6379, 27017}  # SSH, Telnet, DBs
    common_ports    = {80, 443, 8080}
    if port in sensitive_ports: return 10
    if port in common_ports:    return 3
    return 0

def keyword_score(raw_log: str) -> int:
    """Boost score for known-bad keywords in the raw log text."""
    log = raw_log.lower() if raw_log else ""
    score = 0
    if any(kw in log for kw in ["malware", "trojan", "ransomware", "virus", "rootkit", "backdoor"]):
        score += 50
    if any(kw in log for kw in ["failed password", "authentication failure", "invalid user"]):
        score += 15
    if any(kw in log for kw in ["privilege escalation", "sudo", "root"]):
        score += 20
    if any(kw in log for kw in ["deleted", "removed", "dropped"]):
        score += 10
    return score

# ---- Define a score based on the rules 0-100 -----------------------------------------------------------------------

def score_rules(event: SOCevent, blacklist: set, tor_exits: set):
    """Score a SOCevent using rules only — updates severity, label and status."""

    raw_score = (
        wazuh_rule_score(event.wazuh_level or 0)
        + source_ip_score(event.source_ip or "", blacklist, tor_exits)
        + destination_ip_score(event.destination_ip or "")
        + port_score(event.port or 0)
        + keyword_score(event.raw_log)
    )
    return raw_score