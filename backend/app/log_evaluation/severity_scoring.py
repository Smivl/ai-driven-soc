"""
    Rule-based scoring for individual security events
    Uses: Wazuh level, source/destination IP, port, and keyword matching
"""

import ipaddress
import requests
 
from app.log_evaluation.socevent import SOCevent
 
###### source .venv/bin/activate
##### python -m backend.log_evaluation.rule_scoring
 
# ---- Threat intelligence loading -----------------------------------------------------------------------
 
def load_blacklist(timeout: int = 10) -> set:
    """Download a real IP blacklist from FireHOL."""
    url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
    except requests.RequestException as exc:
        print(f"[load_blacklist] failed to download blacklist: {exc}")
        return set()
 
    ips = set()
    for line in r.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.add(line)
    return ips
 
 
def load_tor_exits(timeout: int = 10) -> set:
    """Download up-to-date Tor exit node list (updated hourly)."""
    url = "https://raw.githubusercontent.com/alireza-rezaee/tor-nodes/main/latest.exits.csv"
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
    except requests.RequestException as exc:
        print(f"[load_tor_exits] failed to download Tor exit list: {exc}")
        return set()
 
    exits = set()
    for line in r.text.splitlines():
        if line and not line.lower().startswith("fingerprint"):
            parts = line.split(",")
            if len(parts) >= 2:
                ip = parts[1].strip()
                if ip and ":" not in ip:  # skip IPv6 / empty fields
                    exits.add(ip)
    print(f"Loaded {len(exits)} known Tor exit nodes")
    return exits
 
 
# ---- Helpers -----------------------------------------------------------------------------
 
def _is_private_ip(ip: str) -> bool:
    """True if `ip` parses as a private address; False if it doesn't
    parse at all or isn't private."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
 
 
# Networks/hosts considered "core" infrastructure — adjust to your environment.
_CORE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/24"),
    ipaddress.ip_network("192.168.1.1/32"),  # e.g. gateway / domain controller
)
 
 
def _is_core_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CORE_NETWORKS)
 
 
# ---- Individual rule scores (each function is internally bounded) -----------------------------------------------------------------------
 
def wazuh_rule_score(level: int) -> int:
    """Max 25 points."""
    if level >= 12: return 25
    if level >= 8:  return 18
    if level >= 4:  return 8
    return 0
 
def source_ip_score(ip: str, blacklist: set, tor_exits: set) -> int:
    """Max 25 points (18 blacklist + 5 tor + 2 external)."""
    if not ip:
        return 0
    is_private = _is_private_ip(ip)
    return (
        int(ip in blacklist) * 18 +  # known malicious — hard boost
        int(ip in tor_exits) * 5  +  # anonymization
        int(not is_private)  * 2     # external IP
    )
 
def destination_ip_score(ip: str) -> int:
    """Max 10 points (3 private + 7 core). Core implies private"""
    if not ip:
        return 0
    is_private = _is_private_ip(ip)
    is_core    = _is_core_ip(ip)
    return int(is_private) * 3 + int(is_core) * 7
 
def port_score(port: int) -> int:
    """Max 10 points."""
    sensitive_ports = {22, 23, 3306, 5432, 6379, 27017}  # SSH, Telnet, DBs
    common_ports    = {80, 443, 8080}
    try:
        port = int(port)
    except (TypeError, ValueError):
        return 0
    if port in sensitive_ports: return 10
    if port in common_ports:    return 3
    return 0
 
def keyword_score(raw_log: str) -> int:
    """Boost score for known-bad keywords in the raw log text. Max 30 points."""
    log = raw_log.lower() if raw_log else ""
    score = 0
    if any(kw in log for kw in ["malware", "trojan", "ransomware", "virus", "rootkit", "backdoor"]):
        score += 15
    if any(kw in log for kw in ["failed password", "authentication failure", "invalid user"]):
        score += 5
    if any(kw in log for kw in ["privilege escalation", "sudo su", "sudo -i", "su root"]):
        score += 7
    if any(kw in log for kw in ["deleted", "removed", "dropped"]):
        score += 3
    return score
 
# ---- Define a score based on the rules 0-100 -----------------------------------------------------------------------
 
def score_rules(event: SOCevent, blacklist: set, tor_exits: set) -> int:
    """Score a SOCevent using rules only — returns an int in [0, 100]."""
 
    raw_score = (
        wazuh_rule_score(event.wazuh_level or 0)
        + source_ip_score(event.source_ip or "", blacklist, tor_exits)
        + destination_ip_score(event.destination_ip or "")
        + port_score(event.port or 0)
        + keyword_score(event.raw_log)
    )
 
    # Sub-score maxes already sum to 100
    return max(0, min(100, raw_score))
