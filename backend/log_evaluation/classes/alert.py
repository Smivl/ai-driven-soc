from dataclasses import dataclass
import requests
import ipaddress

from backend.log_evaluation.classes.soc_event import SOCevent

import datetime

""""
    This class represents a correlated object that is shown in the UI.
    An Alert exists of multiple SOCevents.

    The Alert class is responsible for:
        - Storing correlated events and shared attributes
        - Calculating overall threat score based on the events and external intelligence
"""

from dataclasses import dataclass, field
from datetime import datetime
import uuid

 # We define 200 raw points as a catastrophic
MAX_RAW_RATING = 200

# ── Threat lists  ──────────────────────────────────────────────────────────

def load_blacklist() -> set[str]:
    """Download a real IP blacklist from FireHOL."""
    url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        ips = set()
        for line in r.text.splitlines():
            if line and not line.startswith("#"):
                ips.add(line.strip())
        return ips
    except Exception as e:
        print(f"Error loading FireHOL blacklist: {e}")
        return set()

def load_tor_exits() -> set[str]:
    """Download up-to-date Tor exit node list (updated hourly)."""
    url = "https://raw.githubusercontent.com/alireza-rezaee/tor-nodes/main/latest.exits.csv"
    try:
        r = requests.get(url, timeout=10)
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
    except Exception as e:
        print(f"Error loading Tor exit nodes: {e}")
        return set()


# ── Individual scoring ──────────────────────────────────────────────────────────

def wazuh_rule_score(level: int) -> int:
    if level >= 12: return 30
    if level >= 8:  return 20
    if level >= 4:  return 10
    return 0

def source_ip_score(ip: str, blacklist: set[str], tor_exits: set[str]) -> int:
    if not ip:
        return 0
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
    if not ip:
        return 0
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

def score_rules(event: SOCevent, blacklist: set[str], tor_exits: set[str]) -> int:
    """Score a individual SOCevent using signature rules and intelligence matrices."""
    return (
        wazuh_rule_score(event.wazuh_level or 0)
        + source_ip_score(event.source_ip or "", blacklist, tor_exits)
        + destination_ip_score(event.destination_ip or "")
        + port_score(event.port or 0)
        + keyword_score(event.raw_log)
    )

# ── Alert ──────────────────────────────────────────────────────────
@dataclass
class Alert:
    alert_id: str

    first_seen: datetime
    last_seen: datetime

    mitre_id: set[str] = field(default_factory=set)
    mitre_tactic: set[str] = field(default_factory=set)
    mitre_technique: set[str] = field(default_factory=set)

    source_ips: set[str] = field(default_factory=set)
    destination_ips: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    events: list[SOCevent] = field(default_factory=list)

    event_count: int = 0

    status: str = "active"

    @classmethod
    def new_alert(cls, event: SOCevent):
        now = event.timestamp if event.timestamp else datetime.now()

        return cls(
            alert_id=str(uuid.uuid4()),

            first_seen=now,
            last_seen=now,

            mitre_id=set(event.mitre_id or []),
            mitre_tactic=set(event.mitre_tactic or []),
            mitre_technique=set(event.mitre_technique or []),

            users={event.user} if event.user else set(),
            source_ips={event.source_ip} if event.source_ip else set(),

            destination_ips={event.destination_ip} if event.destination_ip else set(),

            events=[event],
            event_count=1,
        )
    
    def add_event(self, event: SOCevent):
        self.events.append(event)
        self.event_count += 1

        if event.timestamp < self.first_seen:
            self.first_seen = event.timestamp

        if event.timestamp > self.last_seen:
            self.last_seen = event.timestamp

        if event.source_ip:
            self.source_ips.add(event.source_ip)

        if event.destination_ip:
            self.destination_ips.add(event.destination_ip)

        if event.user:
            self.users.add(event.user)

        self.mitre_id.update(event.mitre_id or [])
        self.mitre_tactic.update(event.mitre_tactic or [])
        self.mitre_technique.update(event.mitre_technique or [])
    
    def score(self, blacklist: set[str], tor_exits: set[str]) -> int:
        """
        Calculates the normalized threat score from 0 to 100 for the UI.
        """
        raw_score = 0

        # Macro Behavioral Context (MITRE Techniques)
        if self.mitre_id:
            raw_score += 20 * len(self.mitre_id)
        
        # Base Alert Lifecycle Threats
        if self.source_ips.intersection(blacklist):
            raw_score += 30
        if self.destination_ips.intersection(blacklist):
            raw_score += 30
        if self.source_ips.intersection(tor_exits):
            raw_score += 25
        
        # Detection of weird hours (12 AM to 4 AM)
        if self.first_seen and 0 <= self.first_seen.hour < 4:
            raw_score += 15

        # Micro Evidence (Max child signature score)
        if self.events:
            max_child_score = max(score_rules(e, blacklist, tor_exits) for e in self.events)
            raw_score += max_child_score

        # TRANSFORM TO 0-100 SCALE
        
        normalized_score = int((raw_score / MAX_RAW_RATING) * 100)
        
        return min(100, max(0, normalized_score))