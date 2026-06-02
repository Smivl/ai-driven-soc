from dataclasses import dataclass, asdict
from enum import Enum
import datetime
import ipaddress


""""
    This class represents data from the seperate logs pulled from Wazuh. 
    A log is normalised and put in this objects format.
"""


class PipelineStatus(Enum):
    PENDING    = "pending"
    NORMALIZED = "normalized"  # log has been normalized
    SCORED     = "scored"     # ML has scored it
    EXPLAINED  = "explained"  # LLM has explained it
    RESOLVED   = "resolved"   # SOAR has handled it

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

@dataclass
class SOCevent:
    """
        A class to store the normalized log with ML info
            - All data given by the log
            - Level given by Wazuh
            - Severity
            - LLM explaination 
    """
    # ── From the raw log ──────────────────────────────
    source_ip:      str   = None
    destination_ip: str   = None
    port:           int   = None
    user:           str   = None
    event_type:     str   = None
    timestamp:      datetime   = None
    raw_log:        str   = None

    # ── From Wazuh ────────────────────────────────────
    wazuh_level:    int     = None
    rule_id:        str     = None
    frequency:      int     = None
    timeframe:      int     = None
    mitre_id:       list    = None
    mitre_tactic:   list    = None
    mitre_technique:list    = None


    # ── From severity ML ───────────────────────────────
    severity:       int   = None   
    label:          str   = None   

    # ── From LLM ─────────────────────────────────────
    explanation:    str   = None

    # ── Pipeline tracking ─────────────────────────────
    event_id:        str             = None
    alert_id:        str             = None
    status:          PipelineStatus   = PipelineStatus.PENDING   # pending -> normalized -> scored -> explained

    # Obtain any of the information stored in the class from a log
    def return_value(self, field_name):
        return getattr(self, field_name, None)
    
    def return_dict(self):
        d = asdict(self)
        return {k: (v.value if isinstance(v, Enum) else v) for k, v in d.items()}
    
    def score_rules(self, blacklist: set[str], tor_exits: set[str]) -> None:
        """Score a individual SOCevent using signature rules and intelligence matrices."""
        self.severity = (
            wazuh_rule_score(self.wazuh_level or 0)
            + source_ip_score(self.source_ip or "", blacklist, tor_exits)
            + destination_ip_score(self.destination_ip or "")
            + port_score(self.port or 0)
            + keyword_score(self.raw_log)
        )
    
    
                         
