from dataclasses import dataclass, field, asdict
from datetime import datetime

from enum import Enum

class Severity(Enum):
    BENIGN     = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS  = "malicious"
    CRITICAL   = "critical"

class PipelineStatus(Enum):
    PENDING   = "pending"    # just ingested
    NORMALIZED = "normalized"  # log has been normalized
    SCORED    = "scored"     # ML has scored it
    EXPLAINED = "explained"  # LLM has explained it
    RESOLVED  = "resolved"   # SOAR has handled it

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
    timestamp:      str   = None
    raw_log:        str   = None

    # ── From Wazuh ────────────────────────────────────
    wazuh_level:    int   = None
    rule_id:        str   = None

    # ── From ML ───────────────────────────────────────
    severity:       int   = None   # 0-100
    label:          str   = None   # benign/suspicious/malicious/critical

    # ── From LLM ─────────────────────────────────────
    explanation:    str   = None

    # ── Pipeline tracking ─────────────────────────────
    status:         str   = "pending"   # pending → scored → explained

    # Obtain any of the information stored in the class from a log
    def return_value(self, field_name):
        return getattr(self, field_name, None)
    
    def return_dict(self):
        return asdict(self)
