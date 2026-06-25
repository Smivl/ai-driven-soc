from dataclasses import dataclass, asdict
from enum import Enum

class Scoring(Enum):
    BENIGN     = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS  = "malicious"
    CRITICAL   = "critical"

class PipelineStatus(Enum):
    PENDING    = "pending"
    NORMALIZED = "normalized"  # log has been normalized
    SCORED     = "scored"     # ML has scored it
    EXPLAINED  = "explained"  # LLM has explained it
    RESOLVED   = "resolved"   # SOAR has handled it

@dataclass
class SOCevent:
    """
        A class to store the normalized log with ML info
            - All data given by the log
            - Level given by Wazuh
            - Severity
            - LLM explaination 
    """
    # ── Tenant (multi-tenant attribution) ─────────────
    agent_id:       str   = None   # Wazuh agent id, e.g. "001"
    agent_name:     str   = None   # Wazuh agent name, e.g. "companyA-web01"
    group:          str   = None   # Wazuh group = tenant/company

    # ── From the raw log ──────────────────────────────
    source_ip:      str   = None
    destination_ip: str   = None
    port:           int   = None
    user:           str   = None
    event_type:     str   = None
    timestamp:      str   = None
    first_seen:     str   = None   # earliest contributing log time (start of attack)
    last_seen:      str   = None   # most recent contributing log time
    raw_log:        str   = None

    # ── From Wazuh ────────────────────────────────────
    wazuh_level:    Scoring = None
    rule_id:        str     = None
    rule_description: str   = None
    frequency:      int     = None
    timeframe:      int     = None
    mitre_id:       list    = None
    mitre_tactic:   list    = None
    mitre_technique:list    = None
    trigger_logs:   list    = None   # raw logs that triggered this event

    # ── From ML ───────────────────────────────────────
    severity:       int   = None   # 0-100
    label:          str   = None   

    # ── From LLM ─────────────────────────────────────
    explanation:        str   = None
    recommended_action: str   = None

    # ── Pipeline tracking ─────────────────────────────
    event_id:        str             = None
    status:          PipelineStatus   = PipelineStatus.PENDING   # pending -> normalized -> scored -> explained

    # Obtain any of the information stored in the class from a log
    def return_value(self, field_name):
        return getattr(self, field_name, None)
    
    def return_dict(self):
        d = asdict(self)
        return {k: (v.value if isinstance(v, Enum) else v) for k, v in d.items()}
    
                         
