from dataclasses import dataclass, asdict
from enum import Enum

from log_evaluation.rule_individual import score_rules

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

def score_to_label(score: int) -> Scoring:
    if score < 15: return Scoring.BENIGN
    if score < 35: return Scoring.SUSPICIOUS
    if score < 60: return Scoring.MALICIOUS
    return Scoring.CRITICAL

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
    wazuh_level:    Scoring = None
    rule_id:        str     = None
    frequency:      int     = None
    timeframe:      int     = None
    mitre_id:       list    = None
    mitre_tactic:   list    = None
    mitre_technique:list    = None

    # ── From category ML ───────────────────────────────
    category:       str = None

    # ── From severity ML ───────────────────────────────
    severity:       int   = None   # 0-100
    label:          str   = None   

    # ── From LLM ─────────────────────────────────────
    explanation:    str   = None

    # ── Pipeline tracking ─────────────────────────────
    event_id:        str             = None
    status:          PipelineStatus   = PipelineStatus.PENDING   # pending -> normalized -> scored -> explained

    # Obtain any of the information stored in the class from a log
    def return_value(self, field_name):
        return getattr(self, field_name, None)
    
    def return_dict(self):
        d = asdict(self)
        return {k: (v.value if isinstance(v, Enum) else v) for k, v in d.items()}
    
    @staticmethod
    def score_event(event, blacklist: set, torexitslist: set) -> None:
        raw_score = score_rules(event, blacklist, torexitslist)
        event.severity = min(int(raw_score), 100)
        event.label = score_to_label(event.severity)
        event.status = PipelineStatus.SCORED
    
                         
