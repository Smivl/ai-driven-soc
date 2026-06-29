# This file defines the single event type that every pipeline stage reads and
# writes, plus the two small enums used to label an event.

from dataclasses import dataclass, asdict
from enum import Enum

class Scoring(Enum):
    BENIGN     = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS  = "malicious"
    CRITICAL   = "critical"

class PipelineStatus(Enum):
    PENDING    = "pending"
    NORMALIZED = "normalized"  # the raw log has been parsed into fields
    SCORED     = "scored"      # the model has given it a severity
    EXPLAINED  = "explained"   # the LLM has written an explanation
    RESOLVED   = "resolved"    # the event has been handled

@dataclass
class SOCevent:
    """One security event as it moves through the pipeline.

    It starts as a parsed log, then the model adds a severity, and finally the
    LLM adds an explanation and a suggested action. Every field is optional so
    the event can be built up a stage at a time.
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

    # Read one field by name. Returns None if that field has not been set.
    def return_value(self, field_name):
        return getattr(self, field_name, None)

    # Turn the event into a plain dictionary for JSON. Enum fields become their
    # string value so the result is easy to send to the frontend.
    def return_dict(self):
        d = asdict(self)
        return {k: (v.value if isinstance(v, Enum) else v) for k, v in d.items()}
    
                         
