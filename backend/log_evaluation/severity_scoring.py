from backend.log_evaluation.ML_category import categorise_score_log
from backend.log_evaluation.rule_individual import score_rules
from backend.log_evaluation.soc_event import SOCevent, PipelineStatus, Scoring

def score_to_label(score: int) -> Scoring:
    if score < 15: return Scoring.LOW
    if score < 35: return Scoring.MEDIUM
    if score < 60: return Scoring.HIGH
    return Scoring.CRITICAL

def score_event(event: SOCevent, blacklist: set, torexitslist: set) -> SOCevent:
    raw_score      = score_rules(event, blacklist, torexitslist)
    event.severity = min(int(raw_score), 100)
    event.label    = score_to_label(event.severity)
    event.status   = PipelineStatus.SCORED
    return event

