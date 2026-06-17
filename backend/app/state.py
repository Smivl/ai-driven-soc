import threading

_MAX_EVENTS = 500

_events: dict = {}  # event_id -> event dict; insertion-ordered (Python 3.7+)
_resolved: set = set()  # event_ids an analyst has marked resolved
_lock = threading.Lock()


def upsert_event(event_dict: dict) -> None:
    with _lock:
        eid = event_dict["event_id"]
        # Keep a resolved event resolved even if a late worker upserts it.
        if eid in _resolved:
            event_dict["status"] = "resolved"
        if eid not in _events and len(_events) >= _MAX_EVENTS:
            oldest = next(iter(_events))
            del _events[oldest]
            _resolved.discard(oldest)
        _events[eid] = event_dict


def get_event(event_id: str) -> dict | None:
    with _lock:
        return _events.get(event_id)


def get_events(limit: int = 100) -> list[dict]:
    with _lock:
        vals = list(_events.values())
    return vals[-limit:]


def get_events_by_group(group: str, limit: int = 50, include_resolved: bool = False) -> list[dict]:
    """Most-recent events for one tenant (group), newest last."""
    with _lock:
        vals = [
            e for e in _events.values()
            if e.get("group") == group and (include_resolved or e.get("status") != "resolved")
        ]
    return vals[-limit:]


def resolve_event(event_id: str) -> bool:
    """Mark an event resolved. Returns False if the event is unknown."""
    with _lock:
        ev = _events.get(event_id)
        if ev is None:
            return False
        _resolved.add(event_id)
        ev["status"] = "resolved"
        return True


def clear_events() -> None:
    with _lock:
        _events.clear()
        _resolved.clear()


# ── Per-tenant AI assessments (written by the assess worker) ────────────────────
_assessments: dict = {}  # group -> {status, risk_score, summary, window, updated_at}
_assess_lock = threading.Lock()


def set_assessment(group: str, data: dict) -> None:
    with _assess_lock:
        _assessments[group] = data


def get_assessments() -> dict:
    with _assess_lock:
        return dict(_assessments)
