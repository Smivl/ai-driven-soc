import threading

_MAX_EVENTS = 500

_events: dict = {}  # event_id -> event dict; insertion-ordered (Python 3.7+)
_lock = threading.Lock()


def upsert_event(event_dict: dict) -> None:
    with _lock:
        eid = event_dict["event_id"]
        if eid not in _events and len(_events) >= _MAX_EVENTS:
            oldest = next(iter(_events))
            del _events[oldest]
        _events[eid] = event_dict


def get_event(event_id: str) -> dict | None:
    with _lock:
        return _events.get(event_id)


def get_events(limit: int = 100) -> list[dict]:
    with _lock:
        vals = list(_events.values())
    return vals[-limit:]
