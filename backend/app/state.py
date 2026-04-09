from collections import deque
import threading

events: deque = deque(maxlen=500)
_lock = threading.Lock()


def add_events(new_events: list[dict]) -> None:
    with _lock:
        events.extend(new_events)


def get_events(limit: int = 100) -> list[dict]:
    with _lock:
        return list(events)[-limit:]
