from dataclasses import dataclass

from backend.log_evaluation.classes.soc_event import SOCevent

import datetime

""""
    This class represents a correlated object that is shown in the UI.
    An Alert exists of multiple SOCevents.
"""

from dataclasses import dataclass, field
from datetime import datetime
import uuid

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

        self.mitre_id.update(event.mitre_id or [])
        self.mitre_tactic.update(event.mitre_tactic or [])
        self.mitre_technique.update(event.mitre_technique or [])
    
 