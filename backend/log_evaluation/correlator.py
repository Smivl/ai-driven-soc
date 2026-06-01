from dataclasses import dataclass
import datetime

from backend.log_evaluation.classes.alert import Alert
from backend.log_evaluation.classes.soc_event import SOCevent

###### source .venv/bin/activate
##### python -m backend.log_evaluation.correlator

@dataclass
class Correlator: 

    active_alerts: dict[str, Alert] = None

    def correlate_event(self, event: SOCevent):
        for alert in self.active_alerts.values():
            # if the event matches the alert's MITRE ID and source IPs, add it to the alert
            if set(event.mitre_id or []).intersection(alert.mitre_id) and (event.source_ip in alert.source_ips):
                alert.add_event(event)
                return alert

        # If no matching alert is found, create a new one
        alert = Alert.new_alert(event)
        self.active_alerts[alert.alert_id] = alert
        return alert
    
    def update_alerts(self, current_time: datetime.datetime, alert_timeout: datetime.timedelta) -> set[Alert]:
        # Remove and return the alerts that have not been updated in a while
        expired_alerts = set()
        for alert in self.active_alerts:
            if current_time - alert.last_seen > alert_timeout:
                expired_alerts.add(alert)

        self.active_alerts -= expired_alerts
        return expired_alerts

    def return_active_alerts(self)-> set[Alert]:
        return self.active_alerts
