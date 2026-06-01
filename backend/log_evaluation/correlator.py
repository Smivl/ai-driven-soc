from dataclasses import dataclass
import datetime
import field

from backend.log_evaluation.classes.alert import Alert
from backend.log_evaluation.classes.soc_event import SOCevent

###### source .venv/bin/activate
##### python -m backend.log_evaluation.correlator

@dataclass
class Correlator: 
    # Primary index : alert_id -> Alert
    active_alerts: dict[str, Alert] = field(default_factory=dict)

    # Secondary index : mitre_id -> set of alert_ids
    mitre_index: dict[str, set[str]] = field(default_factory=dict)

    # Tertiary index : source_ip -> set of alert_ids
    source_ip_index: dict[str,set[str]] = field(default_factory=dict)

    def correlate_event(self, event: SOCevent) -> Alert:
        event_mitre_ids = set(event.mitre_id) if event.mitre_id else set()
        
        # All alert IDs that match the event's source IP
        ip_matches = self._ip_to_alert_ids.get(event.source_ip, set())
        
        # All alert IDs that match ANY of the event's MITRE IDs
        mitre_matches = set()
        for mitre_id in event_mitre_ids:
            mitre_matches.update(self._mitre_to_alert_ids.get(mitre_id, set()))
            
        # Only check alerts that share BOTH the IP and at least one MITRE ID.
        candidate_alert_ids = ip_matches.intersection(mitre_matches)
        
        for alert_id in candidate_alert_ids:
            alert = self.active_alerts[alert_id]
            # Double check the intersection, then append
            if event_mitre_ids.intersection(alert.mitre_id):
                alert.add_event(event)
                
                # Update indexes because the alert might have gained new mitre_ids from this event
                for mitre_id in event_mitre_ids:
                    self._mitre_to_alert_ids[mitre_id].add(alert.alert_id)
                return alert

        # If no matching alert is found, create a new one
        alert = Alert.new_alert(event)
        
        # Update Primary Index
        self.active_alerts[alert.alert_id] = alert
        
        # Update IP Index
        if event.source_ip:
            self._ip_to_alert_ids[event.source_ip].add(alert.alert_id)
            
        # Update MITRE Index
        for mitre_id in event_mitre_ids:
            self._mitre_to_alert_ids[mitre_id].add(alert.alert_id)
            
        return alert
    
    def update_alerts(self, current_time: datetime.datetime, alert_timeout: datetime.timedelta) -> set[Alert]:
        expired_alerts = set()
        keys_to_remove = []
        
        for alert_id, alert in self.active_alerts.items():
            if current_time - alert.last_seen > alert_timeout:
                expired_alerts.add(alert)
                keys_to_remove.append(alert_id)

        # Keep all indexes perfectly synchronized on deletion
        for alert_id in keys_to_remove:
            alert = self.active_alerts[alert_id]
            
            # Clean up IP index
            for ip in alert.source_ips:
                if ip in self._ip_to_alert_ids:
                    self._ip_to_alert_ids[ip].discard(alert_id)
                    if not self._ip_to_alert_ids[ip]:
                        del self._ip_to_alert_ids[ip]
                        
            # Clean up MITRE index
            for mitre_id in alert.mitre_id:
                if mitre_id in self._mitre_to_alert_ids:
                    self._mitre_to_alert_ids[mitre_id].discard(alert_id)
                    if not self._mitre_to_alert_ids[mitre_id]:
                        del self._mitre_to_alert_ids[mitre_id]
            
            # Clean up Primary Index
            del self.active_alerts[alert_id]
            
        return expired_alerts

    def return_active_alerts(self) -> set[Alert]:
            return set(self.active_alerts.values())
