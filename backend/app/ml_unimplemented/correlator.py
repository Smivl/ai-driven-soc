"""
    Rule-based correlation of events
    THIS FILE IS NOT IMPLEMENTED AND FINISHED IN THE CURRENT PIPELINE AND IS EXPORTED FROM A DIFFERENT BRANCH
"""

from dataclasses import dataclass
import datetime
import field

from backend.app.ml_unimplemented.ml_sequence import Alert
from backend.app.log_evaluation.socevent import SOCevent

###### source .venv/bin/activate
##### python -m backend.log_evaluation.correlator

MIN_SCORE = 65  # Minimum score threshold to bind an event to an existing alert


@dataclass
class Correlator: 
    # Primary index : alert_id -> Alert
    active_alerts: dict[str, Alert] = field(default_factory=dict)

    # Secondary indexes : 
    # mitre_id -> set of alert_ids
    mitre_index: dict[str, set[str]] = field(default_factory=dict)
    # source_ip -> set of alert_ids
    source_ip_index: dict[str,set[str]] = field(default_factory=dict)
    # user -> set of alert_ids
    user_index: dict[str, set[str]] = field(default_factory=dict)
    # destination_ip -> set of alert_ids
    dest_ip_index: dict[str, set[str]] = field(default_factory=dict)

    def correlation_score(self, alert: Alert, event: SOCevent) -> int:
        score = 0

        # Source IP check
        if event.source_ip and alert.alert_id in self.source_ip_index.get(event.source_ip, set()):
            score += 40
        
        # MITRE ID check 
        if event.mitre_id:
            for m_id in event.mitre_id:
                if alert.alert_id in self.mitre_index.get(m_id, set()):
                    score += 40
                    break  
        
        # User Alignment (Optimized if you track alert.users set, otherwise using events list)
        if event.user and alert.alert_id in self.user_index.get(event.user, set()):
            score += 35
        
        # Destination IP check
        if event.destination_ip and alert.alert_id in self.dest_ip_index.get(event.destination_ip, set()):
            score += 15
        
        # Velocity/Frequency check
        if event.frequency and alert.event_count > 0:
            score += min(20, event.frequency * 5)

        return score

    def correlate_event(self, event: SOCevent) -> Alert:
        event_mitre_ids = set(event.mitre_id) if event.mitre_id else set()
        
        # Gather ALL potential matches across all dimensions
        ip_matches = self.source_ip_index.get(event.source_ip, set())
        mitre_matches = set()
        for mitre_id in event_mitre_ids:
            mitre_matches.update(self.mitre_index.get(mitre_id, set()))

        user_matches = self.user_index.get(event.user, set()) if event.user else set()
        dest_matches = self.dest_ip_index.get(event.destination_ip, set()) if event.destination_ip else set()

        #  Get every alert that matches even ONE of these attributes
        candidate_alert_ids = ip_matches.union(mitre_matches, user_matches, dest_matches)
        
        best_alert = None
        highest_score = MIN_SCORE  # Set your minimum score threshold to bind an event to an alert
        
        # Evaluate all potential candidate alerts
        for alert_id in candidate_alert_ids:
            alert = self.active_alerts[alert_id]
            score = self.correlation_score(alert, event)
            
            if score >= highest_score:
                highest_score = score
                best_alert = alert

        # If we found a high-scoring matching alert, attach the event to it
        if best_alert:
            best_alert.add_event(event)
            
            # Update indexes because the alert might have adopted new traits from this event
            if event.source_ip:
                self.source_ip_index.setdefault(event.source_ip, set()).add(best_alert.alert_id)
            for mitre_id in event_mitre_ids:
                self.mitre_index.setdefault(mitre_id, set()).add(best_alert.alert_id)
            for user in best_alert.users:
                self.user_index.setdefault(user, set()).add(best_alert.alert_id)
            for dest_ip in best_alert.destination_ips:
                self.dest_ip_index.setdefault(dest_ip, set()).add(best_alert.alert_id)
                
            return best_alert

        # If no alerts scored above the threshold create new alert
        alert = Alert.new_alert(event)
        
        # Update Indexes
        self.active_alerts[alert.alert_id] = alert
        
        if event.source_ip:
            self.source_ip_index.setdefault(event.source_ip, set()).add(alert.alert_id)
            
        for mitre_id in event_mitre_ids:
            self.mitre_index.setdefault(mitre_id, set()).add(alert.alert_id)
            
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
                if ip in self.source_ip_index:
                    self.source_ip_index[ip].discard(alert_id)
                    if not self.source_ip_index[ip]:
                        del self.source_ip_index[ip]
                        
            # Clean up MITRE index
            for mitre_id in alert.mitre_id:
                if mitre_id in self.mitre_index:
                    self.mitre_index[mitre_id].discard(alert_id)
                    if not self.mitre_index[mitre_id]:
                        del self.mitre_index[mitre_id]
            
            # Clean up DestIP index
            for dest_ip in alert.destination_ips:
                if dest_ip in self.destination_ip_index:
                    self.destination_ip_index[dest_ip].discard(alert_id)
                    if not self.destination_ip_index[dest_ip]:
                        del self.destination_ip_index[dest_ip]
            
            # Clean up user index
            for user in alert.users:
                if user in self.user_index:
                    self.user_index[user].discard(alert_id)
                    if not self.user_index[user]:
                        del self.user_index[user]
            
            # Clean up Primary Index
            del self.active_alerts[alert_id]
            
        return expired_alerts

    def return_active_alerts(self) -> list[Alert]:
        return list(self.active_alerts.values())