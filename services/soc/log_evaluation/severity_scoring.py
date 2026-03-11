"""
Simple LightGBM model — predicts severity 0-100 from 
    - wazuh_level, 
    - Source IP 
    - Destination IP
    - Port features
"""

import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error
import requests
import ipaddress

from services.soc.log_evaluation.log_dataclass import SOCevent, PipelineStatus, Severity

###### source .venv/bin/activate
##### python -m services.soc.log_evaluation.severity_scoring

#=========================== Wazuh level, IP address & Port security relevance ==========================

def load_blacklist() -> set:
    """Download a real IP blacklist from FireHOL."""
    url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    r = requests.get(url)
    ips = set()
    for line in r.text.splitlines():
        if line and not line.startswith("#"):
            ips.add(line.strip())
    return ips


def source_ip_security(ip:str, blacklist: set) -> int :
    """ Tells you WHO is attacking you -
        Convert an IP address into a numerical represenatation that captures its security relevance
            - Private IPs are less likely to be malicious
            - IPs in a blacklist of known malicious IPs are more likely to be malicious
        Higher score means more likely to be malicious
    """

    # Check if IP is public or private 
    # - Private IPs are less likely to be malicious
    try:
        is_private   = ipaddress.ip_address(ip).is_private
    except ValueError:
        is_private   = False

    # Check if it appears in a blacklist of known malicious IPs
    in_blacklist = ip in blacklist

    return int(in_blacklist) * 10 + int(not is_private) * 3 

def destination_ip_security(ip:str) -> int :
    """ Tells you WHO is being attacked -
        Convert an IP address into a numerical represenatation that captures its security relevance
            - Internal serves are more likely to be critical assets being attacked
            - Core infrastructure IPs are more likely to be critical assets being attacked
        Higher score means more critical asset being attacked
    """
    try:
        is_private = ipaddress.ip_address(ip).is_private
    except ValueError:
        is_private = False

    # Targeting internal infrastructure is more concerning than external
    is_internal_server = (ip.startswith("10.0.0.") or ip.startswith("192.168.1.1"))

    return (int(is_private) * 3 + int(is_internal_server) * 5)

def port_security(port:int) :
    """ Convert a port number into a numerical representation that captures its security relevance
            - Common services ports, like for HTTP, SSH, etc. are more likely to be targeted
        Higher score means more likely to be malicious
    """
    common_ports = {22, 90, 443, 3306, 8080}
    return int(port in common_ports) * 5

#=========================== Scoring of events  ==========================

def score_to_label(score :int) -> Severity:
    if score <25: return Severity.BENIGN
    if score <50: return Severity.SUSPICIOUS
    if score <75: return Severity.MALICIOUS
    return Severity.CRITICAL

def score_event(model, blacklist: set, event: SOCevent) -> SOCevent:
    """ Score a SOCevent using the trained model — updates severity, label and status """
    features = pd.DataFrame([{
        "wazuh_level":   event.wazuh_level,
        "source_ip_security":   source_ip_security(event.source_ip, blacklist),
        "destination_ip_security":   destination_ip_security(event.destination_ip),
        "port_security": port_security(event.port),
    }])

    raw_score = model.predict(features)[0]

    event.severity = int(np.clip(raw_score, 0, 100))
    event.label    = score_to_label(event.severity)
    event.status   = PipelineStatus.SCORED

    return event

#=========================== Model Training  ==========================

def events_to_dataframe(events: list[SOCevent], blacklist: set) -> pd.DataFrame:
    """Convert SOCEvents into a feature DataFrame for LightGBM."""
    rows = []
    for e in events:
        rows.append({
            "wazuh_level":  e.wazuh_level,                                        # Scoring between 0-15
            "source_ip_security":  source_ip_security(e.source_ip, blacklist),    # Scoring between 0-13
            "destination_ip_security": destination_ip_security(e.destination_ip), # Scoring between 0-8
            "port_security": port_security(e.port),                               # Scoring either 0 or 5
            "severity":     e.severity,                                           # Scoring between 0-100 (target variable)
        })
    return pd.DataFrame(rows)


def train_model(blacklist: set) -> lgb.LGBMRegressor:
    """Train simple LightGBM on synthetic SOCEvents."""
    events = temp_generate_data()
    df     = events_to_dataframe(events, blacklist)

    X = df[["wazuh_level", "source_ip_security", "destination_ip_security", "port_security"]]
    y = df["severity"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = lgb.LGBMRegressor(
        n_estimators=100,
        learning_rate=0.1,
        num_leaves=31,
        verbose=-1
    )
    model.fit(X_train, y_train)

    mae = mean_absolute_error(y_test, model.predict(X_test))
    print(f"  Trained on {len(X_train)} samples | MAE: {mae:.1f} points")

    return model

#=========================== Test this temp version  ==========================

def temp_generate_data(n: int = 1000) -> list[SOCevent]:
    """Generate synthetic SOCEvents for training the model """
    np.random.seed(42)

    events = []
    for _ in range(n):
        wazuh_level = int(np.random.randint(0, 16))
        source_ip          = f"{np.random.randint(1,255)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(1,255)}"
        destination_ip = f"{np.random.randint(1,255)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(1,255)}"
        port        = int(np.random.randint(1, 65536))

        # Calculate severity — NOTE: not a real formula, just for synthetic training data
        severity = int(np.clip(
            (wazuh_level / 15) * 60
            + source_ip_security(source_ip, set()) * 2
            + destination_ip_security(destination_ip) * 2
            + port_security(port)
            + np.random.uniform(-5, 5),
            0, 100
        ))

        events.append(SOCevent(
            source_ip        = source_ip,
            destination_ip   = destination_ip,
            port             = port,
            wazuh_level      = wazuh_level,
            severity         = severity,
            status            = PipelineStatus.PENDING,
        ))

    return events

def temp_test():
    """Temporary test function to run whole pipeline"""
    print("=" * 60)
    print("  Simple LightGBM Severity Model")
    print("=" * 60)

    print("\n1. Loading blacklist...")
    blacklist = load_blacklist()
    print(f"   Loaded {len(blacklist)} known malicious IPs")

    print("\n2. Training model...")
    model = train_model(blacklist)

    print("\n3. Scoring test events...")
    test_events = [
        SOCevent(source_ip="192.168.1.50",  destination_ip="10.0.0.1",    port=8080,  wazuh_level=3),   # internal, low,     web
        SOCevent(source_ip="192.168.1.105", destination_ip="10.0.0.1",    port=22,    wazuh_level=8),   # internal, medium,  SSH
        SOCevent(source_ip="45.33.32.156",  destination_ip="10.0.0.5",    port=443,   wazuh_level=10),  # external, medium,  HTTPS
        SOCevent(source_ip="185.220.101.1", destination_ip="10.0.0.5",    port=22,    wazuh_level=14),  # external, high,    SSH known bad
        SOCevent(source_ip="10.0.0.25",     destination_ip="10.0.0.20",   port=3306,  wazuh_level=6),   # internal, medium,  MySQL
        SOCevent(source_ip="198.51.100.77", destination_ip="10.0.0.5",    port=80,    wazuh_level=5),   # external, low,     HTTP
        SOCevent(source_ip="172.16.0.10",   destination_ip="10.0.0.1",    port=443,   wazuh_level=2),   # internal, low,     HTTPS
        SOCevent(source_ip="91.108.4.1",    destination_ip="10.0.0.5",    port=22,    wazuh_level=12),  # external, high,    SSH
    ]

    print()
    print(f"  {'wazuh':<8} {'source ip':<18} {'destination ip':<18} {'port':<8} {'score':<8} {'label':<12} {'status'}")
    print(f"  {'-'*8} {'-'*18} {'-'*18} {'-'*8} {'-'*8} {'-'*12} {'-'*10}")

    for event in test_events:
        scored = score_event(model, blacklist, event)
        print(f"  {scored.wazuh_level:<8} {scored.source_ip:<18} {scored.destination_ip:<18} {scored.port:<8} {scored.severity:<8} {scored.label.value:<12} {scored.status.value}")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    temp_test()