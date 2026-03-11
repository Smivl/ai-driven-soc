"""
Simple LightGBM model — predicts severity 0-100 from wazuh_level, IP & Port features.
"""

import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error
import requests
import ipaddress

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


def ip_security(ip:str, blacklist: set) -> int :
    """ Convert an IP address into a numerical represenatation that captures its security relevance
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

def port_security(port:int) :
    """ Convert a port number into a numerical representation that captures its security relevance
            - Common services ports, like for HTTP, SSH, etc. are more likely to be targeted
        Higher score means more likely to be malicious
    """
    common_ports = {22, 90, 443, 3306, 8080}
    return int(port in common_ports) * 5

def preprocess_data(df: pd.DataFrame, blacklist: set) -> pd.DataFrame:
    """ Add features for security relevances based """
    df['ip_security'] = df['ip'].apply(lambda ip: ip_security(ip, blacklist))
    df['port_security'] = df['port'].apply(lambda port: port_security(port))
    df['wazuh_level'] = df['wazuh_level'].astype(int) # Wazuh level between 0-15 should be numerical
    return df

#=========================== Model Training  ==========================

def train_model(blacklist: set) -> lgb.LGBMRegressor:
    """ Train simple lightGBM on synthetic data """
    df = temp_generate_data()
    df = preprocess_data(df, blacklist)

    X = df[["wazuh_level", "ip_security", "port_security"]]
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

def score_event(model, blacklist: set, wazuh_level: int, ip: str, port: int) -> int:
    """Score a single eventusing the trained model — returns severity 0-100"""
    features = pd.DataFrame([{
        "wazuh_level":  wazuh_level,
        "ip_security":  ip_security(ip, blacklist),
        "port_security": port_security(port),
    }])
    score = model.predict(features)[0]
    return int(np.clip(score, 0, 100))


def temp_generate_data(n : int = 1000) -> pd.DataFrame:
    """ Generate synthetic data for the training model """
    np.random.seed(42)
    data = {
        'wazuh_level' : np.random.randint(0,16, size=n),
        'ip'           : [f"{np.random.randint(1,255)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(1,255)}" for _ in range(n)],
        'port'         : np.random.randint(1,65536, size=n)
    }

    df = pd.DataFrame(data)
    # Generate a realistic severity label based on the features
    # This is the "ground truth" we train the model to learn
    df['severity'] = (
        (df['wazuh_level'] / 15) * 60                             # wazuh_level is strongest signal (0-60)
        + df['ip'].apply(lambda ip: ip_security(ip, set())) * 2   # ip contributes up to ~26
        + df['port'].apply(port_security)                         # port contributes up to 5
        + np.random.uniform(-5, 5, size=n)                        # small noise
    ).clip(0, 100).astype(int)

    return df


#=========================== Test this temp version  ==========================

def temp_test():
    """Temporary test function to run whole pipeline"""
    print("=" * 55)
    print("  Simple LightGBM Severity Model")
    print("=" * 55)

    print("\n1. Loading blacklist...")
    blacklist = load_blacklist()
    print(f"   Loaded {len(blacklist)} known malicious IPs")

    print("\n2. Training model...")
    model = train_model(blacklist)

    print("\n3. Scoring test events...")
    test_events = [
        {"wazuh_level": 3,  "ip": "192.168.1.50",  "port": 8080},  # internal, low
        {"wazuh_level": 8,  "ip": "192.168.1.105", "port": 22},    # internal, SSH
        {"wazuh_level": 10, "ip": "45.33.32.156",  "port": 443},   # external, medium
        {"wazuh_level": 14, "ip": "185.220.101.1", "port": 22},    # external, high
    ]

    print()
    print(f"  {'wazuh':<8} {'ip':<18} {'port':<8} {'score':<8}")
    print(f"  {'-'*8} {'-'*18} {'-'*8} {'-'*8} ")

    for e in test_events:
        score = score_event(model, blacklist, e["wazuh_level"], e["ip"], e["port"])
        print(f"  {e['wazuh_level']:<8} {e['ip']:<18} {e['port']:<8} {score:<8} ")

    print("\n" + "=" * 55)


if __name__ == "__main__":
    temp_test()