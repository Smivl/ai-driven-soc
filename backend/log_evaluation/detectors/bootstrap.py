# detectors/bootstrap.py

from backend.ingestion.wazuh_client import WazuhClient
from detectors.configs import FAILED_LOGINS_DETECTOR, LINUX_RESOURCE_DETECTOR

def bootstrap_detectors():
    client = WazuhClient()
    
    # Avoid duplicates — skip if name already exists
    existing = {d["name"] for d in client.list_anomaly_detectors()}
    
    for config in [FAILED_LOGINS_DETECTOR, LINUX_RESOURCE_DETECTOR]:
        if config["name"] in existing:
            print(f"Skipping {config['name']} — already exists")
            continue
        detector_id = client.create_anomaly_detector(config)
        client.start_anomaly_detector(detector_id)
        print(f"Created and started: {config['name']} ({detector_id})")

if __name__ == "__main__":
    bootstrap_detectors()