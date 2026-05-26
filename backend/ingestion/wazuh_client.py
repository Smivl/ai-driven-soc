# services/ingestion/wazuh_client.py
"""
Usage:
    client = WazuhClient()
    alerts = client.get_recent_alerts(limit= some number)
"""

###### source .venv/bin/activate
##### python -m services.soc.ingestion.wazuh_client

import requests
import urllib3
import os
import logging


from dotenv import load_dotenv
load_dotenv()   # reads .env into os.environ automatically

# Suppress self-signed certificate warnings in dev
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

class WazuhClient:
    def __init__(self):
        self.api_url  = os.getenv("API_URL",  "https://localhost:55000")
        self.api_user  = os.getenv("API_USER", "admin") # these are the standard username and password
        self.api_pass  = os.getenv("API_PASS", "SecretPassword")

        self.indexer_url  = os.getenv("INDEXER_URL",  "https://localhost:9200")
        self.indexer_user = os.getenv("INDEXER_USER", "admin")
        self.indexer_pass = os.getenv("INDEXER_PASS", "SecretPassword")

        # Certificate verification, as Wazuh generates its own certificate
        # Point this at root-ca.pem for proper verification
        # or set to False to skip 
        cert_path = os.getenv("WAZUH_CERT", None)
        self.verify = cert_path if cert_path else False

        self._token = None 

    def _authenticate(self) -> str:
        # If the authentication token is already fetched
        if self._token:
            return self._token

        r = requests.get(
            f"{self.api_url}/security/user/authenticate?raw=true",
            auth=(self.api_user, self.api_pass),
            verify=self.verify,
            timeout=10
        )
        r.raise_for_status()
        # We cache it in self._token so we don't re-authenticate every call.
        self._token = r.text.strip()
        logger.info("Authenticated with Wazuh successfully")
        return self._token


    def _headers(self) -> dict:
       # Return auth headers for API calls
        return {"Authorization": f"Bearer {self._authenticate()}"} # Wazuh uses Bearer token auth with the JWT token 

    def get_recent_alerts(self, limit: int = 10) -> list:
        """Fetch recent alerts directly from OpenSearch."""
        r = requests.post(
            f"{self.indexer_url}/wazuh-alerts-*/_search",
            auth=(self.indexer_user, self.indexer_pass),
            json={
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}]
            },
            verify=self.verify,
            timeout=15
        )
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        return [{"_wazuh_id": hit["_id"], **hit["_source"]} for hit in hits]
    
    # ------ Anomaly detector --------------------------------------------------------------

    def create_anomaly_detector(self, detector_config: dict) -> str:
        """
        Create an OpenSearch anomaly detector.
        Returns the detector_id.
        """
        r = requests.post(
            f"{self.indexer_url}/_plugins/_anomaly_detection/detectors",
            auth=(self.indexer_user, self.indexer_pass),
            json=detector_config,
            verify=self.verify,
            timeout=15
        )
        r.raise_for_status()
        detector_id = r.json()["_id"]
        logger.info("Created anomaly detector %s", detector_id)
        return detector_id

    def start_anomaly_detector(self, detector_id: str) -> None:
        r = requests.post(
            f"{self.indexer_url}/_plugins/_anomaly_detection/detectors/{detector_id}/_start",
            auth=(self.indexer_user, self.indexer_pass),
            verify=self.verify,
            timeout=15
        )
        r.raise_for_status()
        logger.info("Started anomaly detector %s", detector_id)

    def stop_anomaly_detector(self, detector_id: str) -> None:
        r = requests.post(
            f"{self.indexer_url}/_plugins/_anomaly_detection/detectors/{detector_id}/_stop",
            auth=(self.indexer_user, self.indexer_pass),
            verify=self.verify,
            timeout=15
        )
        r.raise_for_status()

    def get_anomaly_results(self, detector_id: str, limit: int = 50) -> list:
        """Fetch recent anomaly results for a detector."""
        r = requests.post(
            f"{self.indexer_url}/_plugins/_anomaly_detection/detectors/{detector_id}/results/_search",
            auth=(self.indexer_user, self.indexer_pass),
            json={
                "size": limit,
                "sort": [{"data_start_time": {"order": "desc"}}],
                "query": {
                    "range": {"anomaly_grade": {"gt": 0}}  # only actual anomalies
                }
            },
            verify=self.verify,
            timeout=15
        )
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    def list_anomaly_detectors(self) -> list:
        r = requests.post(
            f"{self.indexer_url}/_plugins/_anomaly_detection/detectors/_search",
            auth=(self.indexer_user, self.indexer_pass),
            json={"size": 50, "query": {"match_all": {}}},
            verify=self.verify,
            timeout=15
        )
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        return [{"id": h["_id"], **h["_source"]} for h in hits]
