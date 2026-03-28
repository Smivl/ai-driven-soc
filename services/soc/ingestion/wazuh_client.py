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

from services.soc.ingestion.normalizerfixed import normalize_wazuh_alert

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

    """
        To log into the Wazuh API
        JSON Web Token (JWT) authentication, this is more secure than the HTTP basic authentication

        An example for the output of fectching a JSON web token
        {"user":"admin","authenticationToken":"bA-a-wc9Ip...KcrUV2omGg","durationSeconds":180}

        - https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html

    """
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
        return [hit["_source"] for hit in hits]
    
import sys
import os
sys.path.append("services/ingestion")

def test_connection():
    print("=" * 50)
    print("  Wazuh Connection Test")
    print("=" * 50)

    client = WazuhClient()

    # 1. Authenticate
    print("\n1. Authenticating...")
    token = client._authenticate()
    print(f"   Token: {token[:30]}...")

    # 2. Fetch alerts
    print("\n2. Fetching last 5 alerts...")
    alerts = client.get_recent_alerts(limit=1)
    print(f"   Got {len(alerts)} alerts")

    # 3. Print them
    print()
    for alert in alerts:
        level = alert.get("rule", {}).get("level", "?")
        desc  = alert.get("rule", {}).get("description", "no description")
        ts    = alert.get("timestamp", "no timestamp")
        print(f"   [{level}] {desc} | {ts}")

    print("\n" + "=" * 50)

    print(alerts[0])

    normalized = normalize_wazuh_alert(alerts[0])

    print(normalized.return_value("wazuh_level"))

if __name__ == "__main__":
    test_connection()