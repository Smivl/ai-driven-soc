# services/ingestion/wazuh_client.py
"""
Usage:
    client = WazuhClient()
    alerts = client.get_recent_alerts(limit= some number)
"""

import requests
import urllib3
import os
import logging
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()   # reads .env into os.environ automatically

# Suppress self-signed certificate warnings in dev
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

class WazuhClient:
    def __init__(self):
        self.base_url  = os.getenv("WAZUH_URL",  "https://localhost:55000")
        self.username  = os.getenv("WAZUH_USER", "admin") # these are the standard username and password
        self.password  = os.getenv("WAZUH_PASS", "SecretPassword")

        # Certificate verification, as Wazuh generates its own certificate
        # Point this at root-ca.pem for proper verification
        # or set to False to skip 
        cert_path = os.getenv("WAZUH_CERT", None)
        self.verify = cert_path if cert_path else False

        self._token = None # cache the JWT token so we don't have to re-authenticate every time

    def _authenticate(self) -> str:
        """
        POST credentials to Wazuh and get back a JWT token
        The token is valid for 15 minutes
        """
        if self._token:
            return self._token

        r = requests.get(
            f"{self.base_url}/security/user/authenticate?raw=true",
            auth=(self.username, self.password),
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
        """
        Fetch the most recent alerts from Wazuh, newest first
        Returns a list of raw Wazuh alert as dicts
        """
        r = requests.get(
            f"{self.base_url}/alerts",
            headers=self._headers(),
            params={
                "limit": limit,
                "sort":  "-timestamp"   # newest first
            },
            verify=self.verify,
            timeout=15
        )
        r.raise_for_status() # will raise an HTTPError if the request has failed
        alerts = r.json().get("data", {}).get("affected_items", []) # Wazuh's API wraps result in a data object with affected_items
        logger.info(f"Fetched {len(alerts)} alerts")
        return alerts