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

        self._token = None 

    """
        To log into the Wazuh indexer API
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

    """ (According to Claude) a in affected_items alert might look like this:
    {
        "id": "1705312425.12345",
        "timestamp": "2024-01-15T10:23:45.000Z",
        "rule": {
          "id": "5710",
          "level": 5,
          "description": "sshd: Attempt to login using a non-existent user",
          "groups": ["authentication_failed", "sshd"]
        },
        "agent": {
          "id": "001",
          "name": "ubuntu-server-01"
        },
        "data": {
          "srcip": "192.168.1.105",
          "dstuser": "admin"
        },
        "full_log": "Jan 15 10:23:45 server sshd[1234]: Failed password for admin from 192.168.1.105 port 4444 ssh2"
      }
      """

    def get_recent_alerts(self, limit: int = 10) -> list:
  
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