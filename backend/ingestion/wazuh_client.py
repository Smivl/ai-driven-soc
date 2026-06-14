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
import uuid
from backend.log_evaluation.classes.soc_event import *
from backend.log_evaluation.classes.alert import Alert

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
    
    # =============== Storing and updating =======================

    def store_soc_event(self, event: SOCevent, doc_id: str = None) -> str:
        """
            Serialize and store a SOCevent in OpenSearch
            Returns the doc_id used (auto-generated if not provided)
        """

        if doc_id is None:
            doc_id = str(uuid.uuid4())

        # Convert to dict
        payload = asdict(event)
        payload["wazuh_level"] = event.wazuh_level
        payload["status"]      = event.status.value if event.status else None
        if hasattr(payload.get("timestamp"), "isoformat"):
            payload["timestamp"] = payload["timestamp"].isoformat()

        r = requests.put(
            f"{self.indexer_url}/soc-events/_doc/{doc_id}",
            auth=(self.indexer_user, self.indexer_pass),
            json=payload,
            verify=self.verify,
            timeout=15
        )
        r.raise_for_status()
        logger.info("Stored SOCevent %s (status=%s)", doc_id, payload["status"])
        return doc_id

    def store_soc_alert(self, alert: Alert) -> str:
        """Persist an Alert to the soc-alerts index in OpenSearch."""
        payload = alert.to_dict()
        r = requests.put(
            f"{self.indexer_url}/soc-alerts/_doc/{alert.alert_id}",
            auth=(self.indexer_user, self.indexer_pass),
            json=payload,
            verify=self.verify,
            timeout=15,
        )
        r.raise_for_status()
        logger.info("Stored Alert %s (status=%s)", alert.alert_id, alert.status)
        return alert.alert_id

    def get_soc_event(self, doc_id: str) -> SOCevent:
        """Retrieve a SOCevent by ID and deserialize back into the dataclass"""

        r = requests.get(
            f"{self.indexer_url}/soc-events/_doc/{doc_id}",
            auth=(self.indexer_user, self.indexer_pass),
            verify=self.verify,
            timeout=15
        )
        r.raise_for_status()
        source = r.json().get("_source", {})
        return self._deserialize_soc_event(source)

    def search_soc_events( self, status: PipelineStatus = None, scoring=None, limit: int = 50) -> list[SOCevent]:
        """
        Search soc-events index with optional filters.
        Examples:
            client.search_soc_events(status=PipelineStatus.PENDING)
            client.search_soc_events(scoring=Scoring.CRITICAL)
        """
        filters = []
        if status:
            filters.append({"term": {"status": status.value}})
        if scoring:
            filters.append({"term": {"wazuh_level": scoring.value}})

        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}

        r = requests.post(
            f"{self.indexer_url}/soc-events/_search",
            auth=(self.indexer_user, self.indexer_pass),
            json={
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": query
            },
            verify=self.verify,
            timeout=15
        )
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        return [self._deserialize_soc_event(hit["_source"]) for hit in hits]

    def update_soc_event(self, doc_id: str, new_status: PipelineStatus, **fields) -> None:
        """
        Partial update for any pipeline stage
        Always updates status, plus any extra fields passed 
        
        Examples:
            # After ML scoring
            client.update_soc_event(doc_id, PipelineStatus.SCORED, severity=0, label="label")
            
            # After LLM explanation
            client.update_soc_event(doc_id, PipelineStatus.EXPLAINED, explanation="explanation")
            
            # After SOAR resolution
            client.update_soc_event(doc_id, PipelineStatus.RESOLVED)
        """
        patch = {"status": new_status.value, **fields}

        # Serialize any Enum values that might be passed in
        for key, val in patch.items():
            if isinstance(val, ( PipelineStatus)):
                patch[key] = val.value

        r = requests.post(
            f"{self.indexer_url}/soc-events/_update/{doc_id}",
            auth=(self.indexer_user, self.indexer_pass),
            json={"doc": patch},
            verify=self.verify,
            timeout=15
        )
        r.raise_for_status()
        logger.info("Updated SOCevent %s -> %s | fields: %s", doc_id, new_status.value, list(fields.keys()))

    @staticmethod
    def _deserialize_soc_event(source: dict) -> SOCevent:
        """Rebuild a SOCevent from a raw OpenSearch _source dict"""

        # Convert string values back to Enums safely
        raw_status = source.get("status")

        return SOCevent(
            source_ip      = source.get("source_ip"),
            destination_ip = source.get("destination_ip"),
            port           = source.get("port"),
            user           = source.get("user"),
            event_type     = source.get("event_type"),
            timestamp      = source.get("timestamp"),
            raw_log        = source.get("raw_log"),
            wazuh_level    = source.get("wazuh_level"),
            rule_id        = source.get("rule_id"),
            severity       = source.get("severity"),
            label          = source.get("label"),
            explanation    = source.get("explanation"),
            status         = PipelineStatus(raw_status) if raw_status else PipelineStatus.PENDING,
        )
    
