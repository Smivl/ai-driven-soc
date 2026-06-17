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
import threading

from ingestion.normalizerfixed import normalize_wazuh_alert

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
        self._token_lock = threading.Lock()

        # Cached {agent_id: group} map, used to resolve a tenant on alert pull.
        self._group_cache: dict[str, str | None] = {}
        self._group_cache_lock = threading.Lock()

    """
        To log into the Wazuh API
        JSON Web Token (JWT) authentication, this is more secure than the HTTP basic authentication

        An example for the output of fectching a JSON web token
        {"user":"admin","authenticationToken":"bA-a-wc9Ip...KcrUV2omGg","durationSeconds":180}

        - https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html

    """
    def _authenticate(self) -> str:
        with self._token_lock:
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

    def _api(self, method: str, path: str, **kwargs) -> requests.Response:
        """Call the Wazuh API, re-authenticating once if the JWT has expired.

        Wazuh API tokens are short-lived (~15 min). On a 401 we drop the cached
        token, re-authenticate, and retry the request once.
        """
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("timeout", 10)
        url = f"{self.api_url}{path}"
        r = requests.request(method, url, headers=self._headers(), **kwargs)
        if r.status_code == 401:
            with self._token_lock:
                self._token = None  # force a fresh login on the next _headers()
            r = requests.request(method, url, headers=self._headers(), **kwargs)
        return r

    # ── Alert queries (OpenSearch) ────────────────────────────────────
    def _search_alerts(self, query: dict, limit: int, ascending: bool = False) -> list:
        """Run an OpenSearch query against wazuh-alerts and return flat hits."""
        order = "asc" if ascending else "desc"
        r = requests.post(
            f"{self.indexer_url}/wazuh-alerts-*/_search",
            auth=(self.indexer_user, self.indexer_pass),
            json={
                "size": limit,
                "query": query,
                "sort": [{"@timestamp": {"order": order}}],
            },
            verify=self.verify,
            timeout=15,
        )
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        return [{"_wazuh_id": hit.get("_id"), **hit["_source"]} for hit in hits]

    def get_recent_alerts(self, limit: int = 10) -> list:
        """Fetch recent alerts directly from OpenSearch."""
        return self._search_alerts({"match_all": {}}, limit)

    def get_alerts_by_agent(self, agent_id: str, limit: int = 10) -> list:
        """Fetch recent alerts attributed to a single agent."""
        return self._search_alerts({"term": {"agent.id": agent_id}}, limit)

    def get_alerts_by_group(self, group: str, limit: int = 10) -> list:
        """Fetch recent alerts for every agent in a Wazuh group (tenant)."""
        agent_ids = [a["id"] for a in self.list_agents(group=group)]
        if not agent_ids:
            return []
        return self._search_alerts({"terms": {"agent.id": agent_ids}}, limit)

    def get_significant_alerts(
        self,
        min_level: int = 7,
        limit: int = 10,
        group: str | None = None,
        require_mitre: bool = False,
        since: str | None = None,
        ascending: bool = False,
    ) -> list:
        """Fetch only "useful" alerts: rule.level >= min_level.

        Optionally restrict to a tenant ``group`` and/or to MITRE-tagged rules.
        ``since`` (an ISO timestamp) limits results to alerts at/after that time
        — used by the pipeline as a watermark so restarts don't re-ingest old
        alerts. ``ascending`` returns oldest-first (so the watermark can advance
        without skipping bursts larger than ``limit``).
        """
        must: list[dict] = [{"range": {"rule.level": {"gte": min_level}}}]
        if require_mitre:
            must.append({"exists": {"field": "rule.mitre.id"}})
        if since:
            must.append({"range": {"@timestamp": {"gte": since}}})
        if group:
            agent_ids = [a["id"] for a in self.list_agents(group=group)]
            if not agent_ids:
                return []
            must.append({"terms": {"agent.id": agent_ids}})
        return self._search_alerts({"bool": {"must": must}}, limit, ascending=ascending)

    # ── Agent / group management (Wazuh API) ──────────────────────────
    def create_group(self, group_id: str) -> None:
        """Create a Wazuh group. Treats an already-existing group as success."""
        r = self._api("POST", "/groups", json={"group_id": group_id})
        if r.status_code == 200:
            logger.info("Created Wazuh group %s", group_id)
            return
        # Wazuh returns 400 with error 1711 when the group already exists.
        if r.status_code == 400 and "already exists" in r.text:
            logger.info("Wazuh group %s already exists", group_id)
            return
        r.raise_for_status()

    def list_agents(self, group: str | None = None) -> list[dict]:
        """List registered agents (optionally filtered by group)."""
        params = {"limit": 1000}
        if group:
            params["group"] = group
        r = self._api("GET", "/agents", params=params)
        r.raise_for_status()
        return r.json().get("data", {}).get("affected_items", [])

    def register_agent(self, name: str, ip: str = "any") -> str:
        """Register an agent by name and return its 3-digit ID.

        Idempotent: if an agent with this name already exists, its existing ID
        is returned instead of raising.
        """
        r = self._api("POST", "/agents", json={"name": name, "ip": ip})
        if r.status_code == 200:
            return r.json()["data"]["id"]
        # Error 1705: an agent with that name already exists — look it up.
        if r.status_code in (400, 409):
            for agent in self.list_agents():
                if agent.get("name") == name:
                    return agent["id"]
        r.raise_for_status()
        raise RuntimeError(f"Could not register or find agent {name!r}")

    def assign_agent_to_group(self, agent_id: str, group_id: str) -> None:
        """Assign an agent to a group (idempotent on the Wazuh side)."""
        r = self._api("PUT", f"/agents/{agent_id}/group/{group_id}")
        r.raise_for_status()

    def get_agent_group(self, agent_id: str) -> str | None:
        """Resolve an agent's group (tenant), caching the full map on first use."""
        if agent_id is None:
            return None
        with self._group_cache_lock:
            if agent_id in self._group_cache:
                return self._group_cache[agent_id]
        # Cache miss — refresh the whole id→group map from the API.
        fresh: dict[str, str | None] = {}
        for agent in self.list_agents():
            groups = agent.get("group") or []
            fresh[agent["id"]] = groups[0] if groups else None
        with self._group_cache_lock:
            self._group_cache = fresh
            return self._group_cache.get(agent_id)


def test_connection():
    print("=" * 50)
    print("  Wazuh Connection Test")
    print("=" * 50)

    client = WazuhClient()

    print("\n1. Authenticating...")
    token = client._authenticate()
    print(f"   Token: {token[:30]}...")

    print("\n2. Fetching last 5 alerts...")
    alerts = client.get_recent_alerts(limit=5)
    print(f"   Got {len(alerts)} alerts")

    print()
    for alert in alerts:
        level = alert.get("rule", {}).get("level", "?")
        desc  = alert.get("rule", {}).get("description", "no description")
        agent = alert.get("agent", {})
        print(f"   [{level}] {desc} | agent={agent.get('id')} ({agent.get('name')})")

    print("\n" + "=" * 50)


if __name__ == "__main__":
    test_connection()