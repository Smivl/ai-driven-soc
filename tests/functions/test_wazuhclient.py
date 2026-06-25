# tests/wazuh_client_test.py
# tests/ingestion/test_wazuh_client.py
"""
Tests for WazuhClient — uses mocking so no real server needed.

Run from project root:
    pytest tests/ingestion/test_wazuh_client.py -v
"""
import pytest
from unittest.mock import patch, MagicMock
import sys
import os
sys.path.insert(0, os.path.abspath("."))

from ingestion.wazuh_client import WazuhClient


# ── Fake data that mimics real OpenSearch responses and API connection ────────────────────────

FAKE_TOKEN = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.fake_token"

FAKE_OPENSEARCH_RESPONSE = {
    "hits": {
        "hits": [
            {
                "_source": {
                    "timestamp": "2026-03-23T16:31:28.689+0000",
                    "rule": {
                        "level": 10,
                        "description": "sshd: brute force trying to get access",
                        "groups": ["authentication_failures", "sshd"],
                        "id": "5712"
                    },
                    "data": {
                        "srcip": "192.168.1.105",
                        "dstport": "22"
                    },
                    "agent": {"name": "ubuntu-server", "id": "001"},
                    "full_log": "Failed password for admin from 192.168.1.105 port 22 ssh2"
                }
            },
            {
                "_source": {
                    "timestamp": "2026-03-23T16:30:00.000+0000",
                    "rule": {
                        "level": 3,
                        "description": "Wazuh server started.",
                        "groups": ["sca"],
                        "id": "19003"
                    },
                    "data": {},
                    "agent": {"name": "wazuh.manager", "id": "000"},
                    "full_log": ""
                }
            }
        ]
    }
}


# ── Helper to build a mock HTTP response ──────────────────────────────────

def mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data
    mock.text = FAKE_TOKEN
    mock.raise_for_status = MagicMock() 
    return mock


# ── Tests ──────────────────────────────────────────────────────────────────


# patch("request.get") intercepts the real HTTP call and returns a fake response instead.
# Fake response comes from the mock object

class TestWazuhClientAuthentication:

    def test_authenticate_returns_token(self):
        """Should return a JWT token on successful authentication"""
        with patch("requests.get") as mock_get:
            mock_get.return_value = mock_response({}, 200)

            client = WazuhClient()
            token  = client._authenticate()

            assert token == FAKE_TOKEN
            assert client._token == FAKE_TOKEN  # token is cached

    def test_authenticate_caches_token(self):
        """Should not re-authenticate if token already exists"""
        with patch("requests.get") as mock_get:
            mock_get.return_value = mock_response({}, 200)

            client = WazuhClient()
            client._authenticate()
            client._authenticate()   # second call

            # The second authenticate should use the cached token 
            # Thus the mock server should be called only once
            assert mock_get.call_count == 1

    def test_authenticate_raises_on_401(self):
        """Should raise HTTPError on wrong credentials"""
        with patch("requests.get") as mock_get:
            mock        = mock_response({}, 401) # 401 error (wrong password)
            mock.raise_for_status.side_effect = Exception("401 Unauthorized")
            mock_get.return_value = mock

            client = WazuhClient()
            with pytest.raises(Exception, match="401"):
                client._authenticate()


class TestWazuhClientGetAlerts:

    def test_get_recent_alerts_returns_list(self):
        """Should return a list of alert dicts"""
        with patch("requests.get") as mock_get, \
             patch("requests.post") as mock_post:

            mock_get.return_value  = mock_response({}, 200)   # authenticate
            mock_post.return_value = mock_response(FAKE_OPENSEARCH_RESPONSE, 200)

            client        = WazuhClient()
            client._token = FAKE_TOKEN  # here authentication is skipped, as it is not the goal
            alerts        = client.get_recent_alerts(limit=2)

            assert isinstance(alerts, list) # Returned list of alerts
            assert len(alerts) == 2         # Received two alerts as limit=2

    def test_get_recent_alerts_correct_fields(self):
        """Each alert should have expected fields"""
        with patch("requests.get") as mock_get, \
             patch("requests.post") as mock_post:

            mock_get.return_value  = mock_response({}, 200)
            mock_post.return_value = mock_response(FAKE_OPENSEARCH_RESPONSE, 200)

            client        = WazuhClient()
            client._token = FAKE_TOKEN
            alerts        = client.get_recent_alerts(limit=2)

            first = alerts[0]
            # Each alert should contain these
            assert "rule"      in first
            assert "timestamp" in first
            assert "agent"     in first

    def test_get_recent_alerts_extracts_level(self):
        """Should correctly extract the rule level"""
        with patch("requests.get") as mock_get, \
             patch("requests.post") as mock_post:

            mock_get.return_value  = mock_response({}, 200)
            mock_post.return_value = mock_response(FAKE_OPENSEARCH_RESPONSE, 200)

            client        = WazuhClient()
            client._token = FAKE_TOKEN
            alerts        = client.get_recent_alerts(limit=2)

            # Wazuh level is contained
            assert alerts[0]["rule"]["level"] == 10
            assert alerts[1]["rule"]["level"] == 3

    def test_get_recent_alerts_empty_response(self):
        """Should return empty list when no alerts exist"""
        with patch("requests.get") as mock_get, \
             patch("requests.post") as mock_post:

            # Tests when the indexer has no results, so hits is empty
            mock_get.return_value  = mock_response({}, 200)
            mock_post.return_value = mock_response({"hits": {"hits": []}}, 200)

            client        = WazuhClient()
            client._token = FAKE_TOKEN
            alerts        = client.get_recent_alerts()

            assert alerts == []

    def test_get_alerts_by_agent_filters_on_agent_id(self):
        """Should query OpenSearch with an agent.id term filter."""
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response(FAKE_OPENSEARCH_RESPONSE, 200)

            client        = WazuhClient()
            client._token = FAKE_TOKEN
            alerts        = client.get_alerts_by_agent("001", limit=2)

            assert len(alerts) == 2
            sent_query = mock_post.call_args.kwargs["json"]["query"]
            assert sent_query == {"term": {"agent.id": "001"}}


# ── Agent / group management (multi-tenant) ────────────────────────────────

FAKE_AGENTS = {
    "data": {"affected_items": [
        {"id": "001", "name": "companyA-web01", "group": ["companyA"]},
        {"id": "003", "name": "companyB-fw01",  "group": ["companyB"]},
    ]}
}


class TestWazuhClientTenants:

    def test_register_agent_returns_id(self):
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response(
                {"data": {"id": "007", "key": "abc"}, "error": 0}, 200)

            client        = WazuhClient()
            client._token = FAKE_TOKEN
            assert client.register_agent("companyA-web01") == "007"

    def test_register_agent_falls_back_to_existing_name(self):
        """A duplicate-name 400 should resolve to the existing agent's id."""
        with patch("requests.post") as mock_post, \
             patch("requests.get") as mock_get:
            mock_post.return_value = mock_response({"error": 1705}, 400)
            mock_get.return_value  = mock_response(FAKE_AGENTS, 200)

            client        = WazuhClient()
            client._token = FAKE_TOKEN
            assert client.register_agent("companyB-fw01") == "003"

    def test_create_group_tolerates_existing(self):
        with patch("requests.post") as mock_post:
            mock = mock_response({"error": 1711}, 400)
            mock.text = "Group 'companyA' already exists"
            mock_post.return_value = mock

            client        = WazuhClient()
            client._token = FAKE_TOKEN
            client.create_group("companyA")  # should not raise

    def test_get_agent_group_resolves_and_caches(self):
        with patch("requests.get") as mock_get:
            mock_get.return_value = mock_response(FAKE_AGENTS, 200)

            client        = WazuhClient()
            client._token = FAKE_TOKEN
            assert client.get_agent_group("001") == "companyA"
            assert client.get_agent_group("003") == "companyB"
            # Second lookups are served from cache (one API call total).
            assert mock_get.call_count == 1


class TestSignificantAlerts:

    def test_get_significant_alerts_builds_level_filter(self):
        """Should query with a rule.level >= min_level range filter."""
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response(FAKE_OPENSEARCH_RESPONSE, 200)

            client        = WazuhClient()
            client._token = FAKE_TOKEN
            client.get_significant_alerts(min_level=7, limit=5)

            query = mock_post.call_args.kwargs["json"]["query"]
            assert query["bool"]["must"][0] == {"range": {"rule.level": {"gte": 7}}}

    def test_get_significant_alerts_require_mitre_adds_exists(self):
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response(FAKE_OPENSEARCH_RESPONSE, 200)

            client        = WazuhClient()
            client._token = FAKE_TOKEN
            client.get_significant_alerts(min_level=10, require_mitre=True)

            must = mock_post.call_args.kwargs["json"]["query"]["bool"]["must"]
            assert {"exists": {"field": "rule.mitre.id"}} in must


class TestExtractTriggerLogs:

    def test_extracts_full_log_and_previous_output(self):
        from ingestion.normalizerfixed import extract_trigger_logs

        alert = {
            "full_log": "line-A",
            "previous_output": "line-B\nline-C",
        }
        assert extract_trigger_logs(alert) == ["line-A", "line-B", "line-C"]

    def test_dedupes_and_strips_blanks(self):
        from ingestion.normalizerfixed import extract_trigger_logs

        alert = {"full_log": "dup", "previous_output": "dup\n\n  other  "}
        assert extract_trigger_logs(alert) == ["dup", "other"]

    def test_single_log_without_previous_output(self):
        from ingestion.normalizerfixed import extract_trigger_logs

        assert extract_trigger_logs({"full_log": "only"}) == ["only"]
        assert extract_trigger_logs({}) == []