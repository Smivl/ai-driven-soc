
# tests/ingestion/test_store_events.py
"""
Tests for WazuhClient — uses mocking so no real server needed

Tests the storing of events

Run from project root:
    pytest tests/ingestion/test_store_events.py -v
"""
import pytest
from unittest.mock import patch, MagicMock
import sys
import os
sys.path.insert(0, os.path.abspath("."))

from backend.ingestion.wazuh_client import WazuhClient
from backend.log_evaluation.soc_event import SOCevent, Scoring, PipelineStatus

# ── Fake data that mimics real OpenSearch responses and Events  ────────────────────────

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


FAKE_SOC_EVENT = SOCevent(
    source_ip      = "192.168.1.42",
    destination_ip = "10.0.0.1",
    port           = 22,
    user           = "admin",
    event_type     = "ssh_brute_force",
    timestamp      = "2026-03-23T16:31:28.689+0000",
    raw_log        = "Failed password for admin from 192.168.1.42 port 22 ssh2",
    wazuh_level    = Scoring.SUSPICIOUS,
    rule_id        = "5712",
    status         = PipelineStatus.NORMALIZED,
)

FAKE_DOC_ID = "a1b2c3d4-0000-0000-0000-000000000000"

# Mimics what OpenSearch returns when you GET a stored SOCevent
FAKE_OPENSEARCH_SOC_SOURCE = {
    "source_ip":      "192.168.1.42",
    "destination_ip": "10.0.0.1",
    "port":           22,
    "user":           "admin",
    "event_type":     "ssh_brute_force",
    "timestamp":      "2026-03-23T16:31:28.689+0000",
    "raw_log":        "Failed password for admin from 192.168.1.42 port 22 ssh2",
    "wazuh_level":    "suspicious",
    "rule_id":        "5712",
    "severity":       None,
    "label":          None,
    "explanation":    None,
    "status":         "normalized",
}

FAKE_OPENSEARCH_SOC_GET = {
    "_id":     FAKE_DOC_ID,
    "_source": FAKE_OPENSEARCH_SOC_SOURCE,
}

FAKE_OPENSEARCH_SOC_SEARCH = {
    "hits": {
        "hits": [
            {"_source": FAKE_OPENSEARCH_SOC_SOURCE},
            {"_source": {**FAKE_OPENSEARCH_SOC_SOURCE, "source_ip": "10.10.10.10"}},
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

class TestStoreSocEvent:

    def test_store_returns_doc_id(self):
        """Should return a non-empty string doc ID"""
        with patch("requests.put") as mock_put:
            mock_put.return_value = mock_response({"result": "created"}, 200)

            client  = WazuhClient()
            doc_id  = client.store_soc_event(FAKE_SOC_EVENT)

            assert isinstance(doc_id, str)
            assert len(doc_id) > 0

    def test_store_uses_custom_doc_id(self):
        """Should use the provided doc_id instead of generating one"""
        with patch("requests.put") as mock_put:
            mock_put.return_value = mock_response({"result": "created"}, 200)

            client = WazuhClient()
            doc_id = client.store_soc_event(FAKE_SOC_EVENT, doc_id=FAKE_DOC_ID)

            assert doc_id == FAKE_DOC_ID
            # Check the URL contained the doc ID
            called_url = mock_put.call_args[0][0]
            assert FAKE_DOC_ID in called_url

    def test_store_serializes_enums(self):
        """Enums should be stored as their string values, not as Enum objects"""
        with patch("requests.put") as mock_put:
            mock_put.return_value = mock_response({"result": "created"}, 200)

            client = WazuhClient()
            client.store_soc_event(FAKE_SOC_EVENT, doc_id=FAKE_DOC_ID)

            payload = mock_put.call_args[1]["json"]
            assert payload["wazuh_level"] == "suspicious"  # not Scoring.SUSPICIOUS
            assert payload["status"]      == "normalized"  # not PipelineStatus.NORMALIZED

    def test_store_raises_on_server_error(self):
        """Should raise if OpenSearch returns an error"""
        with patch("requests.put") as mock_put:
            mock        = mock_response({}, 500)
            mock.raise_for_status.side_effect = Exception("500 Server Error")
            mock_put.return_value = mock

            client = WazuhClient()
            with pytest.raises(Exception, match="500"):
                client.store_soc_event(FAKE_SOC_EVENT)


class TestGetSocEvent:

    def test_get_returns_soc_event_instance(self):
        """Should deserialize the OpenSearch response into a SOCevent"""
        with patch("requests.get") as mock_get:
            mock_get.return_value = mock_response(FAKE_OPENSEARCH_SOC_GET, 200)

            client = WazuhClient()
            event  = client.get_soc_event(FAKE_DOC_ID)

            assert isinstance(event, SOCevent)

    def test_get_deserializes_fields_correctly(self):
        """Fields should match what was stored"""
        with patch("requests.get") as mock_get:
            mock_get.return_value = mock_response(FAKE_OPENSEARCH_SOC_GET, 200)

            client = WazuhClient()
            event  = client.get_soc_event(FAKE_DOC_ID)

            assert event.source_ip   == "192.168.1.42"
            assert event.port        == 22
            assert event.rule_id     == "5712"

    def test_get_deserializes_enums(self):
        """String values from OpenSearch should be converted back to Enum members"""
        with patch("requests.get") as mock_get:
            mock_get.return_value = mock_response(FAKE_OPENSEARCH_SOC_GET, 200)

            client = WazuhClient()
            event  = client.get_soc_event(FAKE_DOC_ID)

            assert event.wazuh_level == Scoring.SUSPICIOUS
            assert event.status      == PipelineStatus.NORMALIZED

    def test_get_raises_on_not_found(self):
        """Should raise if the document does not exist"""
        with patch("requests.get") as mock_get:
            mock        = mock_response({}, 404)
            mock.raise_for_status.side_effect = Exception("404 Not Found")
            mock_get.return_value = mock

            client = WazuhClient()
            with pytest.raises(Exception, match="404"):
                client.get_soc_event("nonexistent-id")


class TestSearchSocEvents:

    def test_search_returns_list_of_soc_events(self):
        """Should return a list of SOCevent instances"""
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response(FAKE_OPENSEARCH_SOC_SEARCH, 200)

            client = WazuhClient()
            events = client.search_soc_events()

            assert isinstance(events, list)
            assert all(isinstance(e, SOCevent) for e in events)

    def test_search_filters_by_status(self):
        """Should include status filter in the query when provided"""
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response(FAKE_OPENSEARCH_SOC_SEARCH, 200)

            client = WazuhClient()
            client.search_soc_events(status=PipelineStatus.NORMALIZED)

            query = mock_post.call_args[1]["json"]["query"]
            filters = query["bool"]["filter"]
            assert {"term": {"status": "normalized"}} in filters

    def test_search_filters_by_scoring(self):
        """Should include wazuh_level filter in the query when provided"""
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response(FAKE_OPENSEARCH_SOC_SEARCH, 200)

            client = WazuhClient()
            client.search_soc_events(scoring=Scoring.SUSPICIOUS)

            query = mock_post.call_args[1]["json"]["query"]
            filters = query["bool"]["filter"]
            assert {"term": {"wazuh_level": "suspicious"}} in filters

    def test_search_no_filters_uses_match_all(self):
        """Should use match_all query when no filters are given"""
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response(FAKE_OPENSEARCH_SOC_SEARCH, 200)

            client = WazuhClient()
            client.search_soc_events()

            query = mock_post.call_args[1]["json"]["query"]
            assert query == {"match_all": {}}

    def test_search_empty_results(self):
        """Should return empty list when no documents match"""
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response({"hits": {"hits": []}}, 200)

            client = WazuhClient()
            events = client.search_soc_events(status=PipelineStatus.PENDING)

            assert events == []


class TestUpdateSocEvent:

    def test_update_patches_status_and_fields(self):
        """Should send status plus extra fields in the doc patch"""
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response({"result": "updated"}, 200)

            client = WazuhClient()
            client.update_soc_event(FAKE_DOC_ID, PipelineStatus.SCORED,
                severity=82, label="brute_force")

            patch_body = mock_post.call_args[1]["json"]["doc"]
            assert patch_body["status"]   == "scored"
            assert patch_body["severity"] == 82
            assert patch_body["label"]    == "brute_force"

    def test_update_status_only(self):
        """Should work with just a status change and no extra fields"""
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response({"result": "updated"}, 200)

            client = WazuhClient()
            client.update_soc_event(FAKE_DOC_ID, PipelineStatus.RESOLVED)

            patch_body = mock_post.call_args[1]["json"]["doc"]
            assert patch_body == {"status": "resolved"}

    def test_update_serializes_enum_fields(self):
        """Enum values passed as kwargs should be serialized to strings"""
        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_response({"result": "updated"}, 200)

            client = WazuhClient()
            client.update_soc_event(FAKE_DOC_ID, PipelineStatus.SCORED,
                wazuh_level=Scoring.MALICIOUS)

            patch_body = mock_post.call_args[1]["json"]["doc"]
            assert patch_body["wazuh_level"] == "malicious"  # not Scoring.MALICIOUS

    def test_update_raises_on_server_error(self):
        """Should raise if OpenSearch returns an error"""
        with patch("requests.post") as mock_post:
            mock        = mock_response({}, 500)
            mock.raise_for_status.side_effect = Exception("500 Server Error")
            mock_post.return_value = mock

            client = WazuhClient()
            with pytest.raises(Exception, match="500"):
                client.update_soc_event(FAKE_DOC_ID, PipelineStatus.SCORED)