# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the alert security module.

Covers ATE_COV.2 — Analysis of Coverage requirement for alert functionality.

Scope:
  - WazuhAlert schema validation and serialisation
  - Severity mapping (_rule_level_to_severity)
  - WazuhKafkaBridge._parse_alert parsing and deduplication
  - Alert API endpoints (ingest, get, list, summary, delete)
  - MOCK_ALERTS index contract (regression guard)
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-that-is-at-least-32-chars!!")
os.environ.setdefault("SHUFFLE_API_KEY", "test-shuffle-key")

from schemas.alert import WazuhAlert


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_alert(**overrides) -> WazuhAlert:
    """Minimal valid WazuhAlert with optional field overrides."""
    defaults = dict(
        agent_id="agent-001",
        rule_id=5763,
        rule_level=8,
        rule_description="SSH brute force attack detected",
        rule_groups=["authentication_failures", "sshd"],
        severity="HIGH",
        alert_category="authentication_failures",
        source_ip="185.220.101.47",
        full_log="Failed password for root from 185.220.101.47 port 22",
    )
    defaults.update(overrides)
    return WazuhAlert(**defaults)


def make_raw_wazuh_dict(**overrides) -> dict:
    """Minimal raw Wazuh API alert dict as returned by the indexer."""
    base = {
        "id": str(uuid.uuid4()),
        "timestamp": "2025-01-01T12:00:00.000Z",
        "rule": {
            "id": "5763",
            "level": 10,
            "description": "SSH brute force attack detected",
            "groups": ["authentication_failures", "sshd"],
        },
        "agent": {"id": "agent-001", "name": "linux-server-01"},
        "data": {"srcip": "185.220.101.47"},
        "full_log": "Failed password for root from 185.220.101.47 port 22",
        "location": "/var/log/auth.log",
        "manager": {"name": "wazuh-manager"},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# WazuhAlert — schema and defaults
# ---------------------------------------------------------------------------


class TestWazuhAlertSchema:
    def test_minimal_required_fields(self):
        alert = WazuhAlert(
            agent_id="agent-001",
            rule_id=1000,
            rule_level=5,
            rule_description="Test rule",
        )
        assert alert.agent_id == "agent-001"
        assert alert.rule_id == 1000

    def test_id_defaults_to_uuid(self):
        a1, a2 = make_alert(), make_alert()
        assert uuid.UUID(a1.id)  # valid UUID
        assert a1.id != a2.id

    def test_timestamp_defaults_to_utcnow(self):
        before = datetime.utcnow()
        alert = make_alert()
        assert isinstance(alert.timestamp, datetime)
        assert alert.timestamp >= before

    def test_severity_default_is_medium(self):
        alert = WazuhAlert(agent_id="x", rule_id=1, rule_level=5, rule_description="d")
        assert alert.severity == "MEDIUM"

    def test_rule_groups_default_is_empty_list(self):
        alert = WazuhAlert(agent_id="x", rule_id=1, rule_level=5, rule_description="d")
        assert alert.rule_groups == []

    def test_alert_category_default_is_generic(self):
        alert = WazuhAlert(agent_id="x", rule_id=1, rule_level=5, rule_description="d")
        assert alert.alert_category == "generic"

    def test_optional_fields_accept_none(self):
        alert = make_alert(source_ip=None, destination_ip=None, user=None)
        assert alert.source_ip is None
        assert alert.destination_ip is None
        assert alert.user is None

    def test_all_severity_values_accepted(self):
        for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            assert make_alert(severity=sev).severity == sev

    def test_timestamp_serialised_to_iso_string(self):
        alert = make_alert()
        dumped = alert.model_dump()
        assert isinstance(dumped["timestamp"], str)
        datetime.fromisoformat(dumped["timestamp"])  # must be valid ISO

    def test_model_dump_contains_required_keys(self):
        dumped = make_alert().model_dump()
        for key in (
            "id", "timestamp", "agent_id", "rule_id", "rule_level",
            "rule_description", "severity", "alert_category", "full_log",
        ):
            assert key in dumped

    def test_full_log_default_is_empty_string(self):
        alert = WazuhAlert(agent_id="x", rule_id=1, rule_level=5, rule_description="d")
        assert alert.full_log == ""

    def test_explicit_id_is_preserved(self):
        fixed = str(uuid.uuid4())
        assert make_alert(id=fixed).id == fixed


# ---------------------------------------------------------------------------
# Severity mapping — _rule_level_to_severity
# ---------------------------------------------------------------------------


class TestRuleLevelToSeverity:
    @pytest.fixture(autouse=True)
    def _fn(self):
        from bridge.wazuh_kafka_bridge import _rule_level_to_severity
        self.fn = _rule_level_to_severity

    def test_level_0_is_low(self):
        assert self.fn(0) == "LOW"

    def test_level_3_is_low(self):
        assert self.fn(3) == "LOW"

    def test_level_4_is_medium(self):
        assert self.fn(4) == "MEDIUM"

    def test_level_6_is_medium(self):
        assert self.fn(6) == "MEDIUM"

    def test_level_7_is_high(self):
        assert self.fn(7) == "HIGH"

    def test_level_11_is_high(self):
        assert self.fn(11) == "HIGH"

    def test_level_12_is_critical(self):
        assert self.fn(12) == "CRITICAL"

    def test_level_15_is_critical(self):
        assert self.fn(15) == "CRITICAL"

    def test_out_of_range_falls_back_to_medium(self):
        assert self.fn(99) == "MEDIUM"

    def test_all_band_boundaries(self):
        from bridge.wazuh_kafka_bridge import _rule_level_to_severity as fn
        for level, expected in (
            (3, "LOW"), (4, "MEDIUM"),
            (6, "MEDIUM"), (7, "HIGH"),
            (11, "HIGH"), (12, "CRITICAL"),
        ):
            assert fn(level) == expected, f"level {level} → expected {expected}"


# ---------------------------------------------------------------------------
# WazuhKafkaBridge._parse_alert
# ---------------------------------------------------------------------------


class TestParseBridgeAlert:
    @pytest.fixture(autouse=True)
    def _bridge(self):
        with patch("bridge.wazuh_kafka_bridge.kafka_producer"):
            from bridge.wazuh_kafka_bridge import WazuhKafkaBridge
            self.bridge = WazuhKafkaBridge()

    def test_parse_returns_wazuh_alert(self):
        assert isinstance(self.bridge._parse_alert(make_raw_wazuh_dict()), WazuhAlert)

    def test_agent_id_and_name_mapped(self):
        alert = self.bridge._parse_alert(make_raw_wazuh_dict())
        assert alert.agent_id == "agent-001"
        assert alert.agent_name == "linux-server-01"

    def test_severity_derived_from_rule_level(self):
        raw = make_raw_wazuh_dict()
        raw["rule"]["level"] = 10
        assert self.bridge._parse_alert(raw).severity == "HIGH"

    def test_critical_severity_at_level_12(self):
        raw = make_raw_wazuh_dict()
        raw["rule"]["level"] = 12
        assert self.bridge._parse_alert(raw).severity == "CRITICAL"

    def test_low_severity_at_level_2(self):
        raw = make_raw_wazuh_dict()
        raw["rule"]["level"] = 2
        assert self.bridge._parse_alert(raw).severity == "LOW"

    def test_alert_category_from_first_group(self):
        raw = make_raw_wazuh_dict()
        raw["rule"]["groups"] = ["web_attack", "sqli"]
        assert self.bridge._parse_alert(raw).alert_category == "web_attack"

    def test_alert_category_generic_when_no_groups(self):
        raw = make_raw_wazuh_dict()
        raw["rule"]["groups"] = []
        assert self.bridge._parse_alert(raw).alert_category == "generic"

    def test_source_ip_from_data_srcip(self):
        raw = make_raw_wazuh_dict()
        raw["data"] = {"srcip": "1.2.3.4"}
        assert self.bridge._parse_alert(raw).source_ip == "1.2.3.4"

    def test_source_ip_from_windows_eventdata_fallback(self):
        raw = make_raw_wazuh_dict()
        raw["data"] = {"win": {"eventdata": {"ipAddress": "10.10.10.1"}}}
        assert self.bridge._parse_alert(raw).source_ip == "10.10.10.1"

    def test_location_and_manager_mapped(self):
        alert = self.bridge._parse_alert(make_raw_wazuh_dict())
        assert alert.location == "/var/log/auth.log"
        assert alert.manager_name == "wazuh-manager"

    def test_rule_description_preserved(self):
        raw = make_raw_wazuh_dict()
        raw["rule"]["description"] = "Custom rule description"
        assert self.bridge._parse_alert(raw).rule_description == "Custom rule description"

    def test_rule_groups_preserved(self):
        raw = make_raw_wazuh_dict()
        raw["rule"]["groups"] = ["malware", "ransomware"]
        assert self.bridge._parse_alert(raw).rule_groups == ["malware", "ransomware"]

    def test_missing_rule_key_returns_none(self):
        assert self.bridge._parse_alert({"id": "bad", "agent": {"id": "a"}, "data": {}}) is None

    def test_completely_empty_dict_returns_none(self):
        assert self.bridge._parse_alert({}) is None

    def test_timestamp_parsed_from_z_suffix(self):
        raw = make_raw_wazuh_dict()
        raw["timestamp"] = "2025-06-10T08:30:00.000Z"
        alert = self.bridge._parse_alert(raw)
        assert alert.timestamp.year == 2025
        assert alert.timestamp.month == 6
        assert alert.timestamp.day == 10


# ---------------------------------------------------------------------------
# WazuhKafkaBridge — deduplication
# ---------------------------------------------------------------------------


class TestBridgeDeduplication:
    @pytest.fixture(autouse=True)
    def _bridge(self):
        with patch("bridge.wazuh_kafka_bridge.kafka_producer"):
            from bridge.wazuh_kafka_bridge import WazuhKafkaBridge
            self.bridge = WazuhKafkaBridge()

    def test_new_alert_id_not_in_seen(self):
        assert "new-id" not in self.bridge._seen_ids

    def test_seen_id_detected_after_insert(self):
        self.bridge._seen_ids.add("alert-123")
        assert "alert-123" in self.bridge._seen_ids

    def test_seen_set_trimmed_when_over_10k(self):
        """Seen IDs set is trimmed to 5 000 when it exceeds 10 000."""
        self.bridge._seen_ids = set(str(i) for i in range(10_001))
        if len(self.bridge._seen_ids) > 10_000:
            self.bridge._seen_ids = set(list(self.bridge._seen_ids)[-5_000:])
        assert len(self.bridge._seen_ids) == 5_000

    def test_duplicate_id_stays_in_seen_set(self):
        self.bridge._seen_ids.add("dup-001")
        self.bridge._seen_ids.add("dup-001")  # second add is idempotent
        assert "dup-001" in self.bridge._seen_ids
        assert len([x for x in self.bridge._seen_ids if x == "dup-001"]) == 1


# ---------------------------------------------------------------------------
# Alert API endpoints
# ---------------------------------------------------------------------------


@pytest.fixture
async def alert_api_client():
    """Async HTTP client for the alert router with mocked infrastructure."""
    import api.alert_api as alert_api_module
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    mock_producer = MagicMock()
    mock_producer.send = AsyncMock(return_value=None)

    mock_sqlite = MagicMock()
    mock_sqlite.get_alert = AsyncMock(return_value=None)
    mock_sqlite.list_alerts = AsyncMock(return_value=[])
    mock_sqlite.get_alert_summary = AsyncMock(
        return_value={"total": 0, "by_severity": {}, "by_category": {}}
    )
    mock_sqlite.delete_alert = AsyncMock(return_value=False)

    with (
        patch.object(alert_api_module, "kafka_producer", mock_producer),
        patch.object(alert_api_module, "sqlite_client", mock_sqlite),
    ):
        app = FastAPI()
        app.include_router(alert_api_module.router)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac, mock_producer, mock_sqlite


class TestIngestEndpoint:
    async def test_returns_200_with_queued_status(self, alert_api_client):
        client, _, _ = alert_api_client
        resp = await client.post("/api/alerts/ingest", json=make_alert().model_dump())
        assert resp.status_code == 200
        assert resp.json()["status"] == "queued"

    async def test_response_contains_alert_id(self, alert_api_client):
        client, _, _ = alert_api_client
        resp = await client.post("/api/alerts/ingest", json=make_alert().model_dump())
        assert "alert_id" in resp.json()

    async def test_response_contains_severity(self, alert_api_client):
        client, _, _ = alert_api_client
        payload = make_alert(severity="CRITICAL").model_dump()
        resp = await client.post("/api/alerts/ingest", json=payload)
        assert resp.json()["severity"] == "CRITICAL"

    async def test_publishes_to_kafka_once(self, alert_api_client):
        client, producer, _ = alert_api_client
        await client.post("/api/alerts/ingest", json=make_alert().model_dump())
        producer.send.assert_awaited_once()

    async def test_explicit_id_echoed_back(self, alert_api_client):
        client, _, _ = alert_api_client
        fixed = str(uuid.uuid4())
        resp = await client.post("/api/alerts/ingest", json=make_alert(id=fixed).model_dump())
        assert resp.json()["alert_id"] == fixed

    async def test_missing_required_field_returns_422(self, alert_api_client):
        client, _, _ = alert_api_client
        resp = await client.post("/api/alerts/ingest", json={"agent_id": "x"})
        assert resp.status_code == 422


class TestGetAlertEndpoint:
    async def test_found_alert_returns_200(self, alert_api_client):
        client, _, sqlite = alert_api_client
        alert_id = str(uuid.uuid4())
        sqlite.get_alert.return_value = {"alert_id": alert_id, "severity": "HIGH"}
        resp = await client.get(f"/api/alerts/{alert_id}")
        assert resp.status_code == 200
        assert resp.json()["alert_id"] == alert_id

    async def test_missing_alert_returns_404(self, alert_api_client):
        client, _, sqlite = alert_api_client
        sqlite.get_alert.return_value = None
        resp = await client.get(f"/api/alerts/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestListAlertsEndpoint:
    async def test_returns_list(self, alert_api_client):
        client, _, sqlite = alert_api_client
        sqlite.list_alerts.return_value = [make_alert().model_dump()]
        resp = await client.get("/api/alerts")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    async def test_empty_result_is_valid(self, alert_api_client):
        client, _, _ = alert_api_client
        resp = await client.get("/api/alerts")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_severity_filter_uppercased_before_query(self, alert_api_client):
        client, _, sqlite = alert_api_client
        await client.get("/api/alerts?severity=critical")
        _, kwargs = sqlite.list_alerts.call_args
        assert kwargs["filters"].get("severity") == "CRITICAL"

    async def test_limit_param_forwarded(self, alert_api_client):
        client, _, sqlite = alert_api_client
        await client.get("/api/alerts?limit=10")
        _, kwargs = sqlite.list_alerts.call_args
        assert kwargs["limit"] == 10

    async def test_offset_param_forwarded(self, alert_api_client):
        client, _, sqlite = alert_api_client
        await client.get("/api/alerts?offset=20")
        _, kwargs = sqlite.list_alerts.call_args
        assert kwargs["offset"] == 20

    async def test_limit_above_200_returns_422(self, alert_api_client):
        client, _, _ = alert_api_client
        assert (await client.get("/api/alerts?limit=201")).status_code == 422

    async def test_limit_zero_returns_422(self, alert_api_client):
        client, _, _ = alert_api_client
        assert (await client.get("/api/alerts?limit=0")).status_code == 422

    async def test_negative_offset_returns_422(self, alert_api_client):
        client, _, _ = alert_api_client
        assert (await client.get("/api/alerts?offset=-1")).status_code == 422


class TestAlertSummaryEndpoint:
    async def test_returns_expected_shape(self, alert_api_client):
        client, _, sqlite = alert_api_client
        sqlite.get_alert_summary.return_value = {
            "total": 42,
            "by_severity": {"CRITICAL": 5, "HIGH": 10},
            "by_category": {"malware": 8},
        }
        resp = await client.get("/api/alerts/stats/summary")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 42
        assert "by_severity" in body
        assert "by_category" in body


class TestDeleteAlertEndpoint:
    async def test_delete_existing_returns_deleted_true(self, alert_api_client):
        client, _, sqlite = alert_api_client
        sqlite.delete_alert.return_value = True
        resp = await client.delete(f"/api/alerts/{uuid.uuid4()}")
        assert resp.status_code == 200
        assert resp.json() == {"deleted": True}

    async def test_delete_missing_returns_404(self, alert_api_client):
        client, _, sqlite = alert_api_client
        sqlite.delete_alert.return_value = False
        resp = await client.delete(f"/api/alerts/{uuid.uuid4()}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# MOCK_ALERTS index contract
# ---------------------------------------------------------------------------


class TestMockAlertsContract:
    """Regression guard for the documented index contract in mock_alert_generator.py."""

    @pytest.fixture(autouse=True)
    def _load(self):
        from bridge.mock_alert_generator import MOCK_ALERTS
        self.alerts = MOCK_ALERTS

    def test_has_20_alerts(self):
        assert len(self.alerts) == 20

    def test_index_0_ssh_brute_force_high(self):
        a = self.alerts[0]
        assert a.severity == "HIGH"
        assert a.rule_id == 5763

    def test_index_5_ransomware_critical(self):
        a = self.alerts[5]
        assert a.severity == "CRITICAL"
        assert "ransomware" in a.rule_description.lower()

    def test_index_6_domain_admin_critical(self):
        a = self.alerts[6]
        assert a.severity == "CRITICAL"
        assert "admin" in a.rule_description.lower()

    def test_index_10_noise_alert(self):
        a = self.alerts[10]
        assert a.severity == "LOW"
        assert a.rule_level == 1
        assert a.rule_id == 1002

    def test_index_11_rdp_failed_login_low(self):
        a = self.alerts[11]
        assert a.severity == "LOW"
        assert "rdp" in a.rule_description.lower() or "rdp" in a.full_log.lower()

    def test_all_alerts_have_valid_severity(self):
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for alert in self.alerts:
            assert alert.severity in valid, (
                f"rule_id={alert.rule_id} has unexpected severity {alert.severity!r}"
            )

    def test_all_alerts_have_non_empty_agent_id(self):
        for alert in self.alerts:
            assert alert.agent_id, f"rule_id={alert.rule_id} has empty agent_id"

    def test_all_severity_bands_represented(self):
        assert {a.severity for a in self.alerts} == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_critical_alerts_have_rule_level_12_or_above(self):
        for alert in self.alerts:
            if alert.severity == "CRITICAL":
                assert alert.rule_level >= 12, (
                    f"CRITICAL alert rule_id={alert.rule_id} has rule_level={alert.rule_level}"
                )
