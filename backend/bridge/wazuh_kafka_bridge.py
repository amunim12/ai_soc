# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Wazuh → Kafka Bridge

Polls the Wazuh REST API for new alerts and publishes them to
the `wazuh.raw` Kafka topic.

Usage:
  python -m bridge.wazuh_kafka_bridge

Requires env vars:
  WAZUH_API_URL, WAZUH_USER, WAZUH_PASSWORD,
  KAFKA_BOOTSTRAP_SERVERS
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta
from typing import Optional

import httpx
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential

from config.settings import settings as _settings
from schemas.alert import WazuhAlert
from infrastructure.kafka_client import kafka_producer

load_dotenv()
log = logging.getLogger(__name__)

WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "changeme")
WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"
POLL_INTERVAL_SECONDS = _settings.WAZUH_POLL_INTERVAL
BATCH_SIZE            = _settings.WAZUH_BATCH_SIZE
TOPIC_RAW = "wazuh.raw"


SEVERITY_MAP = {
    range(0, 4): "LOW",
    range(4, 7): "MEDIUM",
    range(7, 12): "HIGH",
    range(12, 16): "CRITICAL",
}


def _rule_level_to_severity(level: int) -> str:
    for r, sev in SEVERITY_MAP.items():
        if level in r:
            return sev
    return "MEDIUM"


class WazuhKafkaBridge:
    """
    Continuously polls Wazuh REST API and publishes alerts to Kafka.
    """

    def __init__(self):
        self._token: Optional[str] = None
        self._token_expiry: datetime = datetime.utcnow()
        self._seen_ids: set[str] = set()
        self._client = httpx.AsyncClient(verify=WAZUH_VERIFY_SSL, timeout=30)


    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def _refresh_token(self) -> None:
        url = f"{WAZUH_API_URL}/security/user/authenticate"
        resp = await self._client.post(
            url, auth=(WAZUH_USER, WAZUH_PASSWORD)
        )
        resp.raise_for_status()
        self._token = resp.json()["data"]["token"]
        self._token_expiry = datetime.utcnow() + timedelta(minutes=14)
        log.info("Wazuh token refreshed")

    async def _get_token(self) -> str:
        if not self._token or datetime.utcnow() >= self._token_expiry:
            await self._refresh_token()
        return self._token  # type: ignore


    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=5))
    async def _fetch_alerts(self, offset: int = 0) -> list[dict]:
        """
        Fetch alerts from the Wazuh Indexer (OpenSearch) via the events API.
        Wazuh 4.x stores alerts in OpenSearch — the REST API /alerts endpoint
        was removed in v4.x. We query the indexer directly.
        """
        token = await self._get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        body = {
            "query": {"match_all": {}},
            "size": BATCH_SIZE,
            "from": offset,
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        resp = await self._client.post(
            f"{WAZUH_API_URL}/events/feed",
            headers=headers,
            json=body,
        )
        if resp.status_code == 404 or resp.status_code == 405:

            return await self._fetch_alerts_from_indexer(offset)
        resp.raise_for_status()
        hits = resp.json().get("data", {}).get("hits", {}).get("hits", [])
        return [h.get("_source", h) for h in hits]

    async def _fetch_alerts_from_indexer(self, offset: int = 0) -> list[dict]:
        """Fallback: query OpenSearch wazuh-alerts-* index directly."""
        indexer_url = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
        indexer_user = os.getenv("WAZUH_INDEXER_USER", "admin")
        indexer_pass = os.getenv("WAZUH_INDEXER_PASSWORD", os.getenv("WAZUH_PASSWORD", "changeme"))
        body = {
            "query": {"match_all": {}},
            "size": BATCH_SIZE,
            "from": offset,
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        resp = await self._client.post(
            f"{indexer_url}/wazuh-alerts-*/_search",
            auth=(indexer_user, indexer_pass),
            json=body,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])

        return [h.get("_source", {}) for h in hits]

    def _parse_alert(self, raw: dict) -> Optional[WazuhAlert]:
        """Convert Wazuh API alert dict → WazuhAlert schema."""
        if "rule" not in raw:
            return None
        try:
            rule = raw["rule"]
            agent = raw.get("agent", {})
            data = raw.get("data", {})

            rule_level = int(rule.get("level", 0))
            severity = _rule_level_to_severity(rule_level)
            rule_groups = rule.get("groups", [])
            alert_category = rule_groups[0] if rule_groups else "generic"

            return WazuhAlert(
                id=raw.get("id", ""),
                timestamp=datetime.fromisoformat(
                    raw.get("timestamp", datetime.utcnow().isoformat()).replace("Z", "+00:00")
                ),
                agent_id=agent.get("id", "unknown"),
                agent_name=agent.get("name"),
                source_ip=data.get("srcip") or data.get("win", {}).get("eventdata", {}).get("ipAddress"),
                rule_id=int(rule.get("id", 0)),
                rule_level=rule_level,
                rule_description=rule.get("description", ""),
                rule_groups=rule_groups,
                severity=severity,
                alert_category=alert_category,
                full_log=raw.get("full_log", ""),
                location=raw.get("location"),
                manager_name=raw.get("manager", {}).get("name"),
            )
        except Exception as exc:
            log.warning("Failed to parse alert %s: %s", raw.get("id"), exc)
            return None


    async def run(self) -> None:
        log.info("Wazuh→Kafka bridge starting (poll interval=%ss)", POLL_INTERVAL_SECONDS)
        while True:
            try:
                raw_alerts = await self._fetch_alerts()
                new_count = 0
                for raw in raw_alerts:
                    alert_id = raw.get("id", "")
                    if alert_id in self._seen_ids:
                        continue
                    alert = self._parse_alert(raw)
                    if alert:
                        await kafka_producer.send(TOPIC_RAW, alert, key=alert.agent_id)
                        self._seen_ids.add(alert_id)
                        new_count += 1

                if new_count:
                    log.info("Published %d new alerts → %s", new_count, TOPIC_RAW)


                if len(self._seen_ids) > 10_000:
                    self._seen_ids = set(list(self._seen_ids)[-5_000:])

            except Exception as exc:
                log.error("Bridge polling error: %s", exc)

            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    async def close(self) -> None:
        await self._client.aclose()
        kafka_producer.flush()


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    bridge = WazuhKafkaBridge()
    try:
        await bridge.run()
    finally:
        await bridge.close()


if __name__ == "__main__":
    asyncio.run(main())
