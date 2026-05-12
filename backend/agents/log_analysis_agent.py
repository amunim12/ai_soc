# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ipaddress
import logging
import re
import os
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv

from schemas.alert import WazuhAlert
from schemas.analysis import AnalysisResult
from schemas.audit import StepLog
from orchestration.state import PipelineState
from infrastructure.kafka_client import kafka_producer
from infrastructure.redis_client import redis_client

load_dotenv()
log = logging.getLogger(__name__)


IP_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|cc|xyz|info|biz)\b')
MD5_RE    = re.compile(r'\b[0-9a-fA-F]{32}\b')
SHA256_RE = re.compile(r'\b[0-9a-fA-F]{64}\b')
CVE_RE    = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)


NOISE_RULES: set[int] = {100, 200, 533, 1002, 5501, 5502}
NOISE_LEVEL_THRESHOLD = 3


PRIVILEGED_USERS: set[str] = {
    "root", "administrator", "admin", "DOMAIN\\admin",
    "DOMAIN\\svc_backup", "svc_deploy", "svc_ci",
}
CROWN_JEWEL_AGENTS: set[str] = {
    "agent-002",
    "agent-007",
    "agent-006",
}


RULE_TO_MITRE: dict[int, list[str]] = {
    5763:  ["T1110"],
    5715:  ["T1078"],
    5402:  ["T1548"],
    18116: ["T1550.002"],
    31106: ["T1190"],
    59000: ["T1486"],
    18125: ["T1098"],
    22400: ["T1071"],
    91050: ["T1190"],
    92100: ["T1003"],
    31510: ["T1505.003"],
    51010: ["T1014"],
    87600: ["T1611"],
    87900: ["T1195.002"],
    87200: ["T1496"],
    55010: ["T1048"],
    40101: ["T1046"],
    18124: ["T1110.003"],
}


CATEGORY_MAP: dict[str, str] = {
    "authentication_failures": "brute_force",
    "authentication_success":  "account_takeover",
    "privilege_escalation":    "privilege_escalation",
    "lateral_movement":        "lateral_movement",
    "web_attack":              "web_attack",
    "malware":                 "malware",
    "credential_access":       "credential_theft",
    "c2":                      "command_and_control",
    "command_and_control":     "command_and_control",
    "data_exfiltration":       "data_exfiltration",
    "recon":                   "recon",
    "container_security":      "container_escape",
    "supply_chain":            "supply_chain",
}


class LogAnalysisAgent:


    async def run(self, state: PipelineState) -> PipelineState:
        alert: WazuhAlert = state["alert"]
        log.info("[LogAnalysis] Processing alert %s (rule=%s lvl=%s)",
                  alert.id, alert.rule_id, alert.rule_level)


        is_dup = await redis_client.check_dedup(alert.id)


        noise = self._is_noise(alert)


        iocs = self._extract_iocs(alert.full_log)


        mitre = self._map_to_mitre(alert.rule_id)


        correlated = await redis_client.check_burst(alert.rule_id, alert.id)


        malicious_ip = await redis_client.is_known_malicious(alert.source_ip or "")
        score = self._rescore(alert, malicious_ip)


        criticality = self._get_asset_criticality(alert.agent_id)


        category = self._categorise(alert)

        result = AnalysisResult(
            alert_id=alert.id,
            is_duplicate=is_dup,
            noise_filtered=noise,
            adjusted_score=score,
            mitre_techniques=mitre,
            correlated_alert_ids=correlated,
            is_burst=len(correlated) >= 2,
            iocs=iocs,
            has_iocs=bool(iocs),
            asset_criticality=criticality,
            alert_category=category,
        )

        await kafka_producer.send("wazuh.analysed", result)

        state["analysis"] = result
        state["pipeline_stage"] = "analysis_complete"
        state.setdefault("audit_trail", []).append(
            StepLog(
                agent="log_analysis",
                result={
                    "noise_filtered": noise,
                    "is_duplicate": is_dup,
                    "has_iocs": bool(iocs),
                    "adjusted_score": score,
                    "mitre_techniques": mitre,
                },
                ts=datetime.utcnow(),
            )
        )
        log.info("[LogAnalysis] Done — noise=%s iocs=%d mitre=%s",
                  noise, len(iocs), mitre)
        return state


    def _is_noise(self, alert: WazuhAlert) -> bool:
        return alert.rule_level < NOISE_LEVEL_THRESHOLD or alert.rule_id in NOISE_RULES

    def _rescore(self, alert: WazuhAlert, is_known_malicious: bool = False) -> int:
        base = alert.rule_level * 10


        if alert.user:
            user_bare = alert.user.split("\\")[-1]
            if alert.user in PRIVILEGED_USERS or user_bare in PRIVILEGED_USERS:
                base += 15

        if alert.agent_id in CROWN_JEWEL_AGENTS:
            base += 25

        if is_known_malicious:
            base += 20
        return min(base, 150)

    def _map_to_mitre(self, rule_id: int) -> list[str]:
        return RULE_TO_MITRE.get(rule_id, [])

    def _extract_iocs(self, full_log: str) -> list[str]:
        patterns = [IP_RE, DOMAIN_RE, MD5_RE, SHA256_RE, CVE_RE]
        found: set[str] = set()
        for pattern in patterns:
            found.update(re.findall(pattern, full_log))

        filtered = {
            ioc for ioc in found
            if not _is_private_ip(ioc)
        }
        return sorted(filtered)

    def _get_asset_criticality(self, agent_id: str) -> str:
        if agent_id in CROWN_JEWEL_AGENTS:
            return "CROWN_JEWEL"

        high_agents = os.getenv("HIGH_CRITICALITY_AGENTS", "").split(",")
        if agent_id in high_agents:
            return "HIGH"
        medium_agents = os.getenv("MEDIUM_CRITICALITY_AGENTS", "").split(",")
        if agent_id in medium_agents:
            return "MEDIUM"
        return "LOW"

    def _categorise(self, alert: WazuhAlert) -> str:
        raw_cat = alert.alert_category.lower()

        if raw_cat in CATEGORY_MAP:
            return CATEGORY_MAP[raw_cat]

        for group in alert.rule_groups:
            if group in CATEGORY_MAP:
                return CATEGORY_MAP[group]
        return "generic"


def _is_private_ip(token: str) -> bool:
    """
    Return True if token is a private/loopback/reserved IP.
    BUG FIX: the old prefix-string approach used a hand-rolled list that
    missed some 172.16–172.31 addresses and did not handle edge cases.
    Use the stdlib ipaddress module which is authoritative.
    """
    try:
        addr = ipaddress.ip_address(token)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


log_analysis_agent = LogAnalysisAgent()
