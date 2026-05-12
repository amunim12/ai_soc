# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Threat Intelligence Agent — Agent 2

Called by supervisor after log analysis when IOCs are present.
Enriches the alert using six TI sources in parallel.
Computes a composite threat score and populates TIEnrichment.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from schemas.enrichment import TIEnrichment
from schemas.audit import StepLog
from orchestration.state import PipelineState
from infrastructure.kafka_client import kafka_producer
from infrastructure.redis_client import redis_client
from integrations.ti_adapters import (
    virustotal_lookup,
    misp_lookup,
    otx_lookup,
    shodan_lookup,
    nvd_lookup,
    geoip_lookup,
)

log = logging.getLogger(__name__)


class ThreatIntelAgent:

    async def run(self, state: PipelineState) -> PipelineState:
        alert   = state["alert"]
        analysis = state["analysis"]
        iocs    = analysis.iocs if analysis else []
        source_ip = alert.source_ip or ""
        mitre   = analysis.mitre_techniques if analysis else []

        log.info("[ThreatIntel] Enriching alert %s with %d IOCs", alert.id, len(iocs))


        results = await asyncio.gather(
            virustotal_lookup(iocs),
            misp_lookup(iocs),
            otx_lookup(iocs),
            shodan_lookup(source_ip),
            nvd_lookup(mitre),
            geoip_lookup(source_ip),
            return_exceptions=True,
        )

        vt, misp, otx, shodan, cves, geo = results


        for name, res in zip(["VT","MISP","OTX","Shodan","NVD","GeoIP"], results):
            if isinstance(res, Exception):
                log.warning("[ThreatIntel] %s failed: %s", name, res)


        threat_score = self._compute_threat_score(vt, misp, otx, shodan)


        known_threat_actor = (
            misp.threat_actor if (misp and not isinstance(misp, Exception)) else None
        )
        is_tor = (
            geo.is_tor if (geo and not isinstance(geo, Exception)) else False
        )
        is_known_malicious = threat_score >= 0.6


        if is_known_malicious and source_ip:
            await redis_client.mark_malicious(source_ip)

        enrichment = TIEnrichment(
            alert_id=alert.id,
            vt_result=vt if not isinstance(vt, Exception) else None,
            misp_result=misp if not isinstance(misp, Exception) else None,
            otx_result=otx if not isinstance(otx, Exception) else None,
            shodan_result=shodan if not isinstance(shodan, Exception) else None,
            cve_references=cves if not isinstance(cves, Exception) else [],
            geo_context=geo if not isinstance(geo, Exception) else None,
            threat_score=round(threat_score, 4),
            known_threat_actor=known_threat_actor,
            is_tor_exit=is_tor,
            is_known_malicious=is_known_malicious,
        )

        await kafka_producer.send("wazuh.enriched", enrichment)
        state["enrichment"] = enrichment
        state["pipeline_stage"] = "enrichment_complete"
        state.setdefault("audit_trail", []).append(
            StepLog(
                agent="threat_intel",
                result={
                    "threat_score": round(threat_score, 4),
                    "known_threat_actor": known_threat_actor,
                    "is_tor_exit": is_tor,
                    "cve_count": len(enrichment.cve_references),
                },
                ts=datetime.utcnow(),
            )
        )
        log.info("[ThreatIntel] Done — threat_score=%.2f actor=%s", threat_score, known_threat_actor)
        return state


    def _compute_threat_score(self, vt, misp, otx, shodan) -> float:
        """
        Weighted composite score per design spec:
          VT malicious_ratio   × 0.35
          MISP confidence      × 0.25
          OTX pulse_count/100  × 0.20
          Shodan vuln_count/10 × 0.20
        """
        vt_score    = vt.malicious_ratio    if (vt    and not isinstance(vt, Exception))    else 0.0
        misp_score  = misp.confidence       if (misp  and not isinstance(misp, Exception))  else 0.0
        otx_score   = min(otx.pulse_count / 100.0, 1.0) if (otx and not isinstance(otx, Exception)) else 0.0
        shodan_score = min(shodan.vuln_count / 10.0, 1.0) if (shodan and not isinstance(shodan, Exception)) else 0.0

        score = (
            vt_score    * 0.35 +
            misp_score  * 0.25 +
            otx_score   * 0.20 +
            shodan_score * 0.20
        )
        return min(score, 1.0)


threat_intel_agent = ThreatIntelAgent()
