# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Threat Intelligence integrations — Mock and Live adapters.

Each integration module exposes an async function:
  lookup(ioc_or_ip) -> ResultModel | Exception

`USE_MOCK_TI=true` (default) uses deterministic stubs.
Set `USE_MOCK_TI=false` + supply API keys for live calls.
"""
from __future__ import annotations
import os
import logging
import asyncio
from typing import Any

import httpx
from dotenv import load_dotenv

from infrastructure.redis_client import redis_client

load_dotenv()
log = logging.getLogger(__name__)

USE_MOCK = os.getenv("USE_MOCK_TI", "true").lower() == "true"

TI_LOOKUP_TIMEOUT_SECONDS = float(os.getenv("TI_LOOKUP_TIMEOUT_SECONDS", "2"))


VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"


async def virustotal_lookup(iocs: list[str]) -> Any:
    """Return VTResult-compatible dict."""
    from schemas.enrichment import VTResult
    if USE_MOCK or not VT_API_KEY:
        if iocs:
            ioc = iocs[0]
            is_bad = any(x in ioc for x in ["185.220", "203.0.113", "45.33"])
            return VTResult(
                ioc=ioc,
                malicious_ratio=0.72 if is_bad else 0.02,
                malicious_votes=36 if is_bad else 1,
                total_votes=50,
                categories=["malware", "phishing"] if is_bad else [],
                last_analysis_date="2024-12-09",
            )
        return VTResult(ioc="none", malicious_ratio=0.0, total_votes=0)


    if not iocs:
        return VTResult(ioc="none", malicious_ratio=0.0, total_votes=0)
    ioc = iocs[0]
    _ck = f"ti:vt:{ioc}"
    _hit = await redis_client.get(_ck)
    if _hit:
        try:
            return VTResult.model_validate_json(_hit)
        except Exception:
            pass
    resource_type = "ip_addresses" if _is_ip(ioc) else "domains"
    try:
        async with httpx.AsyncClient(timeout=TI_LOOKUP_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                f"{VT_BASE}/{resource_type}/{ioc}",
                headers={"x-apikey": VT_API_KEY},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            total = sum(data.values()) or 1
            malicious = data.get("malicious", 0)
            result = VTResult(
                ioc=ioc,
                malicious_ratio=malicious / total,
                malicious_votes=malicious,
                total_votes=total,
            )
            await redis_client.set(_ck, result.model_dump_json(), ex=86400)
            return result
    except Exception as exc:
        log.debug("VT lookup skipped (%s): %s", type(exc).__name__, exc)
        return VTResult(ioc=ioc, malicious_ratio=0.0, total_votes=0)


MISP_URL = os.getenv("MISP_URL", "")
MISP_KEY = os.getenv("MISP_API_KEY", "")


async def misp_lookup(iocs: list[str]) -> Any:
    from schemas.enrichment import MISPResult
    if USE_MOCK or not MISP_KEY:
        if iocs and any("185.220" in i for i in iocs):
            return MISPResult(
                ioc_matches=iocs[:2],
                confidence=0.85,
                threat_actor="Cozy Bear",
                campaign="APT29-2024",
                event_count=3,
            )
        return MISPResult(confidence=0.0, event_count=0)


    try:
        from pymisp import PyMISP
        api = PyMISP(MISP_URL, MISP_KEY, ssl=False)
        results: list[str] = []
        last_hits: list = []
        for ioc in iocs[:3]:
            last_hits = api.search(value=ioc, limit=1)
            if last_hits:
                results.append(ioc)

        ta = last_hits[0].get("Event", {}).get("threat_level_id") if results and last_hits else None
        return MISPResult(
            ioc_matches=results,
            confidence=0.7 if results else 0.0,
            threat_actor=str(ta) if ta else None,
            event_count=len(results),
        )
    except Exception as exc:
        log.warning("MISP lookup failed: %s", exc)
        return MISPResult(error=str(exc))


OTX_KEY = os.getenv("OTX_API_KEY", "")
OTX_BASE = "https://otx.alienvault.com/api/v1"


async def otx_lookup(iocs: list[str]) -> Any:
    from schemas.enrichment import OTXResult
    if USE_MOCK or not OTX_KEY:
        if iocs and any("185.220" in i for i in iocs):
            return OTXResult(pulse_count=12, malware_families=["Cobalt Strike"], adversary="APT29")
        return OTXResult(pulse_count=0)

    if not iocs:
        return OTXResult(pulse_count=0)
    ioc = iocs[0]
    _ck = f"ti:otx:{ioc}"
    _hit = await redis_client.get(_ck)
    if _hit:
        try:
            return OTXResult.model_validate_json(_hit)
        except Exception:
            pass
    indicator_type = "IPv4" if _is_ip(ioc) else "domain"
    try:
        async with httpx.AsyncClient(timeout=TI_LOOKUP_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                f"{OTX_BASE}/indicators/{indicator_type}/{ioc}/general",
                headers={"X-OTX-API-KEY": OTX_KEY},
            )
            resp.raise_for_status()
            data = resp.json()
            pc = data.get("pulse_info", {}).get("count", 0)
            malware_fams = [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:3]]
            result = OTXResult(pulse_count=pc, malware_families=malware_fams)
            await redis_client.set(_ck, result.model_dump_json(), ex=86400)
            return result
    except Exception as exc:
        log.debug("OTX lookup skipped (%s): %s", type(exc).__name__, exc)
        return OTXResult(pulse_count=0)


SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")


async def shodan_lookup(ip: str) -> Any:
    from schemas.enrichment import ShodanResult
    if not ip:
        return ShodanResult()
    if USE_MOCK or not SHODAN_KEY:
        if "185.220" in ip:
            return ShodanResult(
                ip=ip, org="Tor Project", country="DE",
                open_ports=[22, 80, 443, 9001],
                vuln_count=2, vulns=["CVE-2023-1234", "CVE-2022-5678"],
                hostnames=["exit.tor.example.com"],
            )
        return ShodanResult(ip=ip, vuln_count=0)

    _ck = f"ti:shodan:{ip}"
    _hit = await redis_client.get(_ck)
    if _hit:
        try:
            return ShodanResult.model_validate_json(_hit)
        except Exception:
            pass
    try:
        async with httpx.AsyncClient(timeout=TI_LOOKUP_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": SHODAN_KEY},
            )
            resp.raise_for_status()
            data = resp.json()
            vulns = list(data.get("vulns", {}).keys())
            result = ShodanResult(
                ip=ip,
                org=data.get("org"),
                country=data.get("country_name"),
                open_ports=data.get("ports", []),
                vuln_count=len(vulns),
                vulns=vulns[:10],
                hostnames=data.get("hostnames", []),
            )
            await redis_client.set(_ck, result.model_dump_json(), ex=86400)
            return result
    except Exception as exc:
        log.debug("Shodan lookup skipped (%s): %s", type(exc).__name__, exc)
        return ShodanResult(ip=ip, vuln_count=0)


async def nvd_lookup(mitre_techniques: list[str]) -> list[Any]:
    from schemas.enrichment import CVEReference
    if USE_MOCK:
        if mitre_techniques:
            return [
                CVEReference(
                    cve_id="CVE-2021-44228",
                    description="Log4Shell RCE in Apache Log4j2",
                    cvss_score=10.0,
                    severity="CRITICAL",
                    published_date="2021-12-10",
                ),
                CVEReference(
                    cve_id="CVE-2023-1234",
                    description="Example vulnerability linked to technique",
                    cvss_score=7.5,
                    severity="HIGH",
                    published_date="2023-03-15",
                ),
            ]
        return []


    cves: list[CVEReference] = []
    try:
        import nvdlib

        def _sync_nvd():
            out = []
            for tech in mitre_techniques[:2]:
                results = nvdlib.searchCVE(keywordSearch=tech, limit=2)
                for r in results:
                    metrics = getattr(r, "v31score", None) or getattr(r, "v2score", None) or 0.0
                    out.append(CVEReference(
                        cve_id=r.id,
                        description=r.descriptions[0].value if r.descriptions else "",
                        cvss_score=float(metrics),
                        severity="CRITICAL" if float(metrics) >= 9 else "HIGH" if float(metrics) >= 7 else "MEDIUM",
                        published_date=str(r.published)[:10],
                    ))
            return out

        cves = await asyncio.wait_for(
            asyncio.to_thread(_sync_nvd),
            timeout=TI_LOOKUP_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        log.debug("NVD lookup skipped (%s): %s", type(exc).__name__, exc)
    return cves


MAXMIND_DB = os.getenv("MAXMIND_DB_PATH", "./data/GeoLite2-City.mmdb")


async def geoip_lookup(ip: str) -> Any:
    from schemas.enrichment import GeoContext
    if not ip:
        return GeoContext()
    if USE_MOCK:
        tor_ips = {"185.220.101.47"}
        is_tor = ip in tor_ips or "185.220" in ip
        country = "DE" if is_tor else "US"
        return GeoContext(ip=ip, country=country, city="Frankfurt" if is_tor else "Ashburn",
                          asn="AS209" if is_tor else "AS16509",
                          is_tor=is_tor, is_vpn=False, is_datacenter=not is_tor)

    try:
        import geoip2.database
        reader = geoip2.database.Reader(MAXMIND_DB)

        loop = asyncio.get_running_loop()
        record = await loop.run_in_executor(None, reader.city, ip)
        return GeoContext(
            ip=ip,
            country=record.country.name,
            city=record.city.name,
            latitude=record.location.latitude,
            longitude=record.location.longitude,
        )
    except Exception as exc:
        log.warning("GeoIP lookup failed for %s: %s", ip, exc)
        return GeoContext(ip=ip, error=str(exc))


def _is_ip(value: str) -> bool:
    import re
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value))
