# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
SIEM API — api/siem_api.py

Native SIEM dashboard backend.  Provides four data sources:

  GET /api/siem/summary        — headline stats (agents, 24h alert count, etc.)
  GET /api/siem/alerts         — recent alerts parsed from SQLite hitl_reviews
  GET /api/siem/severity       — per-hour severity breakdown for the last N hours
  GET /api/siem/mitre          — top MITRE ATT&CK techniques seen in alerts
  GET /api/siem/agents         — agent list (Wazuh REST API → SQLite fallback)

Wazuh REST API (port 55000) is queried with a cached JWT token that is
refreshed automatically when it expires.  If Wazuh is unreachable the
endpoints degrade gracefully to SQLite-derived data.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Query

from infrastructure.sqlite_client import sqlite_client
from infrastructure.wazuh_client import wazuh_get

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/siem", tags=["siem"])


def _wazuh_status(raw_status: str) -> str:
    """Normalise Wazuh agent status string to active / disconnected / never_connected."""
    s = (raw_status or "").lower()
    if s in ("active", "online"):
        return "active"
    if s in ("never connected",):
        return "never_connected"
    return "disconnected"


@router.get("/summary")
async def get_summary() -> dict[str, Any]:
    """
    Headline stats for the SIEM overview cards.
    Tries Wazuh API for agent counts; falls back to SQLite for alert metrics.
    """
    metrics = await sqlite_client.get_metrics()


    agents_total  = 0
    agents_active = 0
    wazuh_online  = False

    wazuh_data = await wazuh_get("/overview/agents")
    if wazuh_data:
        wazuh_online  = True
        summary = wazuh_data.get("data", {}).get("agent_os", [])
        agents_total  = wazuh_data.get("data", {}).get("agents_summary", {}).get("total_agents", 0)
        agents_active = wazuh_data.get("data", {}).get("agents_summary", {}).get("active", 0)
    else:

        db_agents = await sqlite_client.get_agents()
        agents_total  = len(db_agents)
        agents_active = sum(1 for a in db_agents if a["status"] == "active")

    return {
        **metrics,
        "agents_total":  agents_total,
        "agents_active": agents_active,
        "wazuh_online":  wazuh_online,
    }


@router.get("/alerts")
async def get_recent_alerts(
    limit: int = Query(100, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL,HIGH,MEDIUM,LOW"),
) -> list[dict[str, Any]]:
    """
    Recent alerts from the pipeline, derived from SQLite hitl_reviews.
    Optionally filter by severity (comma-separated values).
    """
    alerts = await sqlite_client.get_recent_alerts(limit=limit)

    if severity:
        allowed = {s.strip().upper() for s in severity.split(",")}
        alerts = [a for a in alerts if a["severity"] in allowed]

    return alerts


@router.get("/severity")
async def get_severity_breakdown(
    hours: int = Query(24, ge=1, le=168),
) -> list[dict[str, Any]]:
    """
    Per-hour alert counts broken down by severity (CRITICAL / HIGH / MEDIUM / LOW)
    for the last N hours.  Used to drive the multi-line area chart.
    """
    return await sqlite_client.get_severity_breakdown(hours=hours)


@router.get("/mitre")
async def get_mitre_stats(
    limit: int = Query(15, ge=1, le=50),
) -> list[dict[str, Any]]:
    """
    Top MITRE ATT&CK technique IDs seen across all stored alerts and playbooks.
    Returns [{technique_id, technique_name, count}] sorted by frequency.
    """
    return await sqlite_client.get_mitre_stats(limit=limit)


@router.get("/agents")
async def get_agents_siem() -> list[dict[str, Any]]:
    """
    Monitored agent list.  Queries the Wazuh Manager REST API first;
    falls back to SQLite-derived agent data if Wazuh is unreachable.
    """
    wazuh_data = await wazuh_get("/agents", {"limit": 500, "select": "id,name,ip,os,status,lastKeepAlive,version"})

    if wazuh_data:
        raw_agents = wazuh_data.get("data", {}).get("affected_items", [])
        return [
            {
                "id":        item.get("id", "—"),
                "name":      item.get("name", "—"),
                "status":    _wazuh_status(item.get("status", "")),
                "os":        (item.get("os") or {}).get("platform", "—")
                             + " " + (item.get("os") or {}).get("version", ""),
                "ip":        item.get("ip", "—"),
                "last_seen": item.get("lastKeepAlive", "—"),
                "version":   item.get("version", "—"),
                "alerts":    0,
            }
            for item in raw_agents
            if item.get("id") != "000"
        ]


    log.info("[SIEM] Wazuh agents API unavailable — using SQLite fallback")
    return await sqlite_client.get_agents()
