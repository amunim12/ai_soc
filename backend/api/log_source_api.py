# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0
"""
Log Source Management API — api/log_source_api.py

Endpoints:
  GET    /api/log-sources                  — list all configured log sources
  POST   /api/log-sources                  — add a new log source
  GET    /api/log-sources/{id}             — get a single log source
  PUT    /api/log-sources/{id}             — update a log source
  DELETE /api/log-sources/{id}             — remove a log source
  GET    /api/log-sources/{id}/status      — live Wazuh agent status
  GET    /api/log-sources/{id}/enroll      — Wazuh agent enrollment instructions
  POST   /api/log-sources/{id}/test-soar   — test Shuffle SOAR reachability
  GET    /api/log-sources/soar-actions     — list available SOAR action types
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException

from api.auth_api import get_current_user
from config.settings import settings
from infrastructure.log_source_store import log_source_store
from infrastructure.wazuh_client import wazuh_get, wazuh_post, wazuh_ssl
from schemas.log_source import (
    AVAILABLE_SOAR_ACTIONS,
    EnrollmentInstructions,
    LogSource,
    LogSourceCreate,
    LogSourceUpdate,
    SoarTestResult,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/log-sources", tags=["log-sources"])


def _norm_status(raw: str) -> str:
    s = (raw or "").lower()
    if s in ("active", "online"):
        return "active"
    if "never" in s:
        return "never_connected"
    if s == "pending":
        return "pending"
    return "disconnected"


def _enrollment_commands(host: str, os_type: Optional[str], manager_ip: str) -> list[str]:
    """Generate OS-specific Wazuh agent install + registration commands."""
    reg = f"WAZUH_MANAGER='{manager_ip}'"
    if not os_type or os_type == "linux":
        return [
            f"# On the target host ({host}):",
            "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg",
            'echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list',
            "apt-get update",
            f"{reg} apt-get install -y wazuh-agent",
            "systemctl daemon-reload && systemctl enable wazuh-agent && systemctl start wazuh-agent",
        ]
    if os_type == "windows":
        return [
            f"# On the target host ({host}) — run in PowerShell as Administrator:",
            f'Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.10.2-1.msi" -OutFile wazuh-agent.msi',
            f'msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="{manager_ip}" WAZUH_REGISTRATION_SERVER="{manager_ip}"',
            'net start "Wazuh"',
        ]
    if os_type == "macos":
        return [
            f"# On the target host ({host}):",
            f"curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.10.2-1.intel64.pkg",
            f"echo '{reg}' > /tmp/wazuh_envs && sudo installer -pkg wazuh-agent.pkg -target /",
            "sudo /Library/Ossec/bin/wazuh-control start",
        ]
    return [f"# Install the Wazuh agent on {host} and point it to manager {manager_ip}"]


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/soar-actions")
async def list_soar_actions() -> list[str]:
    """Return the list of SOAR action types that can be assigned to a log source."""
    return AVAILABLE_SOAR_ACTIONS


@router.get("", response_model=list[LogSource])
async def list_log_sources() -> list[LogSource]:
    return await log_source_store.list()


@router.post("", response_model=LogSource, status_code=201)
async def create_log_source(body: LogSourceCreate) -> LogSource:
    invalid = [a for a in body.soar_actions if a not in AVAILABLE_SOAR_ACTIONS]
    if invalid:
        raise HTTPException(422, f"Unknown SOAR actions: {invalid}")
    return await log_source_store.create(body)


@router.get("/{source_id}", response_model=LogSource)
async def get_log_source(source_id: str) -> LogSource:
    src = await log_source_store.get(source_id)
    if not src:
        raise HTTPException(404, "Log source not found")
    return src


@router.put("/{source_id}", response_model=LogSource)
async def update_log_source(
    source_id: str,
    body: LogSourceUpdate,
    current_user: dict = Depends(get_current_user),
) -> LogSource:
    if body.soar_actions is not None:
        invalid = [a for a in body.soar_actions if a not in AVAILABLE_SOAR_ACTIONS]
        if invalid:
            raise HTTPException(422, f"Unknown SOAR actions: {invalid}")
    updated = await log_source_store.update(source_id, body)
    if not updated:
        raise HTTPException(404, "Log source not found")
    return updated


@router.delete("/{source_id}", status_code=204)
async def delete_log_source(
    source_id: str,
    current_user: dict = Depends(get_current_user),
) -> None:
    deleted = await log_source_store.delete(source_id)
    if not deleted:
        raise HTTPException(404, "Log source not found")


@router.get("/{source_id}/status")
async def get_live_status(source_id: str) -> dict[str, Any]:
    """
    Query Wazuh live for this log source's agent status.
    Matches by stored wazuh_agent_id, then falls back to searching by host IP.
    Updates the stored status as a side-effect.
    """
    src = await log_source_store.get(source_id)
    if not src:
        raise HTTPException(404, "Log source not found")

    wazuh_data = None
    agent_id = None

    if src.wazuh_agent_id:
        wazuh_data = await wazuh_get(f"/agents/{src.wazuh_agent_id}")
        if wazuh_data:
            agent_id = src.wazuh_agent_id

    if not wazuh_data:
        result = await wazuh_get("/agents", {"q": f"ip={src.host}", "limit": 1})
        if result:
            items = result.get("data", {}).get("affected_items", [])
            if items:
                wazuh_data = {"data": {"affected_items": items}}
                agent_id = items[0].get("id")

    if not wazuh_data:
        return {
            "source_id": source_id,
            "wazuh_status": "unknown",
            "wazuh_agent_id": None,
            "wazuh_reachable": False,
            "message": "Wazuh unavailable or agent not found",
        }

    items = wazuh_data.get("data", {}).get("affected_items", [])
    if not items:
        items = [wazuh_data.get("data", {})]

    agent = items[0] if items else {}
    norm = _norm_status(agent.get("status", "unknown"))

    await log_source_store.update_wazuh_status(source_id, agent_id, norm)

    return {
        "source_id": source_id,
        "wazuh_status": norm,
        "wazuh_agent_id": agent_id or agent.get("id"),
        "wazuh_reachable": True,
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "last_keepalive": agent.get("lastKeepAlive"),
        "os": (agent.get("os") or {}).get("platform"),
        "version": agent.get("version"),
    }


@router.get("/{source_id}/enroll", response_model=EnrollmentInstructions)
async def get_enrollment_instructions(source_id: str) -> EnrollmentInstructions:
    """
    Generate Wazuh agent enrollment commands for the log source.
    Optionally pre-registers the agent via the Wazuh API to obtain an enrollment key.
    """
    src = await log_source_store.get(source_id)
    if not src:
        raise HTTPException(404, "Log source not found")

    manager_url = settings.WAZUH_API_URL or "https://wazuh-manager:55000"
    manager_ip = manager_url.replace("https://", "").replace("http://", "").split(":")[0]

    enrollment_key: Optional[str] = None
    resp = await wazuh_post("/agents", {"name": src.name, "ip": src.host})
    if resp is not None and resp.status_code == 200:
        data = resp.json().get("data", {})
        items = data.get("affected_items", [{}])
        enrollment_key = items[0].get("key") if items else None
        wazuh_id = items[0].get("id") if items else None
        if wazuh_id:
            await log_source_store.update_wazuh_status(source_id, wazuh_id, "never_connected")

    commands = _enrollment_commands(src.host, src.os_type, manager_ip)

    notes = (
        "After running these commands, the agent will appear in the Wazuh Dashboard "
        "and send logs to the AI SOC pipeline within a few minutes."
    )
    if enrollment_key:
        notes = f"Enrollment key: {enrollment_key}\n\n" + notes

    return EnrollmentInstructions(
        log_source_id=source_id,
        wazuh_manager_ip=manager_ip,
        enrollment_key=enrollment_key,
        install_commands=commands,
        notes=notes,
    )


@router.post("/{source_id}/test-soar", response_model=SoarTestResult)
async def test_soar_connection(
    source_id: str,
    current_user: dict = Depends(get_current_user),
) -> SoarTestResult:
    """Test whether Shuffle SOAR is reachable and the API key is valid."""
    src = await log_source_store.get(source_id)
    if not src:
        raise HTTPException(404, "Log source not found")

    if not src.soar_enabled:
        return SoarTestResult(
            log_source_id=source_id,
            reachable=False,
            message="SOAR integration is not enabled for this log source.",
        )

    shuffle_url = settings.SHUFFLE_BASE_URL
    shuffle_key = settings.SHUFFLE_API_KEY

    if not shuffle_url or not shuffle_key:
        return SoarTestResult(
            log_source_id=source_id,
            reachable=False,
            message="SHUFFLE_BASE_URL or SHUFFLE_API_KEY not configured.",
        )

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            r = await client.get(
                f"{shuffle_url}/api/v1/workflows",
                headers={"Authorization": f"Bearer {shuffle_key}"},
            )
            if r.status_code == 200:
                actions = ", ".join(src.soar_actions) or "none"
                return SoarTestResult(
                    log_source_id=source_id,
                    reachable=True,
                    message=f"Shuffle SOAR reachable. Actions enabled: {actions}",
                )
            return SoarTestResult(
                log_source_id=source_id,
                reachable=False,
                message=f"Shuffle returned HTTP {r.status_code}",
            )
    except Exception as exc:
        return SoarTestResult(
            log_source_id=source_id,
            reachable=False,
            message=f"Cannot reach Shuffle: {exc}",
        )
