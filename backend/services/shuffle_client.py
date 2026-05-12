# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Shuffle SOAR HTTP Client — services/shuffle_client.py

Async client for Shuffle SOAR REST API (on-premise, air-gapped).
All network calls target the internal Shuffle instance only.
Credentials are read from config.settings — never hardcoded.

Shuffle REST API reference:
  POST   /api/v1/workflows/{workflow_id}/execute
  GET    /api/v1/workflowexecutions/{execution_id}
  DELETE /api/v1/workflowexecutions/{execution_id}
  GET    /api/v1/workflowexecutions?limit={n}
  POST   /api/v1/workflowexecutions/{execution_id}/continue
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Optional

import httpx

from config.settings import settings

log = logging.getLogger(__name__)


_TERMINAL_STATUSES = frozenset({"FINISHED", "FAILED", "ABORTED"})


_WORKFLOW_IDS_CACHE: Optional[dict[str, str]] = None


def _load_workflow_ids() -> dict[str, str]:
    """
    Load workflow IDs from the JSON file written by register_shuffle_workflows.py.
    Cached in-process after first read.
    """
    global _WORKFLOW_IDS_CACHE
    if _WORKFLOW_IDS_CACHE is not None:
        return _WORKFLOW_IDS_CACHE
    try:
        with open(settings.SHUFFLE_WORKFLOW_IDS_PATH, encoding="utf-8") as fh:
            _WORKFLOW_IDS_CACHE = json.load(fh)
            log.info(
                "Loaded %d Shuffle workflow IDs from %s",
                len(_WORKFLOW_IDS_CACHE),
                settings.SHUFFLE_WORKFLOW_IDS_PATH,
            )
    except FileNotFoundError:
        log.error(
            "Shuffle workflow IDs file not found: %s — "
            "run scripts/register_shuffle_workflows.py first",
            settings.SHUFFLE_WORKFLOW_IDS_PATH,
        )
        _WORKFLOW_IDS_CACHE = {}
    return _WORKFLOW_IDS_CACHE


ATTACK_TO_WORKFLOW: dict[str, str] = {
    "MALWARE":              "malware-response",
    "BRUTE_FORCE":          "brute-force-response",
    "PRIVILEGE_ESCALATION": "privilege-escalation-response",
    "DATA_EXFILTRATION":    "data-exfiltration-response",
}


class ShuffleClient:
    """
    Async HTTP client for Shuffle SOAR (on-premise).

    All methods are async and use httpx.AsyncClient.
    A single shared client is created per instance to reuse connections.
    API key is injected as a bearer token from settings.SHUFFLE_API_KEY.
    """

    def __init__(self) -> None:
        self._base_url = settings.SHUFFLE_BASE_URL.rstrip("/")
        api_key = settings.SHUFFLE_API_KEY
        if api_key.count("-") == 4 and len(api_key) == 36:
            self._headers = {
                "Cookie": f"session_token={api_key}",
                "Content-Type": "application/json",
            }
        else:
            self._headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=2.0),
            follow_redirects=False,
        )
        log.info("ShuffleClient initialised → %s", self._base_url)


    async def trigger(
        self,
        attack_type: str,
        alert_id: str,
        agent_id: str,
        agent_name: str,
        source_ip: Optional[str],
        dest_ip: Optional[str],
        username: Optional[str],
        pid: Optional[str],
        playbook_summary: str,
    ) -> str:
        """
        Trigger a Shuffle workflow execution for the given attack type.

        Posts to POST /api/v1/workflows/{workflow_id}/execute with all alert
        fields serialised as the execution_argument JSON string.
        Includes hitl_expires_at = now + 15 minutes so mid-workflow HITL gates
        know when to time out.

        Args:
            attack_type:      One of MALWARE | BRUTE_FORCE | PRIVILEGE_ESCALATION
                              | DATA_EXFILTRATION
            alert_id:         Unique alert identifier from PipelineState.
            agent_id:         Wazuh agent ID of the affected endpoint.
            agent_name:       Human-readable hostname of the affected endpoint.
            source_ip:        Attacking / source IP address (may be None).
            dest_ip:          Destination / exfil IP address (may be None).
            username:         Account involved in the alert (may be None).
            pid:              Process ID for privilege-escalation kill (may be None).
            playbook_summary: Short human-readable description from the playbook.

        Returns:
            execution_id: Shuffle execution UUID string.

        Raises:
            KeyError:                  If attack_type is not in ATTACK_TO_WORKFLOW.
            httpx.HTTPStatusError:     On non-2xx Shuffle responses.
            httpx.RequestError:        On network connectivity errors.
        """
        workflow_name = ATTACK_TO_WORKFLOW[attack_type]
        workflow_ids  = _load_workflow_ids()

        if workflow_name not in workflow_ids:
            raise KeyError(
                f"Workflow '{workflow_name}' not found in "
                f"{settings.SHUFFLE_WORKFLOW_IDS_PATH}. "
                "Run scripts/register_shuffle_workflows.py first."
            )

        workflow_id = workflow_ids[workflow_name]
        hitl_expires = (datetime.utcnow() + timedelta(minutes=15)).isoformat()

        execution_argument = json.dumps({
            "alert_id":       alert_id,
            "agent_id":       agent_id,
            "agent_name":     agent_name,
            "source_ip":      source_ip,
            "dest_ip":        dest_ip,
            "username":       username,
            "pid":            pid,
            "attack_type":    attack_type,
            "playbook_summary": playbook_summary,
            "hitl_expires_at":  hitl_expires,
            "callback_url":   f"{settings.FASTAPI_INTERNAL_URL}/api/soar/execution-result",
            "hitl_gate_url":  f"{settings.FASTAPI_INTERNAL_URL}/api/soar/hitl-gate",
        })

        url = f"/api/v1/workflows/{workflow_id}/execute"
        log.info(
            "Triggering Shuffle workflow '%s' (id=%s) for alert=%s attack=%s",
            workflow_name, workflow_id, alert_id, attack_type,
        )

        try:
            resp = await self._client.post(url, content=execution_argument)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            log.error(
                "Shuffle trigger failed: workflow=%s status=%d body=%s",
                workflow_name, exc.response.status_code, exc.response.text[:500],
            )
            raise

        data = resp.json()
        execution_id: str = data.get("execution_id") or data.get("id", "")
        log.info(
            "Shuffle execution started: id=%s workflow=%s alert=%s",
            execution_id, workflow_name, alert_id,
        )
        return execution_id

    async def get_status(self, execution_id: str) -> dict[str, Any]:
        """
        Fetch the current status of a Shuffle workflow execution.

        Calls GET /api/v1/workflowexecutions/{execution_id}.

        Args:
            execution_id: Shuffle execution UUID.

        Returns:
            Dict with keys:
              execution_id, workflow, status, started_at, completed_at,
              steps (list of step dicts with: action_id, label, status,
              started, stopped).

        Raises:
            httpx.HTTPStatusError:  On non-2xx Shuffle responses.
            httpx.RequestError:     On network connectivity errors.
        """
        url = f"/api/v1/workflowexecutions/{execution_id}"
        try:
            resp = await self._client.get(url)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            log.error(
                "Shuffle get_status failed: execution_id=%s status=%d body=%s",
                execution_id, exc.response.status_code, exc.response.text[:500],
            )
            raise

        raw = resp.json()


        steps: list[dict[str, Any]] = []
        for result in raw.get("results", []):
            steps.append({
                "action_id": result.get("action", {}).get("id", ""),
                "label":     result.get("action", {}).get("label", ""),
                "status":    result.get("status", ""),
                "started":   result.get("started_at", ""),
                "stopped":   result.get("completed_at", ""),
            })

        return {
            "execution_id": raw.get("execution_id", execution_id),
            "workflow":     raw.get("workflow", {}).get("name", ""),
            "status":       raw.get("status", "UNKNOWN"),
            "started_at":   raw.get("started_at", ""),
            "completed_at": raw.get("completed_at", ""),
            "steps":        steps,
        }

    async def wait(
        self,
        execution_id: str,
        timeout: int = 900,
        poll_interval: int = 5,
    ) -> dict[str, Any]:
        """
        Poll get_status() until the execution reaches a terminal state.

        Terminal states: FINISHED | FAILED | ABORTED.
        For privilege-escalation and data-exfiltration workflows, Shuffle
        pauses at the hitl_gate step and the status stays non-terminal until
        the analyst calls POST /api/soar/hitl-approve/{execution_id}, which
        calls the Shuffle /continue endpoint to resume.

        Args:
            execution_id:   Shuffle execution UUID.
            timeout:        Maximum wait time in seconds (default 900 = 15 min).
            poll_interval:  Seconds between polls (default 5).

        Returns:
            Final status dict from get_status().

        Raises:
            TimeoutError:  When timeout is exceeded before a terminal state.
        """
        log.info(
            "Waiting for Shuffle execution id=%s (timeout=%ds poll=%ds)",
            execution_id, timeout, poll_interval,
        )
        elapsed = 0

        while elapsed < timeout:
            status_data = await self.get_status(execution_id)
            current_status = status_data.get("status", "")
            log.debug(
                "Shuffle poll: id=%s status=%s elapsed=%ds",
                execution_id, current_status, elapsed,
            )

            if current_status in _TERMINAL_STATUSES:
                log.info(
                    "Shuffle execution complete: id=%s status=%s elapsed=%ds",
                    execution_id, current_status, elapsed,
                )
                return status_data

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        raise TimeoutError(
            f"Shuffle execution {execution_id} did not reach a terminal state "
            f"within {timeout} seconds."
        )

    async def abort(self, execution_id: str) -> bool:
        """
        Abort a running Shuffle workflow execution.

        Calls DELETE /api/v1/workflowexecutions/{execution_id}.

        Args:
            execution_id: Shuffle execution UUID to abort.

        Returns:
            True if Shuffle returned HTTP 200.

        Raises:
            httpx.HTTPStatusError:  On non-2xx Shuffle responses.
            httpx.RequestError:     On network connectivity errors.
        """
        url = f"/api/v1/workflowexecutions/{execution_id}"
        log.info("Aborting Shuffle execution id=%s", execution_id)
        try:
            resp = await self._client.delete(url)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            log.error(
                "Shuffle abort failed: execution_id=%s status=%d body=%s",
                execution_id, exc.response.status_code, exc.response.text[:500],
            )
            raise
        return resp.status_code == 200

    async def resume(self, execution_id: str, body: dict[str, Any]) -> bool:
        """
        Resume a Shuffle workflow execution paused at a HITL gate.

        Calls POST /api/v1/workflowexecutions/{execution_id}/continue.
        Used by the /api/soar/hitl-approve route after analyst approves.

        Args:
            execution_id: Shuffle execution UUID.
            body:         Arbitrary JSON body forwarded to Shuffle (e.g. analyst_id).

        Returns:
            True if Shuffle accepted the resume (HTTP 2xx).

        Raises:
            httpx.HTTPStatusError:  On non-2xx Shuffle responses.
            httpx.RequestError:     On network connectivity errors.
        """
        url = f"/api/v1/workflowexecutions/{execution_id}/continue"
        log.info("Resuming Shuffle execution id=%s body=%s", execution_id, body)
        try:
            resp = await self._client.post(url, json=body)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            log.error(
                "Shuffle resume failed: execution_id=%s status=%d body=%s",
                execution_id, exc.response.status_code, exc.response.text[:500],
            )
            raise
        return resp.status_code < 300

    async def list_workflows(self) -> list[dict[str, Any]]:
        """
        List all workflows configured in Shuffle.

        Calls GET /api/v1/workflows.

        Returns:
            List of workflow dicts (id, name, description, is_valid, triggers, etc.)

        Raises:
            httpx.HTTPStatusError:  On non-2xx Shuffle responses.
            httpx.RequestError:     On network connectivity errors.
        """
        log.debug("Listing Shuffle workflows")
        try:
            resp = await self._client.get("/api/v1/workflows")
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            log.error(
                "Shuffle list_workflows failed: status=%d body=%s",
                exc.response.status_code, exc.response.text[:500],
            )
            raise
        data = resp.json()
        return data if isinstance(data, list) else []

    async def list_executions(self, limit: int = 50) -> list[dict[str, Any]]:
        """
        List recent Shuffle workflow executions.

        Calls GET /api/v1/workflowexecutions?limit={limit}.

        Args:
            limit: Maximum number of executions to return (default 50).

        Returns:
            Raw list of execution dicts from Shuffle.

        Raises:
            httpx.HTTPStatusError:  On non-2xx Shuffle responses.
            httpx.RequestError:     On network connectivity errors.
        """
        url = f"/api/v1/workflowexecutions?limit={limit}"
        log.debug("Listing Shuffle executions limit=%d", limit)
        try:
            resp = await self._client.get(url)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            log.error(
                "Shuffle list_executions failed: status=%d body=%s",
                exc.response.status_code, exc.response.text[:500],
            )
            raise
        data = resp.json()
        return data if isinstance(data, list) else []

    async def close(self) -> None:
        """Close the underlying httpx client. Call at application shutdown."""
        await self._client.aclose()


shuffle_client = ShuffleClient()
