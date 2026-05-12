#!/usr/bin/env python3
# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Register Shuffle SOAR Workflows — scripts/register_shuffle_workflows.py

Standalone one-time bootstrap script. Run this once before starting the
pipeline to register the four incident-response workflows in Shuffle.

Usage:
    python scripts/register_shuffle_workflows.py

After success, workflow IDs are saved to SHUFFLE_WORKFLOW_IDS_PATH
(default: /opt/config/shuffle_workflow_ids.json).

Environment variables required:
    SHUFFLE_API_KEY      — Shuffle API key (any value for on-prem defaults)
    SHUFFLE_BASE_URL     — Shuffle base URL (default: http://127.0.0.1:5001)

Internal service URLs (all air-gapped, set via environment variables):
    WAZUH_AR_URL      — Wazuh active-response endpoint  (e.g. http://wazuh-manager:55000)
    FIREWALL_URL      — Firewall management API          (e.g. http://firewall-host:8080)
    THEHIVE_URL       — TheHive case management          (e.g. http://thehive-host:9000)
    LDAP_API_URL      — LDAP/AD management API           (e.g. http://ldap-api-host:8080)
    FASTAPI_INTERNAL_URL — This AI SOC API              (e.g. http://soc-server:8000)

Shuffle variable substitution syntax used in action bodies:
    $exec.argument.field_name  → execution argument fields
    $exec.action_id            → result of a previous step
    $exec.execution_id         → the current execution UUID
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()


SHUFFLE_BASE_URL = os.getenv("SHUFFLE_BASE_URL", "http://127.0.0.1:5001").rstrip("/")
SHUFFLE_API_KEY  = os.getenv("SHUFFLE_API_KEY", "")
WORKFLOW_IDS_PATH = os.getenv(
    "SHUFFLE_WORKFLOW_IDS_PATH", "/opt/config/shuffle_workflow_ids.json"
)

HEADERS = {
    "Authorization": f"Bearer {SHUFFLE_API_KEY}",
    "Content-Type": "application/json",
}


WAZUH_AR_URL  = os.getenv("WAZUH_AR_URL",  "http://wazuh-manager:55000")
FIREWALL_URL  = os.getenv("FIREWALL_URL",  "http://firewall-host:8080")
THEHIVE_URL   = os.getenv("THEHIVE_URL",   "http://thehive-host:9000")
LDAP_API_URL  = os.getenv("LDAP_API_URL",  "http://ldap-api-host:8080")
FASTAPI_URL   = os.getenv("FASTAPI_INTERNAL_URL", "http://localhost:8000")


def _http_action(
    action_id: str,
    label: str,
    url: str,
    method: str,
    body: dict[str, Any],
    position: dict[str, int],
    dependencies: list[str],
) -> dict[str, Any]:
    """
    Build a Shuffle HTTP app action node dict.

    Args:
        action_id:    Unique ID for this step within the workflow.
        label:        Human-readable step label shown in the Shuffle UI.
        url:          Target URL (must be an internal hostname).
        method:       HTTP method: GET | POST | PUT | DELETE | PATCH.
        body:         Request body dict (will be serialised to JSON string).
        position:     {x, y} coordinates for the Shuffle canvas.
        dependencies: List of action_ids this step waits for.

    Returns:
        Dict matching Shuffle's workflow action schema.
    """
    return {
        "id":          action_id,
        "label":       label,
        "app_name":    "HTTP",
        "app_version": "1.4.0",
        "name":        "curl",
        "parameters": [
            {"name": "url",     "value": url},
            {"name": "method",  "value": method},
            {"name": "body",    "value": json.dumps(body)},
            {
                "name":  "headers",
                "value": json.dumps({"Content-Type": "application/json"}),
            },
        ],
        "position":     position,
        "dependencies": dependencies,
    }


def _malware_response() -> dict[str, Any]:
    """
    malware-response workflow:
      1. isolate   — Wazuh AR isolate-host.sh on agent_id
      2. block_c2  — Firewall block source_ip permanently
      3. create_case — TheHive severity=3, tags=[malware, soar]
      4. notify    — Callback to FastAPI /api/soar/execution-result
    """
    return {
        "name":        "malware-response",
        "description": "Automated malware containment: isolate host, block C2, open TheHive case",
        "status":      "running",
        "start":       "isolate",
        "triggers":    [],
        "actions": [
            _http_action(
                action_id="isolate",
                label="Isolate Host via Wazuh AR",
                url=f"{WAZUH_AR_URL}/active-response",
                method="POST",
                body={
                    "command": "isolate-host.sh",
                    "agent_id": "$exec.argument.agent_id",
                    "alert_id": "$exec.argument.alert_id",
                },
                position={"x": 100, "y": 100},
                dependencies=[],
            ),
            _http_action(
                action_id="block_c2",
                label="Block C2 IP on Firewall",
                url=f"{FIREWALL_URL}/block",
                method="POST",
                body={
                    "source_ip": "$exec.argument.source_ip",
                    "action":    "block",
                    "duration":  "permanent",
                    "reason":    "malware-c2",
                    "alert_id":  "$exec.argument.alert_id",
                },
                position={"x": 400, "y": 0},
                dependencies=["isolate"],
            ),
            _http_action(
                action_id="create_case",
                label="Open TheHive Case",
                url=f"{THEHIVE_URL}/api/case",
                method="POST",
                body={
                    "title":       "Malware Incident — $exec.argument.agent_name",
                    "description": "$exec.argument.playbook_summary",
                    "severity":    3,
                    "tags":        ["malware", "soar"],
                    "alert_id":    "$exec.argument.alert_id",
                },
                position={"x": 400, "y": 200},
                dependencies=["isolate"],
            ),
            _http_action(
                action_id="notify",
                label="Notify Pipeline — Execution Complete",
                url=f"{FASTAPI_URL}/api/soar/execution-result",
                method="POST",
                body={
                    "execution_id": "$exec.execution_id",
                    "workflow":     "malware-response",
                    "status":       "FINISHED",
                    "results": {
                        "isolate":     "$exec.isolate",
                        "block_c2":    "$exec.block_c2",
                        "create_case": "$exec.create_case",
                    },
                },
                position={"x": 700, "y": 100},
                dependencies=["block_c2", "create_case"],
            ),
        ],
    }


def _brute_force_response() -> dict[str, Any]:
    """
    brute-force-response workflow:
      1. block_ip     — Firewall block source_ip for 86400s
      2. lock_account — LDAP API lock username
      3. create_case  — TheHive severity=2, tags=[brute_force, soar]
      4. notify       — Callback to FastAPI /api/soar/execution-result
    """
    return {
        "name":        "brute-force-response",
        "description": "Automated brute-force response: block IP, lock account, open TheHive case",
        "status":      "running",
        "start":       "block_ip",
        "triggers":    [],
        "actions": [
            _http_action(
                action_id="block_ip",
                label="Block Source IP on Firewall",
                url=f"{FIREWALL_URL}/block",
                method="POST",
                body={
                    "source_ip": "$exec.argument.source_ip",
                    "action":    "block",
                    "duration":  86400,
                    "reason":    "brute-force-attack",
                    "alert_id":  "$exec.argument.alert_id",
                },
                position={"x": 100, "y": 100},
                dependencies=[],
            ),
            _http_action(
                action_id="lock_account",
                label="Lock Account via LDAP API",
                url=f"{LDAP_API_URL}/users/lock",
                method="POST",
                body={
                    "username": "$exec.argument.username",
                    "reason":   "brute-force-lockout",
                    "alert_id": "$exec.argument.alert_id",
                },
                position={"x": 400, "y": 0},
                dependencies=["block_ip"],
            ),
            _http_action(
                action_id="create_case",
                label="Open TheHive Case",
                url=f"{THEHIVE_URL}/api/case",
                method="POST",
                body={
                    "title":       "Brute Force Attempt — $exec.argument.agent_name",
                    "description": "$exec.argument.playbook_summary",
                    "severity":    2,
                    "tags":        ["brute_force", "soar"],
                    "alert_id":    "$exec.argument.alert_id",
                },
                position={"x": 400, "y": 200},
                dependencies=["block_ip"],
            ),
            _http_action(
                action_id="notify",
                label="Notify Pipeline — Execution Complete",
                url=f"{FASTAPI_URL}/api/soar/execution-result",
                method="POST",
                body={
                    "execution_id": "$exec.execution_id",
                    "workflow":     "brute-force-response",
                    "status":       "FINISHED",
                    "results": {
                        "block_ip":     "$exec.block_ip",
                        "lock_account": "$exec.lock_account",
                        "create_case":  "$exec.create_case",
                    },
                },
                position={"x": 700, "y": 100},
                dependencies=["lock_account", "create_case"],
            ),
        ],
    }


def _privilege_escalation_response() -> dict[str, Any]:
    """
    privilege-escalation-response workflow:
      1. forensics  — Wazuh AR collect-forensics.sh on agent_id
      2. hitl_gate  — POST FastAPI /api/soar/hitl-gate (PAUSES here)
      3. revoke     — Wazuh AR kill-session.sh with pid
      4. suspend    — LDAP API suspend username
      5. notify     — Callback to FastAPI /api/soar/execution-result

    NOTE: Shuffle pauses at hitl_gate and waits until the analyst
    calls POST /api/soar/hitl-approve/{execution_id}, which in turn
    POSTs to Shuffle /api/v1/workflowexecutions/{id}/continue.
    """
    return {
        "name":        "privilege-escalation-response",
        "description": (
            "Analyst-gated privilege-escalation response: "
            "collect forensics, HITL gate, revoke session, suspend account"
        ),
        "status":      "running",
        "start":       "forensics",
        "triggers":    [],
        "actions": [
            _http_action(
                action_id="forensics",
                label="Collect Forensics via Wazuh AR",
                url=f"{WAZUH_AR_URL}/active-response",
                method="PUT",
                body={
                    "command":  "collect-forensics.sh",
                    "agent_id": "$exec.argument.agent_id",
                    "alert_id": "$exec.argument.alert_id",
                },
                position={"x": 100, "y": 100},
                dependencies=[],
            ),
            _http_action(
                action_id="hitl_gate",
                label="HITL Gate — Await Analyst Approval",
                url=f"{FASTAPI_URL}/api/soar/hitl-gate",
                method="POST",
                body={
                    "execution_id": "$exec.execution_id",
                    "alert_id":     "$exec.argument.alert_id",
                    "forensics":    "$exec.forensics",
                    "agent_name":   "$exec.argument.agent_name",
                    "username":     "$exec.argument.username",
                    "pid":          "$exec.argument.pid",
                },
                position={"x": 400, "y": 100},
                dependencies=["forensics"],
            ),
            _http_action(
                action_id="revoke",
                label="Kill Session via Wazuh AR",
                url=f"{WAZUH_AR_URL}/active-response",
                method="PUT",
                body={
                    "command":  "kill-session.sh",
                    "agent_id": "$exec.argument.agent_id",
                    "pid":      "$exec.argument.pid",
                    "alert_id": "$exec.argument.alert_id",
                },
                position={"x": 700, "y": 0},
                dependencies=["hitl_gate"],
            ),
            _http_action(
                action_id="suspend",
                label="Suspend Account via LDAP API",
                url=f"{LDAP_API_URL}/users/suspend",
                method="POST",
                body={
                    "username": "$exec.argument.username",
                    "reason":   "privilege-escalation-detected",
                    "alert_id": "$exec.argument.alert_id",
                },
                position={"x": 700, "y": 200},
                dependencies=["hitl_gate"],
            ),
            _http_action(
                action_id="notify",
                label="Notify Pipeline — Execution Complete",
                url=f"{FASTAPI_URL}/api/soar/execution-result",
                method="POST",
                body={
                    "execution_id": "$exec.execution_id",
                    "workflow":     "privilege-escalation-response",
                    "status":       "FINISHED",
                    "results": {
                        "forensics": "$exec.forensics",
                        "revoke":    "$exec.revoke",
                        "suspend":   "$exec.suspend",
                    },
                },
                position={"x": 1000, "y": 100},
                dependencies=["revoke", "suspend"],
            ),
        ],
    }


def _data_exfiltration_response() -> dict[str, Any]:
    """
    data-exfiltration-response workflow:
      1. pcap       — Wazuh AR capture-traffic.sh with dest_ip
      2. hitl_gate  — POST FastAPI /api/soar/hitl-gate (PAUSES here)
      3. block_dest — Firewall block dest_ip
      4. lock_account — LDAP API lock username
      5. notify     — Callback to FastAPI /api/soar/execution-result

    NOTE: Same HITL pause mechanism as privilege-escalation-response.
    """
    return {
        "name":        "data-exfiltration-response",
        "description": (
            "Analyst-gated data-exfiltration response: "
            "capture traffic, HITL gate, block destination, lock account"
        ),
        "status":      "running",
        "start":       "pcap",
        "triggers":    [],
        "actions": [
            _http_action(
                action_id="pcap",
                label="Capture Traffic via Wazuh AR",
                url=f"{WAZUH_AR_URL}/active-response",
                method="PUT",
                body={
                    "command":  "capture-traffic.sh",
                    "agent_id": "$exec.argument.agent_id",
                    "dest_ip":  "$exec.argument.dest_ip",
                    "alert_id": "$exec.argument.alert_id",
                },
                position={"x": 100, "y": 100},
                dependencies=[],
            ),
            _http_action(
                action_id="hitl_gate",
                label="HITL Gate — Await Analyst Approval",
                url=f"{FASTAPI_URL}/api/soar/hitl-gate",
                method="POST",
                body={
                    "execution_id": "$exec.execution_id",
                    "alert_id":     "$exec.argument.alert_id",
                    "pcap":         "$exec.pcap",
                    "dest_ip":      "$exec.argument.dest_ip",
                    "username":     "$exec.argument.username",
                },
                position={"x": 400, "y": 100},
                dependencies=["pcap"],
            ),
            _http_action(
                action_id="block_dest",
                label="Block Destination IP on Firewall",
                url=f"{FIREWALL_URL}/block",
                method="POST",
                body={
                    "dest_ip":  "$exec.argument.dest_ip",
                    "action":   "block",
                    "reason":   "data-exfiltration",
                    "alert_id": "$exec.argument.alert_id",
                },
                position={"x": 700, "y": 0},
                dependencies=["hitl_gate"],
            ),
            _http_action(
                action_id="lock_account",
                label="Lock Account via LDAP API",
                url=f"{LDAP_API_URL}/users/lock",
                method="POST",
                body={
                    "username": "$exec.argument.username",
                    "reason":   "data-exfiltration-lockout",
                    "alert_id": "$exec.argument.alert_id",
                },
                position={"x": 700, "y": 200},
                dependencies=["hitl_gate"],
            ),
            _http_action(
                action_id="notify",
                label="Notify Pipeline — Execution Complete",
                url=f"{FASTAPI_URL}/api/soar/execution-result",
                method="POST",
                body={
                    "execution_id": "$exec.execution_id",
                    "workflow":     "data-exfiltration-response",
                    "status":       "FINISHED",
                    "results": {
                        "pcap":         "$exec.pcap",
                        "block_dest":   "$exec.block_dest",
                        "lock_account": "$exec.lock_account",
                    },
                },
                position={"x": 1000, "y": 100},
                dependencies=["block_dest", "lock_account"],
            ),
        ],
    }


WORKFLOWS = [
    _malware_response(),
    _brute_force_response(),
    _privilege_escalation_response(),
    _data_exfiltration_response(),
]


def register_workflow(client: httpx.Client, workflow: dict[str, Any]) -> str:
    """
    POST the workflow definition to Shuffle and return its UUID.

    Args:
        client:   Synchronous httpx.Client with auth headers set.
        workflow: Complete workflow dict to register.

    Returns:
        Shuffle-assigned workflow UUID string.

    Raises:
        httpx.HTTPStatusError:  If Shuffle returns a non-2xx response.
        SystemExit:             If the response is missing an 'id' field.
    """
    url  = f"{SHUFFLE_BASE_URL}/api/v1/workflows"
    name = workflow["name"]

    print(f"  Registering '{name}' …", end=" ", flush=True)
    resp = client.post(url, json=workflow)
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        print(f"FAILED (HTTP {exc.response.status_code})")
        print(f"  Response: {exc.response.text[:500]}")
        raise

    data = resp.json()
    workflow_id: str = data.get("id") or data.get("workflow_id", "")
    if not workflow_id:
        print("FAILED (no 'id' in response)")
        print(f"  Response: {json.dumps(data)[:500]}")
        sys.exit(1)

    print(f"OK -> {workflow_id}")
    return workflow_id


def save_ids(ids: dict[str, str]) -> None:
    """
    Persist workflow name → UUID mapping to JSON file.

    Args:
        ids: Dict of {workflow_name: shuffle_uuid}.
    """
    path = Path(WORKFLOW_IDS_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(ids, fh, indent=2)
    print(f"\n✓ Workflow IDs saved → {path}")


def main() -> None:
    """Register all four workflows and save IDs."""
    if not SHUFFLE_API_KEY:
        print("ERROR: SHUFFLE_API_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    print(f"Shuffle SOAR: {SHUFFLE_BASE_URL}")
    print(f"Registering {len(WORKFLOWS)} workflows …\n")

    workflow_ids: dict[str, str] = {}

    with httpx.Client(headers=HEADERS, timeout=30.0, follow_redirects=False) as client:

        try:
            env_resp = client.get(f"{SHUFFLE_BASE_URL}/api/v1/environments")
            env_resp.raise_for_status()
            envs = env_resp.json()
            default_env_id = envs[0]["id"] if envs else "Shuffle"
        except Exception as e:
            print(f"Warning: could not fetch environments ({e}), defaulting to 'Shuffle'")
            default_env_id = "Shuffle"
            envs = []

        for wf in WORKFLOWS:
            wf["execution_env"] = default_env_id
            wf["org_id"] = envs[0].get("org_id", "") if envs else ""
            wf_id = register_workflow(client, wf)
            workflow_ids[wf["name"]] = wf_id

    print("\nRegistered workflows:")
    for name, wf_id in workflow_ids.items():
        print(f"  {name:<40} {wf_id}")

    save_ids(workflow_ids)


if __name__ == "__main__":
    main()
