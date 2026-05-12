# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
RAG Corpus Loader — scripts/load_rag_corpus.py

Seeds all five ChromaDB collections used by PlaybookGenAgent:
  mitre_attack    — MITRE ATT&CK technique descriptions
  nvd_cves        — Top CVE summaries
  wazuh_rules     — Key Wazuh rule descriptions
  past_incidents  — Synthetic SOC incident summaries
  nist_csf        — NIST CSF 2.0 control descriptions

Usage:
  python scripts/load_rag_corpus.py [--wazuh-rules-dir path/to/wazuh/ruleset]

The script is idempotent — re-running upserts updated documents.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = open(sys.stdout.fileno(), mode="w", encoding="utf-8", buffering=1)

from infrastructure.chroma_client import chroma_client

log = logging.getLogger(__name__)


PAST_INCIDENTS = [
    ("INC-001", "SSH Brute Force → Lateral Movement",
     "Attacker brute-forced SSH on web-server-01 (185.220.101.47), gained root, "
     "then performed pass-the-hash to DC. Mitigated by: BLOCK_IP, ISOLATE_HOST, "
     "password reset for root. MITRE: T1110, T1550.002."),
    ("INC-002", "Log4Shell Exploitation Chain",
     "CVE-2021-44228 triggered via User-Agent header. Payload established Cobalt Strike "
     "beacon. Remediation: PATCH_CVE, ISOLATE_HOST, COLLECT_FORENSICS. MITRE: T1190, T1071."),
    ("INC-003", "Ransomware — LockBit3",
     "LockBit3 ransomware propagated via SMB shares from finance workstation. "
     "Crown jewel file server encrypted. Response: ISOLATE_HOST (all segments), "
     "COLLECT_FORENSICS, restore from backup. MITRE: T1486, T1021."),
    ("INC-004", "Mimikatz Credential Dump",
     "Mimikatz detected on DC. Attacker dumped NTLM hashes. "
     "Response: DISABLE_USER (compromised accounts), RESET_PASSWORD, "
     "KILL_PROCESS, audit AD. MITRE: T1003, T1078."),
    ("INC-005", "Cryptominer Deployment via npm Supply Chain",
     "Malicious npm package event-stream installed on CI runner. "
     "xmrig process detected. Response: KILL_PROCESS, BLOCK_IP (pool), "
     "audit npm dependencies. MITRE: T1195.002, T1496."),
    ("INC-006", "Web Shell Upload — PHP",
     "PHP web shell uploaded via vulnerable file upload endpoint. "
     "Attacker executed commands as www-data. "
     "Response: ISOLATE_HOST, COLLECT_FORENSICS, patch file upload validator. "
     "MITRE: T1505.003."),
    ("INC-007", "Data Exfiltration via HTTPS",
     "500 MB uploaded to 45.33.32.156:443 over 2 minutes from file-server. "
     "DLP alert triggered. Response: BLOCK_IP, COLLECT_FORENSICS, "
     "notify legal/compliance. MITRE: T1048."),
    ("INC-008", "Container Escape — Kubernetes Worker",
     "Container escape via nsenter syscall. Attacker gained node-level privileges. "
     "Response: ISOLATE_HOST (node), COLLECT_FORENSICS, rotate node credentials. "
     "MITRE: T1611."),
    ("INC-009", "RDP Brute Force → Ransomware",
     "730 failed RDP logons then successful login as administrator. "
     "BitLocker disabled, ransomware dropped. Response: BLOCK_IP, ISOLATE_HOST, "
     "restore from clean backup. MITRE: T1110.003, T1486."),
    ("INC-010", "Tor Exit Node — C2 Communication",
     "Workstation communicated with known Tor exit node on port 443. "
     "Cobalt Strike HTTP beacon identified. Response: ISOLATE_HOST, BLOCK_IP, "
     "DISABLE_USER, full forensic image. MITRE: T1090, T1071."),
    ("INC-011", "Rootkit Detected — Rexob",
     "ossec rootcheck identified Rexob rootkit. Hidden processes detected. "
     "Response: ISOLATE_HOST, COLLECT_FORENSICS, system rebuild recommended. "
     "MITRE: T1014."),
    ("INC-012", "Privilege Escalation via Sudo",
     "Non-admin user executed sudo /bin/bash. "
     "Response: DISABLE_USER, audit sudoers, COLLECT_FORENSICS. MITRE: T1548."),
    ("INC-013", "SQL Injection → Database Dump",
     "UNION SELECT injection exfiltrated user table from web app. "
     "Response: BLOCK_IP, patch SQL injection, notify DPA. MITRE: T1190."),
    ("INC-014", "Domain Admin Account Compromise",
     "svc_backup account added to Domain Admins. "
     "Response: REVOKE_TOKEN, DISABLE_USER, audit AD logs, COLLECT_FORENSICS. "
     "MITRE: T1098."),
    ("INC-015", "Port Scan Followed by Exploitation",
     "Nmap scan from 192.168.1.200 followed by MS17-010 EternalBlue exploit. "
     "Response: BLOCK_IP, PATCH_CVE (MS17-010), ISOLATE_HOST. MITRE: T1046, T1210."),
    ("INC-016", "Phishing Campaign → BEC",
     "Phishing email lead to O365 token theft. Mailbox rule created to forward to attacker. "
     "Response: REVOKE_TOKEN, RESET_PASSWORD, notify users, CREATE_TICKET to legal. MITRE: T1566, T1114."),
    ("INC-017", "Insider Threat — Finance Data Access",
     "Finance employee accessed 2000 customer records outside business hours. "
     "DLP alert. Response: COLLECT_FORENSICS, DISABLE_USER pending investigation, "
     "CREATE_TICKET to HR. MITRE: T1078."),
    ("INC-018", "Lateral Movement — WMI",
     "Attacker used WMI to execute commands on 5 servers. "
     "Response: ISOLATE_HOST, COLLECT_FORENSICS, RESET_PASSWORD for compromised accounts. "
     "MITRE: T1047."),
    ("INC-019", "Living-Off-The-Land — PowerShell",
     "Encoded PowerShell commands downloaded and executed Cobalt Strike. "
     "Response: KILL_PROCESS, BLOCK_IP, audit PowerShell logs. MITRE: T1059.001."),
    ("INC-020", "Supply Chain — SolarWinds-style DLL Injection",
     "Signed update package contained malicious DLL. "
     "Response: ISOLATE_HOST (all affected), COLLECT_FORENSICS, vendor notification. "
     "MITRE: T1195.001."),
]


NIST_CSF_CONTROLS = [
    ("NIST-ID.AM-1", "Asset Management", "Identify and manage physical and logical assets"),
    ("NIST-ID.RA-1", "Risk Assessment", "Identify and document asset vulnerabilities"),
    ("NIST-PR.AC-1", "Identity Management", "Manage identities and credentials for authorized devices"),
    ("NIST-PR.AC-3", "Remote Access", "Manage remote access with least-privilege"),
    ("NIST-PR.DS-1", "Data at Rest Protection", "Data-at-rest is protected using encryption"),
    ("NIST-PR.IP-1", "Baseline Config", "Maintain baselines for systems including network devices"),
    ("NIST-DE.AE-1", "Anomaly Detection", "Establish baseline of network operations and expected data flows"),
    ("NIST-DE.CM-1", "Network Monitoring", "Monitor network to detect potential cybersecurity events"),
    ("NIST-DE.CM-7", "Unauthorized Activity", "Monitor for unauthorized personnel, connections, devices, and software"),
    ("NIST-RS.RP-1", "Response Planning", "Execute and maintain response plans for detected events"),
    ("NIST-RS.CO-2", "Event Reporting", "Events are reported consistent with established criteria"),
    ("NIST-RS.MI-1", "Containment", "Incidents are contained using response plans"),
    ("NIST-RS.MI-2", "Mitigation", "Incidents are mitigated using response plans"),
    ("NIST-RC.RP-1", "Recovery Planning", "Execute recovery processes to restore to normal operations"),
    ("NIST-RC.CO-1", "Communication Recovery", "Public relations managed following an event"),
    ("NIST-ID.SC-1", "Supply Chain Risk", "Identify and prioritize supply chain risks"),
    ("NIST-PR.PT-1", "Protective Technology", "Audit/log records are determined and managed"),
    ("NIST-DE.DP-1", "Detection Processes", "Roles and responsibilities for detection are defined"),
]


MITRE_TECHNIQUES = [
    ("T1110",     "Brute Force", "Adversaries may use brute force to gain access, including credential stuffing, password spraying, and password guessing."),
    ("T1078",     "Valid Accounts", "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access."),
    ("T1548",     "Abuse Elevation Control Mechanism", "Adversaries may circumvent mechanisms designed to control elevated privileges to escalate permissions."),
    ("T1550.002", "Use Alternate Authentication Material: Pass the Hash", "Adversaries may use pass-the-hash to authenticate as a user without having access to their plaintext password."),
    ("T1190",     "Exploit Public-Facing Application", "Adversaries may attempt to take advantage of a weakness in an Internet-facing host or system to initially access a network."),
    ("T1486",     "Data Encrypted for Impact", "Adversaries may encrypt data on target systems to interrupt availability to system and network resources (ransomware)."),
    ("T1098",     "Account Manipulation", "Adversaries may manipulate accounts to maintain access including adding privileges to accounts."),
    ("T1071",     "Application Layer Protocol", "Adversaries may communicate using application layer protocols to avoid detection/network filtering in C2."),
    ("T1003",     "OS Credential Dumping", "Adversaries may attempt to dump credentials to obtain account login and credential material."),
    ("T1505.003", "Server Software Component: Web Shell", "Adversaries may backdoor web servers with web shells to establish persistent access."),
    ("T1014",     "Rootkit", "Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components."),
    ("T1611",     "Escape to Host", "Adversaries may break out of a container to gain access to the underlying host."),
    ("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Adversaries may manipulate application software prior to receipt by a final consumer."),
    ("T1496",     "Resource Hijacking", "Adversaries may leverage the resources of co-opted systems to solve resource intensive problems such as cryptocurrency mining."),
    ("T1048",     "Exfiltration Over Alternative Protocol", "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel."),
    ("T1046",     "Network Service Discovery", "Adversaries may attempt to get a listing of services running on remote hosts."),
    ("T1110.003", "Brute Force: Password Spraying", "Adversaries try a single or small list of commonly used passwords against many different accounts to avoid lockouts."),
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Adversaries may abuse PowerShell commands and scripts for execution."),
    ("T1059",     "Command and Scripting Interpreter", "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."),
    ("T1047",     "Windows Management Instrumentation", "Adversaries may abuse WMI to execute malicious code."),
    ("T1566",     "Phishing", "Adversaries may send phishing messages to gain access to victim systems."),
    ("T1114",     "Email Collection", "Adversaries may target user email to collect sensitive information."),
    ("T1021",     "Remote Services", "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections."),
    ("T1210",     "Exploitation of Remote Services", "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network."),
    ("T1195.001", "Compromise Software Dependencies and Development Tools", "Adversaries may manipulate software dependencies prior to delivery to end users."),
]


def load_past_incidents() -> None:
    ids   = [f"incident-{i}" for i, _ in enumerate(PAST_INCIDENTS, 1)]
    docs  = [f"{title}\n\n{desc}" for _, title, desc in PAST_INCIDENTS]
    metas = [{"incident_id": inc_id, "title": title} for inc_id, title, _ in PAST_INCIDENTS]
    chroma_client.upsert_documents("past_incidents", ids=ids, documents=docs, metadatas=metas)
    print(f"[OK] Loaded {len(docs)} past incidents into ChromaDB")


def load_nist_csf() -> None:
    ids   = [ctrl[0] for ctrl in NIST_CSF_CONTROLS]
    docs  = [f"{ctrl[0]} — {ctrl[1]}: {ctrl[2]}" for ctrl in NIST_CSF_CONTROLS]
    metas = [{"control_id": ctrl[0], "category": ctrl[1]} for ctrl in NIST_CSF_CONTROLS]
    chroma_client.upsert_documents("nist_csf", ids=ids, documents=docs, metadatas=metas)
    print(f"[OK] Loaded {len(docs)} NIST CSF controls into ChromaDB")


def load_mitre_attack() -> None:
    ids   = [t[0] for t in MITRE_TECHNIQUES]
    docs  = [f"{t[0]} — {t[1]}: {t[2]}" for t in MITRE_TECHNIQUES]
    metas = [{"technique_id": t[0], "name": t[1]} for t in MITRE_TECHNIQUES]
    chroma_client.upsert_documents("mitre_attack", ids=ids, documents=docs, metadatas=metas)
    print(f"[OK] Loaded {len(docs)} MITRE ATT&CK techniques into ChromaDB")


def load_wazuh_rules(rules_dir: str) -> None:
    """Parse Wazuh XML rule files from the ruleset directory."""
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        print(f"[SKIP] Wazuh rules dir not found: {rules_dir} — skipping")
        return

    xml_files = list(rules_path.glob("*.xml"))
    ids, docs, metas = [], [], []

    for xml_file in xml_files[:20]:
        try:
            tree = ET.parse(xml_file)
            for rule in tree.findall(".//rule"):
                rid = rule.get("id")
                level = rule.get("level", "0")
                desc_el = rule.find("description")
                if rid and desc_el is not None and desc_el.text:
                    ids.append(f"wazuh_rule_{rid}")
                    docs.append(f"Rule {rid} (level {level}): {desc_el.text.strip()}")
                    metas.append({"rule_id": rid, "level": level, "file": xml_file.name})
        except Exception as exc:
            log.warning("Failed to parse %s: %s", xml_file, exc)

    if ids:
        chroma_client.upsert_documents("wazuh_rules", ids=ids, documents=docs, metadatas=metas)
        print(f"[OK] Loaded {len(docs)} Wazuh rules from {len(xml_files)} XML files")
    else:
        print("[WARN] No Wazuh rules parsed")


def load_nvd_cves() -> None:
    """Load a curated list of high-impact CVEs into ChromaDB."""
    cves = [
        ("CVE-2021-44228", "Log4Shell", "CRITICAL", "9.3",
         "Apache Log4j2 <=2.14.1 JNDI features allow RCE via crafted log messages."),
        ("CVE-2022-22965", "Spring4Shell", "CRITICAL", "9.8",
         "Spring Framework RCE via data binding (Spring MVC / WebFlux on JDK 9+)."),
        ("CVE-2017-0144", "EternalBlue", "CRITICAL", "9.3",
         "SMBv1 RCE vulnerability used by WannaCry and NotPetya ransomware."),
        ("CVE-2021-34527", "PrintNightmare", "CRITICAL", "9.0",
         "Windows Print Spooler allows arbitrary code execution with SYSTEM privileges."),
        ("CVE-2021-26084", "Confluence OGNL", "CRITICAL", "9.8",
         "Atlassian Confluence OGNL injection allows unauthenticated RCE."),
        ("CVE-2022-1388", "F5 BIG-IP Auth Bypass", "CRITICAL", "9.8",
         "F5 BIG-IP allows undisclosed requests to bypass authentication."),
        ("CVE-2023-44487", "HTTP/2 Rapid Reset", "HIGH", "7.5",
         "HTTP/2 protocol allows DoS via rapid stream resets."),
        ("CVE-2024-21762", "FortiOS OOB Write", "CRITICAL", "9.6",
         "Out-of-bounds write in FortiOS SSL-VPN allows RCE."),
        ("CVE-2023-23397", "Outlook NTLM Leak", "CRITICAL", "9.8",
         "Microsoft Outlook allows forced NTLM hash capture via crafted email."),
        ("CVE-2023-4966", "Citrix Bleed", "CRITICAL", "9.4",
         "Citrix NetScaler memory leak exposes session tokens."),
    ]
    ids   = [c[0] for c in cves]
    docs  = [f"{c[0]} ({c[1]}) — Severity: {c[2]}, CVSS: {c[3]}. {c[4]}" for c in cves]
    metas = [{"cve_id": c[0], "name": c[1], "severity": c[2], "cvss_score": c[3]} for c in cves]
    chroma_client.upsert_documents("nvd_cves", ids=ids, documents=docs, metadatas=metas)
    print(f"[OK] Loaded {len(docs)} NVD CVEs into ChromaDB")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Load RAG corpus into ChromaDB")
    parser.add_argument(
        "--wazuh-rules-dir",
        default=str(Path(__file__).parent.parent.parent / "wazuh" / "ruleset" / "rules"),
        help="Path to Wazuh rules directory (XML files)",
    )
    args = parser.parse_args()

    print("Loading RAG corpus into ChromaDB...")
    load_mitre_attack()
    load_nvd_cves()
    load_wazuh_rules(args.wazuh_rules_dir)
    load_past_incidents()
    load_nist_csf()

    print("\nCollection sizes:")
    for coll in ["mitre_attack", "nvd_cves", "wazuh_rules", "past_incidents", "nist_csf"]:
        count = chroma_client.collection_count(coll)
        print(f"  {coll}: {count} documents")

    print("\n[DONE] RAG corpus loaded.")


if __name__ == "__main__":
    main()
