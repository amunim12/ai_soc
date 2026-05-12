# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Playbook Generation Agent — Agent 3

Retrieves RAG context from ChromaDB (5 collections),
calls Llama 3.3 70B Instruct (via vLLM) to generate a structured YAML playbook,
and returns a Playbook object to supervisor state.

RAG Collections queried:
  mitre_attack, nvd_cves, wazuh_rules, past_incidents, nist_csf
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime

from schemas.alert import WazuhAlert
from schemas.playbook import Playbook, PlaybookPhase, PlaybookStep
from schemas.audit import StepLog
from orchestration.state import PipelineState
from infrastructure.kafka_client import kafka_producer
from infrastructure.chroma_client import chroma_client
from infrastructure.llm_client import llm_client
from infrastructure.redis_client import redis_client

PLAYBOOK_CACHE_TTL_SECONDS = 300
RAG_CTX_CACHE_TTL_SECONDS  = 3600


def _severity_bucket(severity: str | None) -> str:
    s = (severity or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return "high"
    return "low"

log = logging.getLogger(__name__)

RAG_COLLECTIONS = ["mitre_attack", "nvd_cves", "wazuh_rules", "past_incidents", "nist_csf"]
RAG_N_PER_COLLECTION = 1
RAG_MAX_TOTAL_CHUNKS = 3

SYSTEM_PROMPT = """
You are a senior SOC analyst. Generate a structured incident response
playbook in YAML. Every step must map to a MITRE ATT&CK technique and
specify a SOAR action type from this list:
  BLOCK_IP | ISOLATE_HOST | DISABLE_USER | RESET_PASSWORD |
  KILL_PROCESS | CREATE_TICKET | NOTIFY_ANALYST |
  COLLECT_FORENSICS | PATCH_CVE | REVOKE_TOKEN

Output ONLY valid YAML. No markdown fences. No commentary.
Each phase (containment / eradication / recovery) must have steps.
Include: estimated_duration_minutes, confidence_score (0.0-1.0),
auto_approve (true only if confidence > 0.90 and no irreversible steps).

YAML structure:
title: <string>
summary: <string>
confidence_score: <float>
estimated_duration_minutes: <int>
auto_approve: <bool>
containment:
  steps:
    - step_id: C1
      action_type: BLOCK_IP
      description: <string>
      target: <string>
      mitre_technique: T1110
      estimated_duration_minutes: 5
      requires_confirmation: false
      parameters: {}
eradication:
  steps: [...]
recovery:
  steps: [...]
""".strip()


class PlaybookGenAgent:
    """
    RAG-backed playbook generator.
    Retrieves context → builds prompt → calls Llama 3.3 via vLLM → parses YAML → returns Playbook.
    """


    async def _retrieve_context(self, state: PipelineState) -> tuple[str, int]:
        """
        Query all 5 RAG collections in parallel and return (context_string, chunk_count).
        Results are memoised in-process by (category, primary_mitre) for
        RAG_CTX_CACHE_TTL_SECONDS so repeat traffic skips the Chroma round-trip.
        Falls back gracefully if ChromaDB is unavailable.
        """
        alert    = state["alert"]
        analysis = state.get("analysis")
        enrich   = state.get("enrichment")

        mitre_list = analysis.mitre_techniques if analysis and analysis.mitre_techniques else []
        primary_mitre = mitre_list[0] if mitre_list else "-"
        category = (alert.alert_category or "generic").lower()
        cache_key = f"{category}:{primary_mitre}"

        redis_key = f"rag_ctx:{cache_key}"
        cached_raw = await redis_client.get(redis_key)
        if cached_raw:
            try:
                cached_data = json.loads(cached_raw)
                log.debug("[PlaybookGen] RAG cache hit %s", redis_key)
                return cached_data["ctx"], cached_data["n"]
            except Exception:
                pass

        query = " ".join(filter(None, [
            alert.rule_description,
            " ".join(mitre_list),
            alert.alert_category,
            str(enrich.known_threat_actor) if enrich else "",


            " ".join(ref.cve_id for ref in enrich.cve_references[:3]) if enrich else "",
        ]))

        results = await asyncio.gather(
            *(
                asyncio.to_thread(
                    chroma_client.query_collection, coll, query, RAG_N_PER_COLLECTION
                )
                for coll in RAG_COLLECTIONS
            ),
            return_exceptions=True,
        )
        all_chunks: list[str] = []
        for coll, result in zip(RAG_COLLECTIONS, results):
            if isinstance(result, Exception):
                log.warning("[PlaybookGen] RAG query failed for %s: %s", coll, result)
                continue
            all_chunks.extend(result)


        seen: set[str] = set()
        deduplicated: list[str] = []
        for chunk in all_chunks:
            if chunk not in seen:
                seen.add(chunk)
                deduplicated.append(chunk)
            if len(deduplicated) >= RAG_MAX_TOTAL_CHUNKS:
                break

        context_str = "\n\n---\n\n".join(deduplicated) if deduplicated else "[No RAG context available]"
        log.info("[PlaybookGen] RAG retrieved %d chunks from %d collections",
                 len(deduplicated), len(RAG_COLLECTIONS))
        await redis_client.set(
            redis_key,
            json.dumps({"ctx": context_str, "n": len(deduplicated)}),
            ex=RAG_CTX_CACHE_TTL_SECONDS,
        )
        return context_str, len(deduplicated)


    def _build_user_prompt(
        self, state: PipelineState, context: str, hitl_notes: str
    ) -> str:
        """
        Slim prompt: only the fields the playbook actually needs.
        Full JSON dumps of alert/analysis/enrichment were dominating TTFT on small models.
        """
        alert    = state["alert"]
        analysis = state.get("analysis")
        enrich   = state.get("enrichment")

        mitre = (analysis.mitre_techniques if analysis and analysis.mitre_techniques else []) or []
        top_cves = [ref.cve_id for ref in (enrich.cve_references if enrich else [])[:1]]
        actor = str(enrich.known_threat_actor) if enrich and enrich.known_threat_actor else "-"

        header = (
            f"rule={alert.rule_id} level={alert.rule_level} sev={alert.severity} "
            f"category={alert.alert_category} "
            f"host={alert.agent_name or alert.agent_id} "
            f"user={alert.user or '-'} "
            f"src={alert.source_ip or '-'} dst={alert.destination_ip or '-'}"
        )

        return (
            f"ALERT: {header}\n"
            f"DESCRIPTION: {alert.rule_description}\n"
            f"MITRE: {', '.join(mitre) if mitre else '-'}\n"
            f"CVEs: {', '.join(top_cves) if top_cves else '-'}\n"
            f"THREAT_ACTOR: {actor}\n"
            f"CONTEXT:\n{context}"
            f"{hitl_notes}\n"
            f"Generate the complete incident response playbook."
        ).strip()


    async def run(self, state: PipelineState) -> PipelineState:
        alert = state["alert"]
        log.info("[PlaybookGen] Generating playbook for alert %s", alert.id)

        analysis = state.get("analysis")
        hitl_dec = state.get("hitl_decision")
        hitl_edit = bool(hitl_dec and hitl_dec.action == "EDIT" and hitl_dec.notes)

        fast_mode = os.getenv("PLAYBOOK_FAST_MODE", "true").lower() == "true"
        category = (alert.alert_category or "generic").lower()
        has_template = category in _CATEGORY_TEMPLATES

        chunk_count = 0


        if fast_mode and has_template and not hitl_edit:
            log.info("[PlaybookGen] Fast path — contextual template for category=%s", category)
            playbook = _contextual_playbook(alert, analysis)
        else:
            hitl_notes = ""
            if hitl_edit:
                hitl_notes = f"\nANALYST NOTES (from HITL review):\n{hitl_dec.notes}"


            mitre_list = analysis.mitre_techniques if analysis and analysis.mitre_techniques else []
            primary_mitre = mitre_list[0] if mitre_list else "-"
            cache_key = f"playbook_cache:{category}:{primary_mitre}:{_severity_bucket(alert.severity)}"
            cached_yaml = None if hitl_edit else await redis_client.get(cache_key)

            playbook = None
            if cached_yaml:
                try:
                    playbook = Playbook.from_yaml(cached_yaml)
                    log.info("[PlaybookGen] Cache hit %s", cache_key)
                except Exception as exc:
                    log.warning("[PlaybookGen] Cached playbook parse failed: %s — regenerating", exc)
                    playbook = None

            if playbook is None:
                context, chunk_count = await self._retrieve_context(state)
                user_prompt = self._build_user_prompt(state, context, hitl_notes)

                try:
                    playbook_yaml = await llm_client.call(
                        system_prompt=SYSTEM_PROMPT,
                        user_prompt=user_prompt,
                        max_tokens=400,
                        temperature=0.2,
                    )
                    playbook = Playbook.from_yaml(playbook_yaml)
                    if not hitl_edit:
                        await redis_client.set(
                            cache_key, playbook_yaml, ex=PLAYBOOK_CACHE_TTL_SECONDS
                        )
                except Exception as exc:
                    log.error(
                        "[PlaybookGen] LLM/parse failed (%s: %s) — falling back to contextual playbook",
                        type(exc).__name__, exc,
                    )
                    playbook = _contextual_playbook(alert, analysis)

        playbook.alert_id      = alert.id
        playbook.generated_at  = datetime.utcnow()
        playbook.rag_chunks_used = chunk_count

        await kafka_producer.send("wazuh.playbooks", playbook)
        state["playbook"]       = playbook
        state["confidence"]     = playbook.confidence_score
        state["pipeline_stage"] = "playbook_generated"
        state.setdefault("audit_trail", []).append(
            StepLog(
                agent="playbook_gen",
                result={
                    "confidence": round(playbook.confidence_score, 4),
                    "steps_total": playbook.total_steps,
                    "has_irreversible": playbook.has_irreversible_steps,
                    "rag_chunks_used": chunk_count,
                    "auto_approve": playbook.auto_approve,
                },
                ts=datetime.utcnow(),
            )
        )
        log.info("[PlaybookGen] Done — confidence=%.2f steps=%d irreversible=%s",
                  playbook.confidence_score, playbook.total_steps,
                  playbook.has_irreversible_steps)
        return state


_CATEGORY_TEMPLATES: dict[str, dict[str, list[dict]]] = {
    "authentication_failures": {
        "containment": [
            {"action_type": "BLOCK_IP", "mitre": "T1110",
             "desc": "Block source IP {src_ip} at perimeter firewall — brute force attempt",
             "target": "{src_ip}", "mins": 5},
            {"action_type": "DISABLE_USER", "mitre": "T1110",
             "desc": "Temporarily disable target account {user} pending investigation",
             "target": "{user}", "mins": 5, "confirm": True},
        ],
        "eradication": [
            {"action_type": "RESET_PASSWORD", "mitre": "T1110",
             "desc": "Force password reset for {user} and invalidate active sessions",
             "target": "{user}", "mins": 10},
            {"action_type": "REVOKE_TOKEN", "mitre": "T1550",
             "desc": "Revoke any OAuth / SSO tokens issued to {user}",
             "target": "{user}", "mins": 5, "confirm": True},
        ],
        "recovery": [
            {"action_type": "NOTIFY_ANALYST", "mitre": None,
             "desc": "Notify account owner {user} via secondary channel and re-enable after verification",
             "target": "{user}", "mins": 15},
        ],
    },
    "privilege_escalation": {
        "containment": [
            {"action_type": "ISOLATE_HOST", "mitre": "T1068",
             "desc": "Isolate host {host} from production network",
             "target": "{host}", "mins": 5, "confirm": True},
            {"action_type": "KILL_PROCESS", "mitre": "T1068",
             "desc": "Kill suspicious elevated process on {host}",
             "target": "{host}", "mins": 3},
        ],
        "eradication": [
            {"action_type": "COLLECT_FORENSICS", "mitre": "T1005",
             "desc": "Collect memory dump and process tree from {host}",
             "target": "{host}", "mins": 15},
            {"action_type": "DISABLE_USER", "mitre": "T1078",
             "desc": "Disable user {user} account until audit complete",
             "target": "{user}", "mins": 5, "confirm": True},
        ],
        "recovery": [
            {"action_type": "PATCH_CVE", "mitre": "T1068",
             "desc": "Patch privilege-escalation CVE on {host} and restore from clean image",
             "target": "{host}", "mins": 60},
        ],
    },
    "web_attack": {
        "containment": [
            {"action_type": "BLOCK_IP", "mitre": "T1190",
             "desc": "Block attacker IP {src_ip} at WAF",
             "target": "{src_ip}", "mins": 5},
            {"action_type": "COLLECT_FORENSICS", "mitre": "T1190",
             "desc": "Capture web server logs and request bodies from {host}",
             "target": "{host}", "mins": 10},
        ],
        "eradication": [
            {"action_type": "PATCH_CVE", "mitre": "T1190",
             "desc": "Apply WAF rule / patch vulnerable endpoint on {host}",
             "target": "{host}", "mins": 30},
        ],
        "recovery": [
            {"action_type": "CREATE_TICKET", "mitre": None,
             "desc": "Open ticket with app team to review exploited endpoint",
             "target": "{host}", "mins": 10},
        ],
    },
    "lateral_movement": {
        "containment": [
            {"action_type": "ISOLATE_HOST", "mitre": "T1021",
             "desc": "Isolate source host {host} — lateral movement detected toward {dst_ip}",
             "target": "{host}", "mins": 5, "confirm": True},
            {"action_type": "BLOCK_IP", "mitre": "T1021",
             "desc": "Block east-west traffic from {src_ip} to {dst_ip}",
             "target": "{dst_ip}", "mins": 5},
        ],
        "eradication": [
            {"action_type": "DISABLE_USER", "mitre": "T1078",
             "desc": "Disable user {user} pending credential audit",
             "target": "{user}", "mins": 5, "confirm": True},
            {"action_type": "COLLECT_FORENSICS", "mitre": "T1005",
             "desc": "Collect auth logs and SMB/WMI traces across affected segment",
             "target": "{host}", "mins": 20},
        ],
        "recovery": [
            {"action_type": "RESET_PASSWORD", "mitre": "T1110",
             "desc": "Rotate credentials for {user} and service accounts on {host}",
             "target": "{user}", "mins": 15},
        ],
    },
    "malware": {
        "containment": [
            {"action_type": "ISOLATE_HOST", "mitre": "T1486",
             "desc": "Isolate infected host {host} from network",
             "target": "{host}", "mins": 5, "confirm": True},
            {"action_type": "KILL_PROCESS", "mitre": "T1059",
             "desc": "Terminate malicious process tree on {host}",
             "target": "{host}", "mins": 3},
        ],
        "eradication": [
            {"action_type": "COLLECT_FORENSICS", "mitre": "T1005",
             "desc": "Capture disk image and memory dump from {host} for analysis",
             "target": "{host}", "mins": 20},
            {"action_type": "BLOCK_IP", "mitre": "T1071",
             "desc": "Block C2 destination {dst_ip} at egress firewall",
             "target": "{dst_ip}", "mins": 5},
        ],
        "recovery": [
            {"action_type": "PATCH_CVE", "mitre": "T1190",
             "desc": "Re-image {host} from known-good baseline and apply patches",
             "target": "{host}", "mins": 90},
        ],
    },
    "c2": {
        "containment": [
            {"action_type": "BLOCK_IP", "mitre": "T1071",
             "desc": "Block C2 server {dst_ip} at egress firewall",
             "target": "{dst_ip}", "mins": 5},
            {"action_type": "ISOLATE_HOST", "mitre": "T1071",
             "desc": "Isolate beaconing host {host}",
             "target": "{host}", "mins": 5, "confirm": True},
        ],
        "eradication": [
            {"action_type": "KILL_PROCESS", "mitre": "T1059",
             "desc": "Kill beaconing process on {host}",
             "target": "{host}", "mins": 3},
            {"action_type": "COLLECT_FORENSICS", "mitre": "T1005",
             "desc": "Capture network PCAP and process list from {host}",
             "target": "{host}", "mins": 15},
        ],
        "recovery": [
            {"action_type": "PATCH_CVE", "mitre": None,
             "desc": "Re-image {host} and update EDR signatures",
             "target": "{host}", "mins": 60},
        ],
    },
    "data_exfiltration": {
        "containment": [
            {"action_type": "BLOCK_IP", "mitre": "T1048",
             "desc": "Block exfil destination {dst_ip} at egress",
             "target": "{dst_ip}", "mins": 5},
            {"action_type": "ISOLATE_HOST", "mitre": "T1048",
             "desc": "Isolate {host} to stop ongoing data transfer",
             "target": "{host}", "mins": 5, "confirm": True},
        ],
        "eradication": [
            {"action_type": "DISABLE_USER", "mitre": "T1078",
             "desc": "Disable user {user} and audit accessed data",
             "target": "{user}", "mins": 10, "confirm": True},
            {"action_type": "COLLECT_FORENSICS", "mitre": "T1005",
             "desc": "Capture DLP logs and file access history on {host}",
             "target": "{host}", "mins": 20},
        ],
        "recovery": [
            {"action_type": "CREATE_TICKET", "mitre": None,
             "desc": "Open incident ticket with legal and compliance teams",
             "target": "{user}", "mins": 15},
        ],
    },
    "recon": {
        "containment": [
            {"action_type": "BLOCK_IP", "mitre": "T1595",
             "desc": "Block scanning source {src_ip}",
             "target": "{src_ip}", "mins": 5},
        ],
        "eradication": [
            {"action_type": "COLLECT_FORENSICS", "mitre": "T1595",
             "desc": "Log full scan pattern from {src_ip} for threat intel",
             "target": "{src_ip}", "mins": 10},
        ],
        "recovery": [
            {"action_type": "CREATE_TICKET", "mitre": None,
             "desc": "Open low-priority ticket for recon tracking",
             "target": "{src_ip}", "mins": 5},
        ],
    },
    "authentication_success": {
        "containment": [
            {"action_type": "NOTIFY_ANALYST", "mitre": "T1078",
             "desc": "Verify unusual successful auth for {user} from {src_ip}",
             "target": "{user}", "mins": 10},
        ],
        "eradication": [
            {"action_type": "RESET_PASSWORD", "mitre": "T1078",
             "desc": "Force password reset for {user} if auth deemed suspicious",
             "target": "{user}", "mins": 10},
        ],
        "recovery": [
            {"action_type": "CREATE_TICKET", "mitre": None,
             "desc": "Log event in user access audit trail",
             "target": "{user}", "mins": 5},
        ],
    },
    "container_security": {
        "containment": [
            {"action_type": "KILL_PROCESS", "mitre": "T1610",
             "desc": "Terminate suspicious container on {host}",
             "target": "{host}", "mins": 3},
        ],
        "eradication": [
            {"action_type": "COLLECT_FORENSICS", "mitre": "T1005",
             "desc": "Snapshot container filesystem and runtime logs",
             "target": "{host}", "mins": 15},
        ],
        "recovery": [
            {"action_type": "PATCH_CVE", "mitre": None,
             "desc": "Redeploy container from hardened base image",
             "target": "{host}", "mins": 30},
        ],
    },
    "supply_chain": {
        "containment": [
            {"action_type": "ISOLATE_HOST", "mitre": "T1195",
             "desc": "Isolate build/CI host {host} — supply chain compromise suspected",
             "target": "{host}", "mins": 5, "confirm": True},
        ],
        "eradication": [
            {"action_type": "COLLECT_FORENSICS", "mitre": "T1005",
             "desc": "Audit recent package installs and build artifacts on {host}",
             "target": "{host}", "mins": 30},
        ],
        "recovery": [
            {"action_type": "PATCH_CVE", "mitre": None,
             "desc": "Rebuild pipeline from verified package lockfile",
             "target": "{host}", "mins": 60},
        ],
    },
}


def _contextual_playbook(alert: WazuhAlert, analysis) -> Playbook:
    """
    Build a deterministic playbook tailored to the incoming alert.

    Uses the alert category to pick a template, then fills in live fields
    (source_ip, destination_ip, user, agent_name) and MITRE techniques
    from the analysis result. No LLM call — runs in milliseconds.
    """
    category = (alert.alert_category or "generic").lower()
    template = _CATEGORY_TEMPLATES.get(category)

    ctx = {
        "src_ip": alert.source_ip or "unknown",
        "dst_ip": alert.destination_ip or "unknown",
        "user":   alert.user or "unknown",
        "host":   alert.agent_name or alert.agent_id,
    }


    if template is None:
        template = {
            "containment": [
                {"action_type": "NOTIFY_ANALYST", "mitre": None,
                 "desc": f"Review alert: {alert.rule_description}",
                 "target": "{host}", "mins": 10},
                {"action_type": "COLLECT_FORENSICS", "mitre": None,
                 "desc": "Collect surrounding logs from {host} for triage",
                 "target": "{host}", "mins": 15},
            ],
            "eradication": [
                {"action_type": "CREATE_TICKET", "mitre": None,
                 "desc": "Create investigation ticket with full alert context",
                 "target": "{host}", "mins": 5},
            ],
            "recovery": [
                {"action_type": "NOTIFY_ANALYST", "mitre": None,
                 "desc": "Close investigation after analyst verdict",
                 "target": "{host}", "mins": 5},
            ],
        }


    analysis_mitre = (analysis.mitre_techniques if analysis and analysis.mitre_techniques else [])
    primary_mitre = analysis_mitre[0] if analysis_mitre else None

    phases: dict[str, PlaybookPhase] = {}
    total_mins = 0
    for phase_name in ("containment", "eradication", "recovery"):
        steps: list[PlaybookStep] = []
        for i, s in enumerate(template[phase_name], start=1):
            desc = s["desc"].format(**ctx)
            target = s["target"].format(**ctx)
            mitre = primary_mitre or s.get("mitre")
            slug = f"{phase_name[0].upper()}{i}"
            steps.append(PlaybookStep(
                step_id=slug,
                name=slug,
                action_type=s["action_type"],
                description=desc,
                target=target,
                mitre_technique=mitre,
                estimated_duration_minutes=s["mins"],
                requires_confirmation=s.get("confirm", False),
            ))
            total_mins += s["mins"]
        phases[phase_name] = PlaybookPhase(phase_name=phase_name, steps=steps)


    confidence = 0.92 if category in _CATEGORY_TEMPLATES else 0.70

    has_irrev = any(p.has_irreversible for p in phases.values())
    auto_approve = confidence >= 0.90 and not has_irrev

    title = f"{category.replace('_', ' ').title()} Response — {ctx['host']}"
    summary = (
        f"Automated response playbook for {category.replace('_', ' ')} alert "
        f"(rule {alert.rule_id}, level {alert.rule_level}) on {ctx['host']}."
    )

    return Playbook(
        alert_id=alert.id,
        title=title,
        name=title,
        summary=summary,
        description=summary,
        phases=phases,
        confidence_score=confidence,
        estimated_duration_minutes=total_mins or 30,
        auto_approve=auto_approve,
        labels=[category, f"rule_{alert.rule_id}", alert.severity.lower()],
    )


playbook_gen_agent = PlaybookGenAgent()
