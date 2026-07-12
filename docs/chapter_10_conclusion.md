# Chapter 10 — Conclusions

This chapter draws together the results of Chapters 1–9 into a concise
statement of what the **AI-SOC** project has achieved, why the design
can be trusted to work, and where genuine uncertainty remains. Where
uncertainty exists, an alternative or mitigation is given rather than
left open.

## 10.1  Restating the Problem and the Response

Enterprise SOCs generate far more alerts than analysts can triage by
hand, and the SANS 2023 SOC Survey figure cited in the research paper
(65% of analysts naming alert fatigue as their primary constraint) is
the motivating gap this project set out to close. Commercial
AI-augmented SIEM/SOAR products close part of that gap but do so by
sending telemetry to a cloud inference endpoint — a non-starter for
air-gapped, regulated, or defence environments.

**AI-SOC** answers this with a supervisor-directed, multi-agent
pipeline (Wazuh → Kafka → LangGraph agents → Shuffle SOAR) that runs
**entirely on-premises**, keeps a human in the loop for every
irreversible or low-confidence decision, and produces an immutable,
standards-compliant audit trail. The sections below assess how well
the implemented system meets that goal.

## 10.2  Conclusions Drawn from the Work

| Objective | Conclusion |
|-----------|------------|
| **RO1 — Alert volume reduction** | The noise filter (`rule_level < 3` / exclusion set), Redis-backed 24-hour deduplication, and burst correlation remove low-value alerts before any AI inference is invoked. Combined with auto-execution of high-confidence, reversible playbooks, the design-intent triage split (§5.1, Table 3) resolves the majority of alerts without analyst intervention, meeting the intent of RO1 architecturally. |
| **RO2 — Privacy-preserving inference** | No code path transmits alert content to an external API. Qwen 2.5 72B is served locally via vLLM, threat-intel lookups default to `USE_MOCK_TI=true`, and embeddings run in-process via `sentence-transformers`. `LOCAL_AI_ONLY=true` is verified as the production setting. RO2 is met by construction, not by configuration discipline alone. |
| **RO3 — Structured human accountability** | The irreversibility classification (`ISOLATE_HOST`, `DISABLE_USER`, `REVOKE_TOKEN`) is enforced at the schema level and routed through `SupervisorAgent.route_after_playbook()` regardless of LLM confidence. White-box supervisor-routing tests (WB-31…WB-41, 15/15 passing) exercise every branch of this logic directly, including the 900-second timeout path that strips irreversible steps rather than executing them unattended. RO3 is both designed and verified. |
| **RO4 — Auditable, standards-compliant response** | Every generated playbook is CACAO v2.0-structured and validated against the `SOAR_ACTION_TYPES` enum before use; every pipeline decision is written to both the `wazuh.audit` Kafka topic and the SQLite `audit_log` table. The audit-trail test (WB-47) and the non-functional observability check in §8.4 confirm this holds for both human and system-timeout decisions. |

Testing (Chapter 8) supports these conclusions with evidence rather
than assertion: **95 of 98 test cases pass (97%)** — 70/70 white-box,
20/23 black-box, 5/5 non-functional — and the six defects found during
testing (D1–D6, §8.5) were root-caused and fixed rather than worked
around (e.g. the fast-path playbook builder introduced to bring
per-alert latency down from ~3 minutes to ≤500 ms, and the SQLite
fallback added when Shuffle returns an unexpected 403).

## 10.3  Why the Design Can Be Trusted

Three properties of the implementation give confidence that it will
hold up beyond the test bench:

1. **Deterministic routing, bounded AI.** The LLM is confined to
   playbook-content generation; it never decides whether to execute,
   escalate, or skip HITL. That logic is plain, testable Python in
   `SupervisorAgent`, and the routing tests (§8.2.5) cover it directly
   rather than through the LLM's behaviour.
2. **Graceful degradation is tested, not assumed.** Kafka
   disconnect/reconnect, Shuffle unreachability, and a failing threat-
   intel adapter all have coded fallback paths, and each fallback is
   itself exercised by a passing test (BB-13, BB-15, non-functional
   resilience checks in §8.4) rather than left as an untested
   assumption.
3. **The security posture is enforced in CI, not just documented.**
   The seven-stage gate (secrets scan, SAST, SCA, container scan,
   SBOM, coverage-gated tests, DAST) runs on every PR, and per-module
   coverage floors (65–85%, §4.11) apply to the exact modules that
   implement the HITL and audit logic described above.

Taken together, the reader should be convinced that the pipeline does
what it claims for the alerts and failure modes it was built and
tested against.

## 10.4  Uncertainties and Residual Risks

Three uncertainties remain live, each with a concrete alternative or
mitigation rather than being left open:

| # | Uncertainty | Evidence | Mitigation / Alternative |
|---|-------------|----------|---------------------------|
| U1 | Sustained ingestion throughput falls short of the 100 EPS stretch target (~92 EPS measured, BB-17). | `synthetic_log_generator.py` is single-threaded asyncio, bottlenecked on Kafka producer serialisation on the test host. | The pipeline itself already absorbs a 2,000 EPS burst (BB-18); the bottleneck is the *test generator*, not the pipeline. If a higher sustained rate is required for a specific deployment, switch to a multi-process generator or tune `linger.ms`/`batch.size` (§8.3.5) — no pipeline redesign is needed. |
| U2 | Performance figures in §5.1 of the research paper are derived from architecture parameters (semaphore limits, timeout values), not a controlled empirical benchmark against a labelled, production-scale alert corpus. | Explicitly stated as a limitation (Research Paper §6.2). | Treat the current figures as a design envelope, not a guarantee. Before a production rollout, run the load test in §8.3.4 against the target site's real Wazuh alert volume and revise the concurrency parameters (`KAFKA_NUM_CONSUMER_WORKERS`, `PIPELINE_MAX_CONCURRENT_ALERTS`) if the observed rate differs. |
| U3 | Playbook *semantic* quality (is the advice actually correct for the threat, not just structurally valid YAML) is unverified — only structural/schema validation is tested. | Playbook validation checks parse correctness and `action_type` enum membership (WB-18…WB-24), not analyst-judged appropriateness. | RAG grounding from the five ChromaDB collections reduces the risk of fabricated techniques, but a human-evaluation study with practising SOC analysts (proposed in Chapter 11) is the correct way to close this gap before relying on LLM-path playbooks unsupervised. |

None of these uncertainties block the functional requirements the
system was tested against (Chapter 8, §8.3.5); they define the
boundary of what has been demonstrated versus what would need further
validation before a live, unsupervised production deployment.

## 10.5  Closing Statement

The implemented system meets its four research objectives with
architectural evidence (bounded AI autonomy, mandatory HITL gating,
immutable audit trail) and empirical evidence (97% test pass rate,
defects found and fixed, a passing seven-stage security gate). The
open items are performance-tuning and empirical-validation work,
not architectural gaps — which is the basis for the future-work
proposals in Chapter 11.
