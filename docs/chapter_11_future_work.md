# Chapter 11 — Future Work

This chapter proposes work that goes beyond the scope of the current
project but builds directly on it. Each proposal is scoped in enough
detail that a future student could pick it up, understand why it
matters, and appraise the amount of work involved without needing to
reverse-engineer intent from the codebase alone. Items are grouped
into (A) work already underway that should be completed, (B)
substantial new capabilities on the existing pipeline, (C) an
empirical evaluation study, and (D) applying the same architecture to
other domains.

## 11.1  A — Completing the On-Prem K3s Migration (in progress)

At the time of writing, a Kubernetes migration is **already underway**
on the `feature/k3s-deployment` branch, motivated by a real gap: the
CI/CD pipeline's `deploy-k3s` stage (`release.yml`) already runs
`kubectl set image` / `kubectl rollout status`, but no manifests or
self-hosted runner existed for it to act on. The design is recorded in
`docs/superpowers/specs/2026-07-10-k3s-core-pipeline-deployment-design.md`.

**Completed so far:**

| Component | Kind | Status |
|-----------|------|--------|
| `namespace.yaml`, `configmap.yaml`, `secret.example.yaml` | Cluster bootstrap | Done |
| Kafka, Redis, PostgreSQL, ChromaDB | `StatefulSet` + `ClusterIP Service` | Done (`k8s/infra/`) |
| `ai-soc-api` | `Deployment` + `NodePort Service` | Done (`k8s/app/`) |
| `ai-soc-orchestrator` | `Deployment` (previously a bare `python -m` process) | Done |
| `ai-soc-wazuh-bridge` | `Deployment` (previously a bare `python -m` process) | Done |

**Remaining work for a future student:**

1. **Ingress and TLS.** The API is currently reachable via `NodePort`
   only (§ design doc). Add an ingress controller (e.g. Traefik,
   already bundled with K3s) with TLS termination so the dashboard and
   Shuffle webhook callback are not exposed on a raw node port.
2. **Horizontal scaling for the orchestrator.** The orchestrator runs
   16 Kafka consumer workers in-process (`KAFKA_NUM_CONSUMER_WORKERS`).
   Converting this to multiple orchestrator replicas with Kafka
   consumer-group rebalancing (instead of one pod with 16 internal
   workers) would let K3s scale the pipeline horizontally under load,
   and is a natural follow-on to the throughput ceiling identified in
   Chapter 10 (U1).
3. **NetworkPolicies.** The StatefulSets are `ClusterIP`-only by
   design, but no `NetworkPolicy` resources currently restrict pod-to-
   pod traffic within the `ai-soc` namespace. Adding them would bring
   the cluster closer to the EAL4-aligned posture claimed for the CI
   pipeline (Research Paper §4.11).
4. **Backup/restore strategy for PersistentVolumes.** PostgreSQL
   (HITL + audit log) and ChromaDB (RAG corpus) are stateful and
   currently have no documented backup procedure once running under
   K3s — this is a compliance gap given the audit-immutability claims
   in §10.2 (RO4).
5. **Deciding the fate of the Docker-Compose components.** Wazuh SIEM,
   Shuffle SOAR, Prometheus/Grafana, and vLLM are explicitly **out of
   scope** for this migration and remain on Docker Compose on the same
   host (design doc, "Out of scope" table). A future project could
   either (a) formally document this hybrid boundary as the permanent
   target architecture, or (b) extend the migration to bring Shuffle
   and the monitoring stack into the cluster as well — GPU scheduling
   for vLLM is a separate, harder problem (device plugins, `nvidia-
   smi` in-cluster) and should stay a distinct future item rather than
   be bundled in.
6. **Multi-node HA.** The current manifests target a **single-node**
   K3s install. A follow-on project could replicate the StatefulSets
   (Kafka in KRaft multi-broker mode, Postgres with a standby, Redis
   Sentinel) across a small K3s cluster, closing the single-node
   limitation noted in the Research Paper (§6.2).

## 11.2  B — Substantial New Capabilities

These four items were identified as future scope in the accompanying
research paper (§6.3) and remain unimplemented; each is restated here
with enough detail to scope as an independent study.

### 11.2.1  Federated Threat Intelligence (STIX/TAXII 2.1)

Replace the current point-to-point MISP dependency with a federated
sharing mechanism using the STIX/TAXII 2.1 standard, so that
participating organisations can exchange anonymised IOC observations
without pooling raw data centrally. This extends the privacy-by-design
principle already applied to LLM inference (CPP-1) to the threat-
intelligence layer. Scope includes: a TAXII 2.1 client adapter
alongside the existing `ThreatIntelAgent` adapters (VirusTotal, OTX,
Shodan, NVD, GeoIP2), an anonymisation step before any outbound
publication of locally observed IOCs, and a trust-scoring mechanism
for federated sources analogous to the existing composite-score
weighting (§4.5).

### 11.2.2  Analyst Feedback Loop for LLM Alignment

Capture HITL `EDIT` (analyst rewrote the playbook) and `REJECT`
decisions as labelled examples, and use them for supervised fine-
tuning or preference alignment (RLHF/DPO) of the locally-hosted model.
This would let the model improve on organisation-specific response
patterns over time, entirely on-premises. Scope includes: a data
pipeline that pairs each `hitl_reviews` record with its final analyst
decision, a review process to prevent adversarial drift (the current
design deliberately has *no* autonomous learning loop, CPP-4, to avoid
this risk), and an evaluation harness to confirm fine-tuning improves
playbook acceptance rate rather than degrading it.

### 11.2.3  Real-Time Streaming HITL Interface

The HITL background task currently polls the `hitl_decisions` SQLite
table every 5 seconds (§4.7). Replacing this with PostgreSQL
`LISTEN/NOTIFY` (now that Postgres is the audit store, per the K3s
migration in §11.1) or a WebSocket push channel from the FastAPI
backend would cut HITL response latency from up to 5 seconds to
sub-second, which matters for CRITICAL-severity alerts sitting in the
900-second review window.

### 11.2.4  Multi-Tenant Deployment

Extend the existing RBAC model (`analyst`/`admin` roles, §4.10) to
support multiple tenancy levels — for example, a Managed Security
Service Provider (MSP) operating one AI-SOC instance across several
client SOCs. Scope includes Kafka topic isolation per tenant, schema-
level data segregation in Postgres/ChromaDB, and a tenant-scoped HITL
queue so one client's analysts never see another client's alerts.

## 11.3  C — Empirical Evaluation Study

Chapter 10 (§10.4, U2–U3) identifies that current performance and
playbook-quality figures are design-derived rather than empirically
measured. A dedicated follow-on study should:

1. Assemble a labelled alert corpus (or use a public dataset such as
   CIRA-CIC-DoHBrw or a Wazuh-compatible log set) and measure AI-SOC's
   triage precision/recall/F1 against a rule-only Wazuh baseline.
2. Run a structured human-evaluation session with practising SOC
   analysts scoring generated playbooks for appropriateness,
   completeness, and executability — closing the semantic-quality gap
   noted in §10.4 (U3).
3. Load-test the K3s-deployed pipeline (§11.1) against a realistic
   sustained EPS profile from a real Wazuh deployment, rather than the
   synthetic generator used in Chapter 8, to validate or revise the
   concurrency parameters in Research Paper Table 2.

This is substantial enough to be its own subsequent project: it needs
a data-collection phase, an analyst-recruitment phase (for the human
evaluation), and a statistics-driven write-up — not something that can
be bolted onto a single sprint.

## 11.4  D — Applying the Same Concept to Other Domains

The core pattern behind AI-SOC — **deterministic pre-filtering →
AI-assisted enrichment/response generation → mandatory human approval
for irreversible actions → immutable audit trail** — is not specific
to network security. It generalises to any domain where automated
systems propose high-stakes actions that a human must remain
accountable for. Candidate follow-on projects, each a full FYP-scale
effort in its own right:

| Domain | "Alert" becomes | "Playbook" becomes | HITL gate example |
|--------|------------------|---------------------|--------------------|
| Banking fraud / AML | Flagged transaction or account pattern | Freeze account, block card, file a Suspicious Activity Report | Compliance officer must approve any account freeze or SAR filing |
| Clinical decision support | Abnormal vitals / lab result trend | Recommended care escalation | Attending physician must approve any irreversible intervention (e.g. medication change) |
| DevOps / SRE incident response | Prometheus/Datadog alert | Auto-remediation steps (restart pod, scale out, roll back) | On-call engineer must approve destructive actions (delete volume, roll back production database) |
| Industrial control systems (OT security) | Anomalous PLC/SCADA network traffic | Network segmentation / device isolation | Mandatory HITL given physical-safety stakes — mirrors the existing `ISOLATE_HOST` irreversibility class directly |

Each of these would reuse the LangGraph supervisor pattern, the
irreversibility-classification schema, and the RAG-grounded generation
approach almost unchanged; the domain-specific work is in the
ingestion adapter (replacing the Wazuh bridge), the action taxonomy
(replacing the `SOAR_ACTION_TYPES` enum), and the knowledge base feeding
RAG (replacing MITRE ATT&CK / NIST CSF / NVD with the domain's own
regulatory and procedural references).

## 11.5  Summary and Suggested Priority

| Priority | Item | Rationale |
|----------|------|-----------|
| High | 11.1 — Complete K3s migration (ingress, HPA, NetworkPolicies, backups) | Already in progress; closes a real CI/CD gap; bounded scope |
| High | 11.3 — Empirical evaluation study | Directly resolves the two open uncertainties from Chapter 10 |
| Medium | 11.2.3 — Real-time HITL push channel | Small, well-scoped, measurable latency win |
| Medium | 11.2.2 — Analyst feedback loop | High value but requires careful safeguards against drift |
| Lower (larger scope) | 11.2.1 — Federated TI, 11.2.4 — Multi-tenant deployment | Substantial new subsystems, best suited to a dedicated subsequent project |
| Exploratory | 11.4 — Cross-domain applications | Same architecture, new domain — recommended as an independent FYP topic rather than an extension of this one |
