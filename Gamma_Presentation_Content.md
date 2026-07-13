# AI SOC — Gamma AI Presentation Content
*(Paste everything below into Gamma's "paste in text" / outline mode. Each `#` is a new slide. Diagrams are marked [ATTACH DIAGRAM HERE] — add your own image on those slides and keep the text as the caption/talking points.)*

---

# Slide 1: Title Slide

**Group #:** [FILL IN YOUR GROUP NUMBER]

**Project Title:** AI SOC — An On-Premises, AI-Powered Security Operations Centre

**Subtitle:** Automated Alert Triage, AI-Generated Incident Response, and Human-in-the-Loop Governance for Air-Gapped Environments

**Group Members:**
- [FILL IN NAME 1]
- [FILL IN NAME 2]
- [FILL IN NAME 3 — add/remove as needed]

**Supervisor:** [FILL IN SUPERVISOR NAME]

**Department / University:** [FILL IN]

---

# Slide 2: Problem Statement

**Title: The Problem — Security Teams Are Drowning in Alerts**

- Enterprise Security Operations Centres (SOCs) receive tens of thousands of security alerts every day from firewalls, endpoint tools, and authentication logs.
- 65% of SOC analysts cite "alert fatigue" as their #1 productivity problem (SANS 2023 SOC Survey).
- Average time to detect a serious incident remains above 197 hours in mid-market organisations.
- Around 45% of all alerts are false positives — real attacks get buried in noise.
- Existing AI-powered security tools (Microsoft Copilot for Security, CrowdStrike Charlotte AI) send alert data to the cloud to work.
- Cloud AI is not legally or contractually usable in air-gapped, regulated, or classified environments — banks, defence, government, healthcare — exactly where this help is needed most.
- **The real gap: AI automation exists, but not in a form that regulated and high-security organisations are allowed to use.**

---

# Slide 3: System Diagram

[ATTACH DIAGRAM HERE — 6-layer system architecture image]

**Talking points for this slide:**
- Layer 1 — Wazuh SIEM: watches the network and raises raw security alerts.
- Layer 2 — Apache Kafka: reliably streams alerts between every part of the system, even under heavy load.
- Layer 3 — LangGraph multi-agent pipeline: 6 specialised AI agents analyse, enrich, and respond to each alert.
- Layer 4 — Supporting storage: Redis (fast cache/dedup), PostgreSQL (decisions + audit trail), ChromaDB (AI knowledge base).
- Layer 5 — FastAPI backend + Electron desktop dashboard: what analysts actually use.
- Layer 6 — Shuffle SOAR: executes the final approved response in the real environment.
- **One-line summary to say out loud: "Alerts flow in at the top, get progressively analysed by AI agents in the middle, are shown to a human when needed, and the approved action is carried out at the bottom — with everything logged."**

---

# Slide 4: Operational Diagram

**Note: This project is a fully software-based system — no physical hardware component is involved (no sensors, embedded devices, or custom circuitry).** All processing runs on standard server/desktop hardware (a machine with a GPU for local AI inference). This slide can be skipped, or replaced with a one-line note: *"No physical hardware — deployment target is a standard on-premises server with one GPU."*

If you want to keep a slide here for pacing, use it to show the **deployment footprint** instead:
- Runs entirely on-premises on a single server (or small Docker Compose / Kubernetes cluster).
- Requires one consumer-grade GPU (fits a 12GB card) to run the local AI model.
- No internet connection required or permitted in production.
- Every component is containerised with Docker for consistent, repeatable deployment.

---

# Slide 5: Component Diagram

[ATTACH DIAGRAM HERE — the 6-agent pipeline diagram]

**Talking points — the 6 AI agents, in processing order:**

1. **Log Analysis Agent ("The Triage Nurse")** — First to see every alert. Filters junk/duplicates, tags severity, spots bursts of related alerts, extracts suspicious IPs/hashes, maps to MITRE ATT&CK techniques.
2. **Threat Intelligence Agent ("The Detective")** — Checks suspicious IPs/files against 6 real threat-intel sources simultaneously (VirusTotal, MISP, AlienVault OTX, Shodan, NVD, GeoIP).
3. **Playbook Generation Agent ("The Strategist")** — Writes the step-by-step response plan. Uses instant templates for known attacks, or a locally-hosted AI model (grounded in MITRE ATT&CK, NIST CSF, past incidents) for anything unusual.
4. **Supervisor Agent ("The Manager")** — Decides what happens next at every stage: drop, auto-execute, or send to a human. Enforces the rule that irreversible actions always need human sign-off.
5. **HITL Agent — Human-in-the-Loop ("The Approval Desk")** — Pauses risky decisions, notifies an analyst (Slack/email/dashboard), waits for Approve/Edit/Reject/Escalate, with a safety timeout.
6. **SOAR Agent ("The Executor")** — Once approved, hands the plan to Shuffle, which physically executes the response (block IP, disable account, kill process).

---

# Slide 6: Achievements of Project Group

*Note: fill this in with your team's actual events/activities. Suggested structure and example content below — replace with what genuinely happened.*

**Suggested categories to fill in:**
- **University FYP exhibition / demo day** — [add date, outcome, feedback received]
- **Competitions entered** (cybersecurity / AI showcases, university cyber-defence competitions) — [add if applicable]
- **Conferences / paper submissions** — a full research paper for this project already exists in submittable draft form (`FYP_Research_Paper.md`) and could be adapted for a student systems/security conference — [add outcome if submitted]
- **Incubation / entrepreneurship interest** — the air-gapped/on-premises angle is commercially relevant for regulated industries (banking, defence, healthcare) — [add if pursued]

**If no external events yet, present it as technical achievements instead:**
- Built and deployed a complete working multi-agent pipeline end-to-end (not just a prototype/mockup).
- Passed a full end-to-end functional test under simulated load (100+ synthetic alerts processed with zero pipeline errors).
- Implemented a 7-stage automated security-testing pipeline (secrets scan, SAST, dependency scan, container scan, SBOM generation, automated tests, DAST) — matching real industry security engineering practice.
- Achieved per-module automated test coverage gates (80% agents/orchestration, 85% schemas, 65% API/infrastructure).
- Produced a submittable-quality research paper documenting the full system design and Computing Professional Practices mapping.

---

# Slide 7: Future Enhancement

**Title: Where This Project Goes Next**

**Near-term (already in progress):**
- Completing migration to Kubernetes (K3s) for production-style deployment — ingress/TLS, horizontal scaling of pipeline workers, network policies, backup/restore for the database.
- Empirical evaluation study — benchmark real triage accuracy (precision/recall/F1) against a labelled alert dataset, and run a human-analyst study scoring AI-generated playbook quality.

**Medium-term:**
- Real-time streaming HITL interface — replace periodic polling with instant push notifications, cutting analyst-response latency to sub-second.
- Analyst feedback loop — let the local AI model learn from real approve/reject/edit decisions over time, entirely on-premises, with safeguards against drift.

**Longer-term / larger scope:**
- Federated threat-intelligence sharing (STIX/TAXII 2.1) — organisations exchange anonymised threat indicators without pooling raw data centrally.
- Multi-tenant deployment — one deployment securely serving multiple client organisations (e.g. a managed security provider).
- Applying the same architecture to other high-stakes domains: banking fraud/AML, clinical decision support, DevOps incident response, industrial control systems (OT security) — anywhere automated systems propose high-stakes actions that a human must stay accountable for.

---

# Slide 8: Bug List / Known Issues

**Title: Known Issues & Testing Status**

*Framed honestly — this shows engineering maturity, not weakness.*

**Summary:** 33 tracked failing/at-risk test cases identified through systematic gap-analysis testing, all logged and triaged (not hidden).

**Confirmed environmental issues (not core logic bugs):**
- SOAR execution history doesn't populate from Shuffle — API key configuration issue in the test environment (HTTP 403).
- GeoIP enrichment section renders empty when the GeoLite2 database file isn't present locally.
- Synthetic load generator sustains ~92 events/sec vs. a 100 EPS target — single-threaded generator bottleneck (not a pipeline bottleneck).

**Gap-analysis hardening items tracked for next iteration (examples):**
- IPv6 addresses not yet captured by the IOC-extraction regex (IPv4-only currently).
- No rate-limiting yet on the HITL decision API endpoint.
- Two analysts approving/rejecting the same review simultaneously — last write wins (no optimistic locking yet).
- Large alert payloads (>1MB) can be rejected by the Kafka producer's default message-size limit.
- Dark-mode contrast issue on one dashboard button (WCAG AA gap).

**Key point to make to the panel:** *"We built a systematic gap-analysis test list rather than only testing the happy path. Every issue found is documented, categorised by severity, and tracked — this is the same practice used in professional QA processes, not something we're hiding."*

---

# Bonus: Live Demo Script (for the 25-minute demonstration block)

*Not a slide — use this as your run-of-show for the live demo portion.*

1. **Open the app** — show the Electron desktop dashboard, log in as admin.
2. **Show the live SIEM/dashboard view** — point out the alert feed, metrics, and service-status indicators.
3. **Trigger live alerts** — run the synthetic alert generator briefly (or explain that in production these come from real Wazuh sensors) to show alerts flowing through the pipeline in real time.
4. **Show automatic triage** — point out an alert that was auto-resolved (dropped as noise/duplicate, or auto-executed because confidence was high and the action was safe).
5. **Show the HITL queue** — open a pending review that needed human approval (critical severity or an irreversible action). Explain *why* it stopped here.
6. **Make a live decision** — click Approve (or Reject/Escalate) on a pending alert and show the system respond in real time.
7. **Show the audit trail** — pull up the logged decision (who approved it, when, what happened) to demonstrate accountability and compliance-readiness.
8. **(Optional) Show the generated playbook** — open one AI-generated response plan and point out it follows the OASIS CACAO v2.0 standard format.
9. **Close the loop** — briefly show system health / service status to prove the whole stack (Kafka, database, AI pipeline) is genuinely running, not a static mockup.

---

# Quick-Reference Answers (keep open on your phone during Q&A)

- **What does it do?** Automatically triages, investigates, and writes AI-generated response plans for security alerts — with mandatory human approval for anything risky or irreversible.
- **What's unique?** 100% on-premises — even the AI model runs locally. No cloud API, ever. Usable in banks, defence, government, healthcare.
- **Biggest safety guarantee?** Irreversible actions (isolate host, disable user, revoke token) can NEVER execute without a human's explicit approval — enforced in code, not policy.
- **Tech stack in one breath:** Wazuh (detects) → Kafka (streams) → LangGraph agents with a local vLLM + Qwen2.5 model grounded in a ChromaDB knowledge base (decide & respond) → Redis/PostgreSQL (memory & audit) → FastAPI + Electron dashboard (human interface) → Shuffle SOAR (executes).
- **Scale:** Designed for 512 concurrent alerts across 16 parallel workers.
- **Confidence threshold for auto-execution:** 85% — below that, or for Critical severity, or for irreversible actions, it always asks a human.
