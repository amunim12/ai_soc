# Chapter 8 — Testing

This chapter summarises the verification of the **AI-Powered SOC
Pipeline**: the test plan, **white-box** unit tests that exercise
internal logic, **black-box** system tests that exercise the REST API
and Electron desktop app, and a tabular summary of results. Per the
project brief, only test cases and their results are shown here;
screenshots and full terminal logs are collected in **Annexure A —
Test Evidence**.

## 8.1  Test Plan

**Objectives** — verify that the pipeline (i) classifies alerts and
extracts IOCs, (ii) enriches IOCs via live threat intelligence and
tolerates adapter failures, (iii) generates a playbook tailored to the
alert, (iv) routes to Human-in-the-Loop (HITL) on low confidence /
CRITICAL severity / irreversible actions, (v) executes approved
playbooks via Shuffle SOAR, and (vi) renders the full state in the
Electron desktop app.

**Strategy**

| Level        | Technique  | Harness                     | Scope                              |
|--------------|------------|-----------------------------|------------------------------------|
| Unit         | White-box  | `pytest` + `pytest-asyncio` | Single agent / helper              |
| Integration  | White-box  | `pytest`                    | Full LangGraph flow                |
| System / E2E | Black-box  | Synthetic log generator     | Kafka → Agents → SOAR → Desktop    |
| Load         | Black-box  | `synthetic_log_generator`   | 10 / 100 / 2000 EPS                |

**Environment** — Windows 11, Python 3.14, Dockerised Kafka / Redis /
ChromaDB, Ollama `qwen2.5:3b` on Intel MX350 (2 GB VRAM), Shuffle SOAR
on-prem, Electron + React desktop.

## 8.2  White-Box Testing

White-box cases inspect the internal logic of each agent with full
visibility of code paths. They live in
[ai_soc_pipeline/tests/](ai_soc_pipeline/tests/). LLM, Kafka and Redis
clients are stubbed via fixtures in
[conftest.py](ai_soc_pipeline/tests/conftest.py) so no network calls
are made. Representative cases per module are listed below.

### 8.2.1  Log Analysis Agent — [test_log_analysis.py](ai_soc_pipeline/tests/test_log_analysis.py)

| # (WB) | Test Case                        | Input                                | Expected                                   | Result |
|--------|----------------------------------|--------------------------------------|--------------------------------------------|:------:|
| WB-01  | `test_noise_filter_low_level`    | `rule_level=2`                       | `noise_filtered == True`                   | Pass   |
| WB-02  | `test_not_noise_high_level`      | `rule_level=10`                      | `noise_filtered == False`                  | Pass   |
| WB-03  | `test_ioc_extraction_ip`         | Log containing public IPv4           | IP captured in IOC list                    | Pass   |
| WB-04  | `test_ioc_extraction_sha256`     | Log containing SHA-256 hash          | Hash captured as IOC                       | Pass   |
| WB-05  | `test_ioc_extraction_cve`        | `CVE-2024-3094` in log               | CVE captured as IOC                        | Pass   |
| WB-06  | `test_ioc_excludes_private_ip`   | Log with `10.0.0.5`                  | Private IP is **not** an IOC               | Pass   |
| WB-07  | `test_rescore_crown_jewel`       | Alert on `CROWN_JEWEL` asset         | Severity score boosted                     | Pass   |
| WB-08  | `test_rescore_max_150`           | High severity + critical asset       | Re-score clamped at 150                    | Pass   |
| WB-09  | `test_mitre_mapping_known_rule`  | Wazuh rule 5712 (brute force)        | Maps to `T1110`                            | Pass   |
| WB-10  | `test_category_brute_force`      | Brute-force rule                     | `alert_category == "authentication_failures"` | Pass |
| WB-11  | `test_run_full_pipeline`         | Happy-path alert                     | `AnalysisResult` with IOCs                 | Pass   |

*Also covered in this module:* duplicate detection, burst correlation,
noise by rule ID, `test_category_fallback_generic` — **11 additional
cases, all passing (22 total).**

### 8.2.2  Threat Intelligence Agent — [test_threat_intel.py](ai_soc_pipeline/tests/test_threat_intel.py)

| # (WB) | Test Case                                   | Input                          | Expected                        | Result |
|--------|---------------------------------------------|--------------------------------|---------------------------------|:------:|
| WB-12  | `test_composite_score_all_high`             | All 6 adapters return high     | Composite ≈ 1.0                 | Pass   |
| WB-13  | `test_composite_score_all_zero`             | All adapters return zero       | Composite == 0.0                | Pass   |
| WB-14  | `test_composite_score_partial`              | VT high, others unknown        | Composite 0.3 – 0.6             | Pass   |
| WB-15  | `test_composite_score_exception_resilience` | One adapter raises             | Score still produced            | Pass   |
| WB-16  | `test_composite_score_caps_at_1`            | Over-weighted inputs           | Capped at 1.0                   | Pass   |
| WB-17  | `test_run_full_mock`                        | Mock TI, 3 IOCs                | Full `EnrichmentResult`         | Pass   |

### 8.2.3  Playbook Generation Agent — [test_playbook_gen.py](ai_soc_pipeline/tests/test_playbook_gen.py)

| # (WB) | Test Case                         | Input                         | Expected                                  | Result |
|--------|-----------------------------------|-------------------------------|-------------------------------------------|:------:|
| WB-18  | `test_parse_valid_yaml`           | Well-formed YAML              | Parsed into `Playbook`                    | Pass   |
| WB-19  | `test_parse_strips_markdown_fence`| YAML wrapped in ``` fences    | Fences stripped before parse              | Pass   |
| WB-20  | `test_total_steps`                | 2/3/2 steps in C/E/R          | `total_steps == 7`                        | Pass   |
| WB-21  | `test_has_irreversible_steps`     | Includes `ISOLATE_HOST`       | `has_irreversible_steps == True`          | Pass   |
| WB-22  | `test_no_irreversible_steps`      | Only `BLOCK_IP`               | `has_irreversible_steps == False`         | Pass   |
| WB-23  | `test_invalid_yaml_raises`        | Malformed YAML                | Raises `ValueError`                       | Pass   |
| WB-24  | `test_irreversible_actions_constant` | –                          | Set includes `ISOLATE_HOST`, `DISABLE_USER`, `REVOKE_TOKEN` | Pass |

*Plus 4 more cases covering `auto_approve` default, per-step
`is_irreversible`, and phase-level step counts — **11 total, all
passing.***

### 8.2.4  HITL Agent — [test_hitl_agent.py](ai_soc_pipeline/tests/test_hitl_agent.py)

| # (WB) | Test Case                             | Input                            | Expected                                  | Result |
|--------|---------------------------------------|----------------------------------|-------------------------------------------|:------:|
| WB-25  | `test_explain_reason_low_confidence`  | `confidence=0.5`                 | Reason mentions "Low confidence"          | Pass   |
| WB-26  | `test_explain_reason_critical`        | `severity=CRITICAL`              | Reason mentions "Critical severity"       | Pass   |
| WB-27  | `test_explain_reason_irreversible`    | Playbook with `ISOLATE_HOST`     | Reason mentions "irreversible"            | Pass   |
| WB-28  | `test_auto_partial_approve`           | Timeout branch                   | Returns APPROVE by `system:timeout`       | Pass   |
| WB-29  | `test_has_irreversible_true/false/none` | Playbook with / without / none | Correct boolean each case                 | Pass   |
| WB-30  | `test_run_fast_decision`              | Decision available immediately   | End-to-end run without escalation         | Pass   |

### 8.2.5  Supervisor Routing — [test_supervisor_routing.py](ai_soc_pipeline/tests/test_supervisor_routing.py)

These tests verify the **conditional edges** of the LangGraph state
machine — the central decision logic of the pipeline.

| # (WB) | Pipeline State                      | Expected Route                     | Result |
|--------|-------------------------------------|------------------------------------|:------:|
| WB-31  | `noise_filtered=True`               | → DROP                             | Pass   |
| WB-32  | `is_duplicate=True`                 | → DROP                             | Pass   |
| WB-33  | `has_iocs=True`                     | → ENRICH                           | Pass   |
| WB-34  | `has_iocs=False`                    | → PLAYBOOK (skip ENRICH)           | Pass   |
| WB-35  | conf=0.92, MEDIUM, reversible       | → EXECUTE                          | Pass   |
| WB-36  | conf=0.60                           | → HITL (low confidence)            | Pass   |
| WB-37  | severity=CRITICAL                   | → HITL (critical)                  | Pass   |
| WB-38  | Playbook has `ISOLATE_HOST`         | → HITL (irreversible)              | Pass   |
| WB-39  | HITL action = APPROVE               | → EXECUTE                          | Pass   |
| WB-40  | HITL action = REJECT                | → DROP                             | Pass   |
| WB-41  | HITL action = ESCALATE              | → ESCALATE                         | Pass   |

*Plus 4 additional cases (EDIT action, `None` playbook, borderline
confidence 0.85, `None` analysis) — **15 total, all passing.***

### 8.2.6  Integration (LangGraph end-to-end) — [test_e2e_pipeline.py](ai_soc_pipeline/tests/test_e2e_pipeline.py)

Still white-box — drives the compiled graph with stubbed externals.

| # (WB) | Test Case                          | Scenario                                      | Expected                              | Result |
|--------|------------------------------------|-----------------------------------------------|---------------------------------------|:------:|
| WB-42  | `test_happy_path_execute`          | High-conf, non-critical, reversible           | `pipeline_stage == "executed"`        | Pass   |
| WB-43  | `test_noise_alert_drops`           | Low-level alert                               | Routed to DROP                        | Pass   |
| WB-44  | `test_critical_alert_triggers_hitl`| CRITICAL alert                                | HITL node reached                     | Pass   |
| WB-45  | `test_hitl_reject_drops_alert`     | Analyst rejects                               | Pipeline DROPPED                      | Pass   |
| WB-46  | `test_no_ioc_skips_ti_agent`       | Alert with no IOCs                            | ENRICH skipped                        | Pass   |
| WB-47  | `test_audit_trail_populated`       | Any successful run                            | `audit_trail` has every agent step    | Pass   |
| WB-48  | `test_all_20_mock_alerts_complete` | All 20 seed alerts                            | Each terminates cleanly               | Pass   |

**White-box total: 70 / 70 passing.** Terminal evidence captured as
**Screenshot 8-A** (unit) and **Screenshot 8-B** (integration) in
Annexure A.

## 8.3  Black-Box Testing

Black-box cases drive the **running system from the outside** — the
REST API and the Electron desktop app — without inspecting internal
code. Preconditions: `docker-compose up -d`, FastAPI backend on :8000,
pipeline consumer running, Electron desktop launched,
`PLAYBOOK_FAST_MODE=true`. Alerts are injected with
`python -m scripts.synthetic_log_generator`.

### 8.3.1  Pipeline flow and desktop UI

| # (BB) | Test Case                       | Steps                                  | Expected                                                      | Result | Evidence |
|--------|---------------------------------|----------------------------------------|---------------------------------------------------------------|:------:|----------|
| BB-01  | Alert lands in Overview         | Inject 1 brute-force alert             | Row visible in Overview within 5 s                            | Pass   | **8-1**  |
| BB-02  | Live trace across stages        | Click alert                            | ANALYSE → ENRICH → PLAYBOOK → EXECUTE shown                   | Pass   | **8-2**  |
| BB-03  | Contextual playbook content     | Expand Playbook panel                  | Title uses category + host; steps reference live src/dst/user | Pass   | **8-3**  |
| BB-04  | Category routing — malware      | Inject malware alert                   | Playbook has `ISOLATE_HOST` + `KILL_PROCESS`                  | Pass   | **8-4**  |
| BB-05  | Category routing — web attack   | Inject web-attack alert                | Playbook has `BLOCK_IP` at WAF                                | Pass   | **8-5**  |
| BB-06  | Audit trail rendered            | Open Audit tab                         | One row per agent hop                                         | Pass   | **8-6**  |

### 8.3.2  HITL workflow

| # (BB) | Test Case                | Steps                                             | Expected                                      | Result | Evidence |
|--------|--------------------------|---------------------------------------------------|-----------------------------------------------|:------:|----------|
| BB-07  | Queue populated          | Inject CRITICAL alert                             | Row appears in HITL Queue as Pending          | Pass   | **8-7**  |
| BB-08  | Approve                  | Click *Approve*                                   | Status → Approved; moves to Execution History | Pass   | **8-8**  |
| BB-09  | Reject                   | Click *Reject*                                    | Status → Rejected; Overview shows DROPPED     | Pass   | **8-9**  |
| BB-10  | Escalate                 | Click *Escalate*                                  | Overview escalated count increments           | Pass   | **8-10** |
| BB-11  | Timeout auto-approve     | Leave queued past `HITL_TIMEOUT_SECONDS`          | Auto-approved by `system:timeout`             | Pass   | **8-11** |

### 8.3.3  Shuffle SOAR and threat intelligence

| # (BB) | Test Case                              | Steps                                    | Expected                                          | Result    | Evidence |
|--------|----------------------------------------|------------------------------------------|---------------------------------------------------|:---------:|----------|
| BB-12  | Execution History populated            | Run 5 alerts                             | 5 FINISHED rows sourced from Shuffle API          | **Fail**  | **8-12** |
| BB-13  | Shuffle unreachable — SQLite fallback  | Stop Shuffle; `GET /api/soar/executions` | 200 OK from SQLite `audit_log`                    | Pass      | **8-13** |
| BB-14  | Live TI enrichment (full coverage)     | Alert with known-malicious IP            | Enrichment shows VT, OTX, Shodan **and** GeoIP    | **Fail**  | **8-14** |
| BB-15  | Graceful TI failure                    | Break one TI API key                     | Failing source marked error; pipeline completes   | Pass      | **8-15** |

### 8.3.4  Load and REST API contract

```bash
python -m scripts.synthetic_log_generator --eps 10   --duration 60
python -m scripts.synthetic_log_generator --eps 100  --duration 120
python -m scripts.synthetic_log_generator --eps 2000 --duration 30
```

| # (BB) | Test Case                                        | Input          | Expected                                    | Result   | Evidence |
|--------|--------------------------------------------------|----------------|---------------------------------------------|:--------:|----------|
| BB-16  | Baseline 10 EPS / 60 s                           | 600 alerts     | All consumed; lag ≈ 0                       | Pass     | **8-16** |
| BB-17  | Sustained 100 EPS / 120 s                        | ≈12 000 alerts | Generator sustains **≥ 100 EPS**            | **Fail** | **8-17** |
| BB-18  | Burst 2000 EPS / 30 s                            | 60 000 alerts  | Ingestion OK; expected downstream lag       | Pass     | **8-18** |
| BB-19  | FAST_MODE per-alert latency                      | 1 alert        | End-to-end ≤ 500 ms                         | Pass     | **8-19** |
| BB-20  | `GET /health`                                    | –              | 200 `{"status":"ok"}`                       | Pass     | **8-20** |
| BB-21  | `GET /api/soar/executions?limit=100`             | –              | 200, JSON list                              | Pass     | **8-21** |
| BB-22  | `POST /api/hitl/{id}/decision` (APPROVE)         | valid body     | 200, `recorded:true`                        | Pass     | **8-22** |
| BB-23  | `POST /api/hitl/{id}/decision` (invalid action)  | bad body       | 422 validation error                        | Pass     | **8-23** |

**Black-box total: 20 / 23 passing — 3 failures analysed in §8.3.5.**

### 8.3.5  Failing black-box cases — root cause and remediation

| ID     | Failure observed                                                                                       | Root cause                                                                                          | Remediation                                                                                                     | Status    |
|--------|--------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|-----------|
| BB-12  | Execution History tab only shows pipeline-derived rows from SQLite; no executions are fetched from the real Shuffle REST API. | Shuffle rejects the configured API key with **HTTP 403 Forbidden** on `/api/v1/workflowexecutions`. The backend catches the error and falls back to `audit_log`, so the UI is populated but the *source* is wrong. | Issue a fresh API key from the Shuffle Settings page and update `SHUFFLE_API_KEY` in `.env`. The fallback path (BB-13) continues to protect the UI until the key is rotated. | Deferred — environment issue, code path already verified via BB-13. |
| BB-14  | Enrichment panel renders VT, OTX and Shodan sections correctly, but the **GeoIP** section is empty.   | `GeoLite2-City.mmdb` database file is missing from `./data/`; the GeoIP adapter logs a warning and returns `None`. | Register for a free MaxMind account, download `GeoLite2-City.mmdb`, place it at `MAXMIND_DB_PATH` and restart the backend. | Deferred — external dependency, graceful degradation confirmed (non-blocking). |
| BB-17  | Generator measured sustained rate of **~92 EPS** against a target of 100 EPS over a 120 s run.         | `synthetic_log_generator.py` is single-threaded asyncio and hits an upper bound from Kafka producer serialisation on the test hardware. | Switch to a multi-process generator (one producer per CPU core) or raise Kafka producer `linger.ms` and `batch.size`. Burst test BB-18 shows the pipeline itself can absorb much higher peak rates. | Open — performance optimisation, tracked for next iteration. |

All three failures are **non-functional / environmental** — no
functional requirement of the pipeline is blocked. BB-12 and BB-14
are mitigated by graceful fallbacks (verified in BB-13 and BB-15) and
BB-17 still meets the baseline 10 EPS demo target (BB-16) and the
2000 EPS burst-ingestion goal (BB-18).

## 8.4  Non-Functional Testing

| Property      | Test                                     | Expected                                     | Result |
|---------------|------------------------------------------|----------------------------------------------|:------:|
| Resilience    | Stop Kafka and restart                   | Consumer reconnects automatically            | Pass   |
| Resilience    | Stop Shuffle                             | `/api/soar/executions` falls back to SQLite  | Pass   |
| Security      | Secrets loaded only from `.env`          | No secret in git history                     | Pass   |
| Observability | Every agent emits `StepLog` → audit      | Audit tab shows full trace per alert         | Pass   |
| Performance   | FAST_MODE per-alert latency              | ≤ 500 ms                                     | Pass   |

## 8.5  Defects Found and Fixed

| ID | Defect                                                      | Fix                                                             |
|----|-------------------------------------------------------------|-----------------------------------------------------------------|
| D1 | Kafka consumer kicked from group on slow LLM calls          | Raised `max.poll.interval.ms` to 1 800 000                      |
| D2 | `/api/soar/executions` → 502 when Shuffle returned 403      | Added SQLite fallback in `routes/soar.py`                       |
| D3 | Generic "manual review" fallback playbook                   | Replaced with category-aware contextual generator               |
| D4 | Ollama out-of-memory on 2 GB MX350                          | Set `num_ctx=2048`, `max_tokens=400`                            |
| D5 | Per-alert latency ≈ 3 minutes                               | `PLAYBOOK_FAST_MODE` — deterministic playbook builder           |
| D6 | RAG CVE list returned only first reference                  | Replaced `for _ in range(1)` loop with `[:3]` slice             |

## 8.6  Test Summary

| Category                                | Total  | Passed | Failed |
|-----------------------------------------|:------:|:------:|:------:|
| White-box — unit (WB-01 … WB-41)        |  63    |  63    |   0    |
| White-box — integration (WB-42 … WB-48) |   7    |   7    |   0    |
| Black-box — system (BB-01 … BB-23)      |  23    |  20    |   3    |
| Non-functional                          |   5    |   5    |   0    |
| **Total**                               | **98** | **95** | **3**  |

The three black-box failures (**BB-12, BB-14, BB-17**) are analysed in
§8.3.5. None of them block a functional requirement: BB-12 and BB-14
are masked by graceful-degradation paths that are themselves verified
(BB-13, BB-15), and BB-17 misses a stretch performance target while
still meeting the demo baseline. All test evidence — pytest
terminals, desktop screenshots, curl outputs — is collected in
**Annexure A** under the labels **8-A, 8-B** (white-box terminals) and
**8-1 through 8-23** (black-box evidence) referenced in the tables
above.
