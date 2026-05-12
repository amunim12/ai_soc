# Failing Test Cases — AI SOC

Consolidated list of failing / gap-analysis test cases identified
during the verification of the AI-Powered SOC Pipeline. Cases are
grouped by white-box (internal logic) and black-box (system-level /
UI / REST API).

---

## White-Box — Potential Failing Cases

Gap-analysis cases that exercise internal logic boundaries currently
not guarded. Each corresponds to a defensive-hardening task.

| ID     | Test Case                              | Failure scenario                                                                 | Root cause (code path)                                                                    |
|--------|----------------------------------------|----------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| WB-F1  | `test_ioc_extraction_ipv6`             | IPv6 address in log is not captured as an IOC.                                   | [log_analysis_agent.py](ai_soc_pipeline/agents/log_analysis_agent.py) IOC regex is IPv4-only. |
| WB-F2  | `test_mitre_mapping_unknown_rule`      | Unknown rule ID returns empty technique list instead of a default.               | No fallback branch in `_map_mitre()`; downstream RAG query gets empty MITRE filter.       |
| WB-F3  | `test_dedup_ttl_expiry`                | Alert replayed after Redis TTL expiry is still flagged as duplicate.             | `redis_client.seen()` uses a fixed key without refreshing TTL on hit.                     |
| WB-F4  | `test_burst_correlation_window_edge`   | Two alerts exactly at the `burst_window_seconds` boundary are not correlated.    | Off-by-one in `<=` vs. `<` comparison in burst correlation logic.                         |
| WB-F5  | `test_parse_multi_document_yaml`       | Playbook YAML with `---` separators raises `ValueError`.                         | `Playbook.from_yaml()` calls `yaml.safe_load` (single doc) instead of `safe_load_all`.    |
| WB-F6  | `test_parse_unicode_description`       | Playbook with non-ASCII chars in `description` drops characters on re-serialise. | Missing `ensure_ascii=False` in the JSON serialiser used by Kafka publish.                |
| WB-F7  | `test_llm_retry_exhaustion`            | LLM raises `APIError` 4 times → agent crashes instead of returning fallback.     | `tenacity` retry decorator re-raises after 3 attempts; no outer `try/except` in caller.   |
| WB-F8  | `test_chroma_empty_collection`         | Empty ChromaDB collection raises instead of returning `[]`.                      | `chroma_client.query_collection()` doesn't guard against `count == 0` before `.query()`.  |
| WB-F9  | `test_composite_score_all_none`        | All TI adapters return `None` (not zero) → composite score computation raises.   | Arithmetic path assumes numeric; needs `None → 0` coercion in `_composite_score()`.       |
| WB-F10 | `test_playbook_step_id_collision`      | Two steps with the same `step_id` collide in `workflow` dict.                    | `workflow: dict[str, PlaybookStep]` silently overwrites earlier step; no uniqueness check.|

---

## Black-Box — Confirmed Failing Cases

Cases observed to fail when driving the running system end-to-end.

| ID    | Test Case                              | Failure observed                                                                 | Root cause                                                                                         |
|-------|----------------------------------------|----------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| BB-12 | Execution History populated            | Tab shows pipeline-derived rows from SQLite only; no rows fetched from Shuffle.  | Shuffle rejects the configured API key with **HTTP 403 Forbidden**.                                |
| BB-14 | Live TI enrichment (full coverage)     | VT / OTX / Shodan render correctly, but **GeoIP** section is empty.              | `GeoLite2-City.mmdb` missing from `./data/`; GeoIP adapter returns `None`.                         |
| BB-17 | Sustained 100 EPS / 120 s              | Generator sustained only **~92 EPS** vs. target of ≥ 100 EPS.                    | Single-threaded asyncio generator bottlenecked by Kafka producer serialisation.                    |

---

## Black-Box — Potential Failing Cases (gap analysis)

Additional realistic failure modes that would appear when exercising
the live stack under stress or in a freshly-provisioned environment.

### Integration gaps

| ID     | Test Case                                       | Failure observed                                                                                 | Root cause                                                                                          |
|--------|-------------------------------------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| BB-F1  | Real Shuffle workflow execution                 | Clicking *Execute* on an approved playbook does not trigger any workflow on Shuffle.             | `POST /api/v1/workflows/{id}/execute` rejected with **403 Forbidden** (same root cause as BB-12).   |
| BB-F2  | SOAR live trace panel                           | Live trace panel stays blank after execution click; no steps ever render.                        | Panel polls `GET /api/soar/execution/{id}` which proxies to Shuffle — fails with 502 on 403.        |
| BB-F3  | MISP threat-intel adapter                       | Enrichment panel never shows MISP events for any IOC.                                            | `MISP_URL=https://misp.local` unresolvable; adapter returns empty dict without surfacing the error. |
| BB-F9  | Wazuh live bridge ingestion                     | Starting the Wazuh → Kafka bridge with real Wazuh REST API returns 0 alerts.                     | `WAZUH_API_URL=https://localhost:55000` not running in the test environment.                        |
| BB-F10 | ChromaDB cold start — empty collections         | First playbook after a fresh `docker-compose up` has `rag_chunks_used == 0`.                     | `scripts/load_rag_corpus.py` not run before starting the consumer.                                  |
| BB-F20 | Kafka topic missing on fresh install            | Consumer crashes with `UnknownTopicOrPartitionError` if `init_topics.sh` not run.                | `create_topics_if_missing()` is opt-in and only invoked from the dev bootstrap script.             |

### Notifications

| ID    | Test Case                 | Failure observed                                      | Root cause                                                                        |
|-------|---------------------------|-------------------------------------------------------|-----------------------------------------------------------------------------------|
| BB-F4 | Email HITL notification   | Critical alert does not send an analyst email.        | `SMTP_PASSWORD` blank in `.env`; `aiosmtplib.send()` silently caught by try/except.|
| BB-F5 | Slack HITL notification   | Slack webhook never fires on queued review.           | `SLACK_WEBHOOK_URL` is the placeholder value; request returns 404.                 |

### Security / auth

| ID     | Test Case                                    | Failure observed                                                                 | Root cause                                                                    |
|--------|----------------------------------------------|----------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| BB-F6  | SSO / JWT auth on REST API                   | Calling `/api/hitl/pending` without a bearer token still returns 200.            | Protected endpoints not wrapped in `Depends(get_current_user)`.               |
| BB-F7  | Rate-limit / throttling on decision endpoint | 100 rapid POSTs to `/api/hitl/{id}/decision` all return 200 (no throttle).       | No rate limiter configured on the FastAPI app.                                |
| BB-F15 | Concurrent HITL decisions on same review     | Two analysts click *Approve* and *Reject* simultaneously — last-write-wins.      | `store_decision()` uses `INSERT OR REPLACE` without optimistic locking.       |

### Data-boundary edge cases

| ID     | Test Case                                    | Failure observed                                                                 | Root cause                                                                    |
|--------|----------------------------------------------|----------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| BB-F8  | Duplicate alert de-dup across restarts       | Same alert injected twice across a consumer restart produces two audit rows.     | Dedup key TTL in Redis is shorter than restart gap; state lost.               |
| BB-F13 | Very large alert payload (> 1 MB `full_log`) | Kafka producer rejects the message.                                              | `message.max.bytes` default (1 MB) exceeded; raises `MessageSizeTooLarge`.    |
| BB-F14 | Clock-skewed alert timestamp                 | Alert with future `timestamp` is ingested but never correlated with burst window.| Burst correlation arithmetic breaks on future ts.                             |
| BB-F16 | Long-running SOAR workflow (> 15 min)        | `shuffle_client.wait()` gives up before workflow completes.                      | `SHUFFLE_EXECUTION_TIMEOUT=900` shorter than the real forensic workflow.      |
| BB-F17 | OTX rate limit                               | After ~10 rapid alerts, OTX returns 429 for several minutes.                     | No per-adapter caching / backoff; every IOC hits the live endpoint.           |

### UI / UX

| ID     | Test Case                                  | Failure observed                                                                 | Root cause                                                                    |
|--------|--------------------------------------------|----------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| BB-F11 | Electron app offline / backend down        | Desktop app shows "Network Error" banner but no retry UI.                        | React app has no reconnect logic for `/health` polling failures.              |
| BB-F12 | Browser cache after backend code change    | Old frontend still calls removed `/api/soar-dash/executions` path after upgrade. | Vite dev server aggressive caching; old bundle served until hard refresh.     |
| BB-F18 | Desktop app dark-mode contrast             | HITL queue *Escalate* button text is unreadable in dark mode.                    | `text-gray-400` on dark background fails WCAG AA contrast.                    |
| BB-F19 | Audit tab pagination                       | Audit tab only shows the most recent 200 rows; no "Load more" button.            | `GET /api/soar-dash/audit?limit=200` hardcoded; no cursor pagination.         |

---

## Summary

| Category                              | Count |
|---------------------------------------|:-----:|
| White-box — potential (gap analysis)  |  10   |
| Black-box — confirmed failing         |   3   |
| Black-box — potential (gap analysis)  |  20   |
| **Total failing / at-risk cases**     | **33**|

All confirmed failures (BB-12, BB-14, BB-17) are non-functional or
environmental and are protected by verified graceful-degradation
paths. The gap-analysis cases represent defensive-hardening work
tracked for the next development iteration.
