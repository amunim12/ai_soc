# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
PostgreSQL client — drop-in replacement for SQLiteClient.

Uses asyncpg connection pool for high-concurrency writes.
Same method signatures as SQLiteClient so the rest of the codebase
can switch transparently based on POSTGRES_DSN env var.

Requires:
    pip install asyncpg
    POSTGRES_DSN=postgresql://soc:soc_pipeline_dev@localhost:5432/soc_pipeline
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Callable, Optional

import asyncpg

from schemas.hitl import ApprovalDecision
from schemas.playbook import Playbook
from schemas.audit import AuditEntry

log = logging.getLogger(__name__)

DDL = """
CREATE TABLE IF NOT EXISTS hitl_reviews (
    review_id     TEXT PRIMARY KEY,
    alert_id      TEXT NOT NULL,
    alert_json    TEXT NOT NULL,
    playbook_json TEXT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    reason        TEXT,
    status        TEXT NOT NULL DEFAULT 'PENDING',
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS hitl_decisions (
    decision_id   TEXT PRIMARY KEY,
    review_id     TEXT NOT NULL REFERENCES hitl_reviews(review_id),
    action        TEXT NOT NULL,
    analyst_id    TEXT NOT NULL,
    notes         TEXT,
    final_playbook_json TEXT,
    elapsed_seconds INTEGER,
    decided_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hitl_decisions_review
    ON hitl_decisions(review_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id            TEXT PRIMARY KEY,
    alert_id      TEXT NOT NULL,
    outcome       TEXT NOT NULL,
    pipeline_trace_json TEXT,
    analyst_id    TEXT,
    hitl_elapsed_seconds INTEGER,
    recorded_at   TIMESTAMPTZ NOT NULL
);
"""


class PostgresClient:
    """Async Postgres client for HITL and audit persistence using asyncpg."""

    def __init__(self, dsn: str, min_pool: int = 10, max_pool: int = 128):
        self._dsn = dsn
        self._min_pool = min_pool
        self._max_pool = max_pool
        self._pool: Optional[asyncpg.Pool] = None

    @property
    def db_path(self) -> str:
        return self._dsn

    async def initialise(self) -> None:
        self._pool = await asyncpg.create_pool(
            self._dsn, min_size=self._min_pool, max_size=self._max_pool, ssl=False,
        )
        async with self._pool.acquire() as conn:
            for stmt in DDL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    await conn.execute(stmt)
        log.info(
            "PostgresClient initialised → %s  pool=%d–%d",
            self._dsn.split("@")[-1] if "@" in self._dsn else self._dsn,
            self._min_pool, self._max_pool,
        )

    async def store_pending_review(
        self,
        alert,
        playbook: Playbook,
        confidence: float,
        reason: str,
        expires_at: Optional[datetime] = None,
    ) -> str:
        review_id = str(uuid.uuid4())
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO hitl_reviews
                  (review_id, alert_id, alert_json, playbook_json, confidence,
                   reason, expires_at, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                review_id,
                alert.id,
                alert.model_dump_json(),
                playbook.model_dump_json(),
                confidence,
                reason,
                expires_at,
                datetime.utcnow(),
            )
        log.info("HITL review stored: %s (alert=%s)", review_id, alert.id)
        return review_id

    async def poll_decision(
        self, review_id: str,
    ) -> Optional[ApprovalDecision]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM hitl_decisions WHERE review_id = $1 ORDER BY decided_at DESC LIMIT 1",
                review_id,
            )
        if row is None:
            return None

        final_pb = None
        if row["final_playbook_json"]:
            try:
                final_pb = Playbook.model_validate_json(row["final_playbook_json"])
            except Exception:
                pass

        return ApprovalDecision(
            review_id=review_id,
            action=row["action"],
            analyst_id=row["analyst_id"],
            notes=row["notes"] or "",
            final_playbook=final_pb,
            elapsed_seconds=row["elapsed_seconds"] or 0,
            decided_at=row["decided_at"],
        )

    async def wait_for_decision(
        self,
        review_id: str,
        timeout_seconds: int,
        escalate_seconds: int,
        on_escalate: Callable,
    ) -> Optional["ApprovalDecision"]:
        """
        Block until Postgres fires NOTIFY hitl_decision for this review_id.
        Uses a dedicated connection outside the pool — LISTEN requires a
        persistent connection that cannot be returned mid-wait.
        Returns None on timeout; caller should auto-approve.
        """
        start = datetime.utcnow()
        escalated = False
        conn = await asyncpg.connect(self._dsn, ssl=False)

        # asyncpg has no wait_for_notification() — LISTEN/NOTIFY is
        # callback-based via add_listener(). Bridge it to an awaitable.
        notified = asyncio.Event()
        matched = False

        def _on_notify(_connection, _pid, _channel, payload) -> None:
            nonlocal matched
            if payload == review_id:
                matched = True
                notified.set()

        try:
            await conn.add_listener("hitl_decision", _on_notify)
            while True:
                elapsed = int((datetime.utcnow() - start).total_seconds())

                if elapsed >= escalate_seconds and not escalated:
                    await on_escalate(review_id, elapsed)
                    escalated = True

                if elapsed >= timeout_seconds:
                    return None

                remaining = timeout_seconds - elapsed
                until_escalate = (escalate_seconds - elapsed) if not escalated else remaining
                wait_secs = max(1.0, float(min(until_escalate, remaining, 30)))

                try:
                    await asyncio.wait_for(notified.wait(), timeout=wait_secs)
                    if matched:
                        return await self.poll_decision(review_id)
                    notified.clear()
                except asyncio.TimeoutError:
                    pass
        finally:
            await conn.remove_listener("hitl_decision", _on_notify)
            await conn.close()

    async def store_decision(self, decision: ApprovalDecision) -> None:
        fp_json = None
        if decision.final_playbook:
            fp_json = decision.final_playbook.model_dump_json()

        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO hitl_decisions
                      (decision_id, review_id, action, analyst_id, notes,
                       final_playbook_json, elapsed_seconds, decided_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    """,
                    str(uuid.uuid4()),
                    decision.review_id,
                    decision.action,
                    decision.analyst_id,
                    decision.notes,
                    fp_json,
                    decision.elapsed_seconds,
                    decision.decided_at,
                )
                await conn.execute(
                    "UPDATE hitl_reviews SET status = $1 WHERE review_id = $2",
                    decision.action, decision.review_id,
                )
                await conn.execute(
                    "SELECT pg_notify('hitl_decision', $1)",
                    decision.review_id,
                )

    async def get_pending_reviews(self) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM hitl_reviews WHERE status = 'PENDING' ORDER BY created_at DESC"
            )
        return [dict(r) for r in rows]

    async def get_review_by_id(self, review_id: str) -> Optional[dict]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM hitl_reviews WHERE review_id = $1 LIMIT 1",
                review_id,
            )
        return dict(row) if row else None

    async def get_metrics(self) -> dict:
        async with self._pool.acquire() as conn:
            total     = await conn.fetchval("SELECT COUNT(*) FROM audit_log")
            executed  = await conn.fetchval("SELECT COUNT(*) FROM audit_log WHERE outcome = 'EXECUTED'")
            dropped   = await conn.fetchval("SELECT COUNT(*) FROM audit_log WHERE outcome = 'DROPPED'")
            escalated = await conn.fetchval("SELECT COUNT(*) FROM audit_log WHERE outcome = 'ESCALATED'")
            pending   = await conn.fetchval("SELECT COUNT(*) FROM hitl_reviews WHERE status = 'PENDING'")
            avg_conf  = await conn.fetchval("SELECT AVG(confidence) FROM hitl_reviews")
        return {
            "total_alerts": total or 0,
            "executed_playbooks": executed or 0,
            "dropped_alerts": dropped or 0,
            "escalated_alerts": escalated or 0,
            "pending_reviews": pending or 0,
            "avg_confidence": round(float(avg_conf or 0), 3),
        }

    async def get_activity(self, hours: int = 24) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT to_char(recorded_at, 'HH24:00') as hour,
                       COUNT(*) as count,
                       SUM(CASE WHEN outcome = 'EXECUTED' THEN 1 ELSE 0 END) as executed,
                       SUM(CASE WHEN outcome = 'DROPPED'  THEN 1 ELSE 0 END) as dropped
                FROM audit_log
                WHERE recorded_at >= now() - make_interval(hours => $1)
                GROUP BY to_char(recorded_at, 'HH24:00'), to_char(recorded_at, 'HH24')
                ORDER BY to_char(recorded_at, 'HH24')
                """,
                hours,
            )
        return [dict(r) for r in rows]

    async def get_severity_breakdown(self, hours: int = 24) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT alert_json, created_at
                FROM hitl_reviews
                WHERE created_at >= now() - make_interval(hours => $1)
                ORDER BY created_at
                """,
                hours,
            )

        buckets: dict[str, dict[str, int]] = {}
        for row in rows:
            ca = row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else str(row["created_at"])
            hour = ca[:13] + ":00"
            if hour not in buckets:
                buckets[hour] = {"hour": hour[-5:], "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            try:
                sev = (json.loads(row["alert_json"]).get("severity") or "MEDIUM").upper()
            except Exception:
                sev = "MEDIUM"
            sev = sev if sev in buckets[hour] else "MEDIUM"
            buckets[hour][sev] += 1
        return list(buckets.values())

    async def get_mitre_stats(self, limit: int = 15) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT alert_json, playbook_json FROM hitl_reviews"
            )

        counts: dict[str, dict] = {}
        for row in rows:
            try:
                alert = json.loads(row["alert_json"])
                for t in alert.get("mitre_techniques") or []:
                    tid = str(t)
                    counts.setdefault(tid, {"technique_id": tid, "technique_name": tid, "count": 0})
                    counts[tid]["count"] += 1
            except Exception:
                pass

            try:
                pb = json.loads(row["playbook_json"])
                for phase in (pb.get("phases") or {}).values():
                    for step in phase.get("steps") or []:
                        tid = step.get("mitre_technique")
                        if tid:
                            counts.setdefault(tid, {"technique_id": tid, "technique_name": tid, "count": 0})
                            counts[tid]["count"] += 1
            except Exception:
                pass

        return sorted(counts.values(), key=lambda x: x["count"], reverse=True)[:limit]

    async def get_recent_alerts(self, limit: int = 100) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT review_id, alert_json, confidence, created_at FROM hitl_reviews ORDER BY created_at DESC LIMIT $1",
                limit,
            )

        results = []
        for row in rows:
            try:
                a = json.loads(row["alert_json"])
            except Exception:
                a = {}
            ca = row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else str(row["created_at"])
            results.append({
                "review_id":       row["review_id"],
                "alert_id":        a.get("id", row["review_id"]),
                "severity":        (a.get("severity") or "MEDIUM").upper(),
                "category":        a.get("alert_category") or "—",
                "rule_description": a.get("rule_description") or "—",
                "agent_name":      a.get("agent_name") or a.get("agent_id") or "—",
                "agent_ip":        a.get("agent_ip") or a.get("source_ip") or "—",
                "source_ip":       a.get("source_ip") or "—",
                "dest_ip":         a.get("destination_ip") or "—",
                "user":            a.get("user") or "—",
                "mitre_techniques": a.get("mitre_techniques") or [],
                "confidence":      row["confidence"],
                "created_at":      ca,
            })
        return results

    async def get_agents(self) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT alert_json, created_at FROM hitl_reviews ORDER BY created_at DESC"
            )

        agents: dict[str, dict] = {}
        for row in rows:
            try:
                a = json.loads(row["alert_json"])
            except Exception:
                continue
            ca = row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else str(row["created_at"])
            agent_id   = str(a.get("agent_id") or "unknown")
            agent_name = str(a.get("agent_name") or agent_id)
            key = agent_id
            if key not in agents:
                agents[key] = {
                    "id":        agent_id,
                    "name":      agent_name,
                    "last_seen": ca,
                    "alerts":    0,
                    "os":        str(a.get("os_name") or a.get("os") or "—"),
                    "ip":        str(a.get("agent_ip") or a.get("source_ip") or "—"),
                    "status":    "active",
                }
            agents[key]["alerts"] += 1
            if ca > agents[key]["last_seen"]:
                agents[key]["last_seen"] = ca
        return sorted(agents.values(), key=lambda x: x["last_seen"], reverse=True)

    async def get_top_rules(self, limit: int = 10) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT alert_json FROM hitl_reviews"
            )

        counts: dict[str, int] = {}
        for row in rows:
            try:
                a = json.loads(row["alert_json"])
            except Exception:
                continue
            rule = str(a.get("rule_description") or a.get("rule") or "Unknown rule")[:80]
            counts[rule] = counts.get(rule, 0) + 1
        sorted_rules = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"rule": r, "count": c} for r, c in sorted_rules]

    async def store_audit_entry(self, entry: AuditEntry) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_log
                  (id, alert_id, outcome, pipeline_trace_json,
                   analyst_id, hitl_elapsed_seconds, recorded_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                str(uuid.uuid4()),
                entry.alert_id,
                entry.outcome,
                json.dumps([s.model_dump(mode="json") for s in entry.pipeline_trace]),
                entry.analyst_id,
                entry.hitl_elapsed_seconds,
                entry.timestamp,
            )

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
