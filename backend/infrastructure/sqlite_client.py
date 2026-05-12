# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
SQLite client — HITL decision storage and pipeline audit log.

Tables:
  hitl_reviews    — pending/resolved HITL review records
  hitl_decisions  — analyst decisions (poll target for HITL agent)
  audit_log       — immutable pipeline execution records
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime
from typing import Optional

import aiosqlite
from dotenv import load_dotenv

from schemas.hitl import ApprovalDecision
from schemas.playbook import Playbook
from schemas.audit import AuditEntry

load_dotenv()
log = logging.getLogger(__name__)

SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "./data/hitl.db")

DDL = """
CREATE TABLE IF NOT EXISTS hitl_reviews (
    review_id     TEXT PRIMARY KEY,
    alert_id      TEXT NOT NULL,
    alert_json    TEXT NOT NULL,
    playbook_json TEXT NOT NULL,
    confidence    REAL NOT NULL,
    reason        TEXT,
    status        TEXT NOT NULL DEFAULT 'PENDING',
    expires_at    TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hitl_decisions (
    decision_id   TEXT PRIMARY KEY,
    review_id     TEXT NOT NULL,
    action        TEXT NOT NULL,
    analyst_id    TEXT NOT NULL,
    notes         TEXT,
    final_playbook_json TEXT,
    elapsed_seconds INTEGER,
    decided_at    TEXT NOT NULL,
    FOREIGN KEY (review_id) REFERENCES hitl_reviews(review_id)
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
    recorded_at   TEXT NOT NULL
);
"""


class SQLiteClient:
    """Async SQLite client for HITL and audit persistence."""

    def __init__(self, db_path: str = SQLITE_DB_PATH):
        self._db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)

    @property
    def db_path(self) -> str:
        return self._db_path

    async def initialise(self) -> None:
        """
        Create tables if they don't exist. Call once at startup.

        Also sets WAL journaling, relaxed sync, and a busy timeout so the
        single-writer pipeline can sustain higher write throughput without
        lock contention. This pushes aiosqlite from ~300 writes/sec to
        ~2000+ writes/sec, which is enough for the current EPS target and
        avoids the larger Postgres migration.
        """
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute("PRAGMA synchronous=NORMAL")
            await db.execute("PRAGMA busy_timeout=5000")
            await db.execute("PRAGMA temp_store=MEMORY")
            await db.executescript(DDL)
            await db.commit()
        log.info("SQLite initialised at %s (WAL, sync=NORMAL)", self._db_path)


    async def store_pending_review(
        self,
        alert,
        playbook: Playbook,
        confidence: float,
        reason: str,
        expires_at: Optional[datetime] = None,
    ) -> str:
        review_id = str(uuid.uuid4())
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                INSERT INTO hitl_reviews
                  (review_id, alert_id, alert_json, playbook_json, confidence,
                   reason, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    review_id,
                    alert.id,
                    alert.model_dump_json(),
                    playbook.model_dump_json(),
                    confidence,
                    reason,
                    expires_at.isoformat() if expires_at else None,
                    datetime.utcnow().isoformat(),
                ),
            )
            await db.commit()
        log.info("HITL review stored: %s (alert=%s)", review_id, alert.id)
        return review_id

    async def poll_decision(
        self, review_id: str
    ) -> Optional[ApprovalDecision]:
        """Returns ApprovalDecision if analyst has submitted one, else None."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM hitl_decisions WHERE review_id = ? ORDER BY decided_at DESC LIMIT 1",
                (review_id,),
            ) as cursor:
                row = await cursor.fetchone()
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
            decided_at=datetime.fromisoformat(row["decided_at"]),
        )

    async def store_decision(self, decision: ApprovalDecision) -> None:
        """Called by the HITL API after analyst submits."""
        fp_json = None
        if decision.final_playbook:
            fp_json = decision.final_playbook.model_dump_json()

        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                INSERT INTO hitl_decisions
                  (decision_id, review_id, action, analyst_id, notes,
                   final_playbook_json, elapsed_seconds, decided_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    decision.review_id,
                    decision.action,
                    decision.analyst_id,
                    decision.notes,
                    fp_json,
                    decision.elapsed_seconds,
                    decision.decided_at.isoformat(),
                ),
            )
            await db.execute(
                "UPDATE hitl_reviews SET status = ? WHERE review_id = ?",
                (decision.action, decision.review_id),
            )
            await db.commit()


    async def get_pending_reviews(self) -> list[dict]:
        """Return all PENDING HITL reviews ordered newest-first."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM hitl_reviews WHERE status = 'PENDING' ORDER BY created_at DESC"
            ) as cursor:
                rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_review_by_id(self, review_id: str) -> Optional[dict]:
        """Return a single hitl_review row as a dict, or None if not found."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM hitl_reviews WHERE review_id = ? LIMIT 1",
                (review_id,),
            ) as cursor:
                row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_metrics(self) -> dict:
        """Return aggregate pipeline health metrics."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT COUNT(*) as cnt FROM audit_log") as cur:
                total = (await cur.fetchone())["cnt"]
            async with db.execute(
                "SELECT COUNT(*) as cnt FROM audit_log WHERE outcome = 'EXECUTED'"
            ) as cur:
                executed = (await cur.fetchone())["cnt"]
            async with db.execute(
                "SELECT COUNT(*) as cnt FROM audit_log WHERE outcome = 'DROPPED'"
            ) as cur:
                dropped = (await cur.fetchone())["cnt"]
            async with db.execute(
                "SELECT COUNT(*) as cnt FROM audit_log WHERE outcome = 'ESCALATED'"
            ) as cur:
                escalated = (await cur.fetchone())["cnt"]
            async with db.execute(
                "SELECT COUNT(*) as cnt FROM hitl_reviews WHERE status = 'PENDING'"
            ) as cur:
                pending = (await cur.fetchone())["cnt"]
            async with db.execute(
                "SELECT AVG(confidence) as avg_conf FROM hitl_reviews"
            ) as cur:
                row = await cur.fetchone()
                avg_conf = row["avg_conf"] if row["avg_conf"] is not None else 0.0
        return {
            "total_alerts": total,
            "executed_playbooks": executed,
            "dropped_alerts": dropped,
            "escalated_alerts": escalated,
            "pending_reviews": pending,
            "avg_confidence": round(float(avg_conf), 3),
        }

    async def get_activity(self, hours: int = 24) -> list[dict]:
        """Return per-hour alert counts from audit_log for the last N hours."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT strftime('%H:00', recorded_at) as hour,
                       COUNT(*) as count,
                       SUM(CASE WHEN outcome = 'EXECUTED' THEN 1 ELSE 0 END) as executed,
                       SUM(CASE WHEN outcome = 'DROPPED'  THEN 1 ELSE 0 END) as dropped
                FROM audit_log
                WHERE recorded_at >= datetime('now', ?)
                GROUP BY strftime('%H', recorded_at)
                ORDER BY recorded_at
                """,
                (f"-{hours} hours",),
            ) as cursor:
                rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_severity_breakdown(self, hours: int = 24) -> list[dict]:
        """
        Return per-hour alert counts split by severity for the last N hours.
        Parses severity from alert_json stored in hitl_reviews.
        """
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT alert_json, created_at
                FROM hitl_reviews
                WHERE created_at >= datetime('now', ?)
                ORDER BY created_at
                """,
                (f"-{hours} hours",),
            ) as cursor:
                rows = await cursor.fetchall()

        buckets: dict[str, dict[str, int]] = {}
        for row in rows:
            hour = row["created_at"][:13] + ":00"
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
        """
        Count top MITRE ATT&CK technique IDs from stored alert + playbook JSON.
        Returns [{technique_id, technique_name, count}] sorted descending.
        """
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT alert_json, playbook_json FROM hitl_reviews"
            ) as cursor:
                rows = await cursor.fetchall()

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

        sorted_counts = sorted(counts.values(), key=lambda x: x["count"], reverse=True)[:limit]
        return sorted_counts

    async def get_recent_alerts(self, limit: int = 100) -> list[dict]:
        """Return recent alerts parsed from hitl_reviews, newest first."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT review_id, alert_json, confidence, created_at FROM hitl_reviews ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()

        results = []
        for row in rows:
            try:
                a = json.loads(row["alert_json"])
            except Exception:
                a = {}
            results.append({
                "review_id":       row["review_id"],
                "alert_id":        a.get("id", row["review_id"]),
                "severity":        (a.get("severity") or "MEDIUM").upper(),
                "category":        a.get("alert_category") or "—",
                "rule_description":a.get("rule_description") or "—",
                "agent_name":      a.get("agent_name") or a.get("agent_id") or "—",
                "agent_ip":        a.get("agent_ip") or a.get("source_ip") or "—",
                "source_ip":       a.get("source_ip") or "—",
                "dest_ip":         a.get("destination_ip") or "—",
                "user":            a.get("user") or "—",
                "mitre_techniques":a.get("mitre_techniques") or [],
                "confidence":      row["confidence"],
                "created_at":      row["created_at"],
            })
        return results

    async def get_agents(self) -> list[dict]:
        """
        Derive agent summary from alerts stored in hitl_reviews.
        Returns unique agents with their last-seen time and alert count.
        """
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT alert_json, created_at FROM hitl_reviews ORDER BY created_at DESC"
            ) as cursor:
                rows = await cursor.fetchall()

        agents: dict[str, dict] = {}
        for row in rows:
            try:
                a = json.loads(row["alert_json"])
            except Exception:
                continue
            agent_id   = str(a.get("agent_id") or "unknown")
            agent_name = str(a.get("agent_name") or agent_id)
            key = agent_id
            if key not in agents:
                agents[key] = {
                    "id":        agent_id,
                    "name":      agent_name,
                    "last_seen": row["created_at"],
                    "alerts":    0,
                    "os":        str(a.get("os_name") or a.get("os") or "—"),
                    "ip":        str(a.get("agent_ip") or a.get("source_ip") or "—"),
                    "status":    "active",
                }
            agents[key]["alerts"] += 1

            if row["created_at"] > agents[key]["last_seen"]:
                agents[key]["last_seen"] = row["created_at"]

        return sorted(agents.values(), key=lambda x: x["last_seen"], reverse=True)

    async def get_top_rules(self, limit: int = 10) -> list[dict]:
        """
        Count the most frequently triggered rules from alert_json in hitl_reviews.
        Returns list of {rule, count} sorted descending.
        """
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT alert_json FROM hitl_reviews"
            ) as cursor:
                rows = await cursor.fetchall()

        counts: dict[str, int] = {}
        for row in rows:
            try:
                a = json.loads(row["alert_json"])
            except Exception:
                continue
            rule = str(a.get("rule_description") or a.get("rule") or "Unknown rule")
            rule = rule[:80]
            counts[rule] = counts.get(rule, 0) + 1

        sorted_rules = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"rule": r, "count": c} for r, c in sorted_rules]


    async def store_audit_entry(self, entry: AuditEntry) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                INSERT INTO audit_log
                  (id, alert_id, outcome, pipeline_trace_json,
                   analyst_id, hitl_elapsed_seconds, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    entry.alert_id,
                    entry.outcome,
                    json.dumps([s.model_dump(mode="json") for s in entry.pipeline_trace]),
                    entry.analyst_id,
                    entry.hitl_elapsed_seconds,
                    entry.timestamp.isoformat(),
                ),
            )
            await db.commit()


_POSTGRES_DSN = os.getenv("POSTGRES_DSN")

if _POSTGRES_DSN:
    from infrastructure.postgres_client import PostgresClient
    sqlite_client = PostgresClient(_POSTGRES_DSN)  # type: ignore[assignment]
    log.info("DB backend: PostgreSQL (%s)", _POSTGRES_DSN.split("@")[-1] if "@" in _POSTGRES_DSN else "")
else:
    sqlite_client = SQLiteClient()
    log.info("DB backend: SQLite (%s)", SQLITE_DB_PATH)
