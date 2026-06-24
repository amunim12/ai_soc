# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0
"""
Log Source persistence — SQLite table managed alongside the HITL tables.

Uses the same database file as sqlite_client so WAL-mode sharing is safe.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from schemas.log_source import LogSource, LogSourceCreate, LogSourceUpdate

log = logging.getLogger(__name__)

SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "./data/hitl.db")

DDL = """
CREATE TABLE IF NOT EXISTS log_sources (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    source_type       TEXT NOT NULL DEFAULT 'agent',
    host              TEXT NOT NULL,
    os_type           TEXT,
    wazuh_agent_id    TEXT,
    wazuh_status      TEXT NOT NULL DEFAULT 'pending',
    soar_enabled      INTEGER NOT NULL DEFAULT 0,
    soar_actions      TEXT NOT NULL DEFAULT '[]',
    soar_target_label TEXT,
    tags              TEXT NOT NULL DEFAULT '[]',
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_log_sources_host
    ON log_sources(host);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_model(row: aiosqlite.Row) -> LogSource:
    d = dict(row)
    return LogSource(
        id=d["id"],
        name=d["name"],
        description=d["description"],
        source_type=d["source_type"],
        host=d["host"],
        os_type=d.get("os_type"),
        wazuh_agent_id=d.get("wazuh_agent_id"),
        wazuh_status=d.get("wazuh_status", "pending"),
        soar_enabled=bool(d["soar_enabled"]),
        soar_actions=json.loads(d["soar_actions"] or "[]"),
        soar_target_label=d.get("soar_target_label"),
        tags=json.loads(d["tags"] or "[]"),
        created_at=datetime.fromisoformat(d["created_at"]),
        updated_at=datetime.fromisoformat(d["updated_at"]),
    )


class LogSourceStore:
    def __init__(self, db_path: str = SQLITE_DB_PATH):
        self._db = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)

    async def initialise(self) -> None:
        async with aiosqlite.connect(self._db) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.executescript(DDL)
            await db.commit()
        log.info("LogSourceStore initialised")

    async def list(self) -> list[LogSource]:
        async with aiosqlite.connect(self._db) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM log_sources ORDER BY created_at DESC"
            ) as cur:
                rows = await cur.fetchall()
        return [_row_to_model(r) for r in rows]

    async def get(self, source_id: str) -> Optional[LogSource]:
        async with aiosqlite.connect(self._db) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM log_sources WHERE id = ?", (source_id,)
            ) as cur:
                row = await cur.fetchone()
        return _row_to_model(row) if row else None

    async def create(self, body: LogSourceCreate) -> LogSource:
        source_id = str(uuid.uuid4())
        now = _now()
        async with aiosqlite.connect(self._db) as db:
            await db.execute(
                """
                INSERT INTO log_sources
                  (id, name, description, source_type, host, os_type,
                   wazuh_status, soar_enabled, soar_actions, soar_target_label,
                   tags, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    source_id,
                    body.name,
                    body.description,
                    body.source_type,
                    body.host,
                    body.os_type,
                    "pending",
                    int(body.soar_enabled),
                    json.dumps(body.soar_actions),
                    body.soar_target_label,
                    json.dumps(body.tags),
                    now,
                    now,
                ),
            )
            await db.commit()
        log.info("Log source created: %s (%s)", body.name, source_id)
        return (await self.get(source_id))  # type: ignore[return-value]

    async def update(self, source_id: str, body: LogSourceUpdate) -> Optional[LogSource]:
        existing = await self.get(source_id)
        if not existing:
            return None

        fields = body.model_dump(exclude_none=True)
        if not fields:
            return existing

        set_clauses = []
        values = []
        for key, val in fields.items():
            if key in ("soar_actions", "tags"):
                val = json.dumps(val)
            elif key == "soar_enabled":
                val = int(val)
            set_clauses.append(f"{key} = ?")
            values.append(val)

        set_clauses.append("updated_at = ?")
        values.append(_now())
        values.append(source_id)

        async with aiosqlite.connect(self._db) as db:
            await db.execute(
                f"UPDATE log_sources SET {', '.join(set_clauses)} WHERE id = ?",
                values,
            )
            await db.commit()
        return await self.get(source_id)

    async def update_wazuh_status(
        self, source_id: str, wazuh_agent_id: Optional[str], status: str
    ) -> None:
        async with aiosqlite.connect(self._db) as db:
            await db.execute(
                "UPDATE log_sources SET wazuh_agent_id=?, wazuh_status=?, updated_at=? WHERE id=?",
                (wazuh_agent_id, status, _now(), source_id),
            )
            await db.commit()

    async def delete(self, source_id: str) -> bool:
        async with aiosqlite.connect(self._db) as db:
            cur = await db.execute(
                "DELETE FROM log_sources WHERE id = ?", (source_id,)
            )
            await db.commit()
        return cur.rowcount > 0

    async def find_by_host(self, host: str) -> Optional[LogSource]:
        async with aiosqlite.connect(self._db) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM log_sources WHERE host = ? LIMIT 1", (host,)
            ) as cur:
                row = await cur.fetchone()
        return _row_to_model(row) if row else None


log_source_store = LogSourceStore()
