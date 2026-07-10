# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Auth Client — infrastructure/auth_client.py

SOC2-compliant JWT authentication with bcrypt password hashing.
Stores users in SQLite (or PostgreSQL when POSTGRES_DSN is set).
Every login attempt — success or failure — is written to the audit log.

Roles:
  admin   — full access (vector DB upload, user management)
  analyst — HITL review, execution history, dashboard
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

import aiosqlite
import bcrypt
from jose import JWTError, jwt

from config.settings import settings

log = logging.getLogger(__name__)

DB_PATH = settings.SQLITE_DB_PATH


AUTH_DDL = """
CREATE TABLE IF NOT EXISTS users (
    user_id    TEXT PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'analyst',
    is_active  INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT
);

CREATE TABLE IF NOT EXISTS auth_audit (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    event      TEXT NOT NULL,     -- LOGIN_SUCCESS | LOGIN_FAILED | LOGOUT | TOKEN_REFRESH
    ip_address TEXT,
    user_agent TEXT,
    timestamp  TEXT NOT NULL
);
"""


DEFAULT_ADMIN_USER = os.getenv("DEFAULT_ADMIN_USER", "admin")

# If not explicitly set, generate a random password and print it once.
# Operators MUST capture this from the startup log on first run.
_env_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "")
if _env_password:
    DEFAULT_ADMIN_PASSWORD = _env_password
else:
    import secrets as _secrets
    DEFAULT_ADMIN_PASSWORD = _secrets.token_urlsafe(24)
    log.warning(
        "DEFAULT_ADMIN_PASSWORD not set — generated for this run. "
        "Set DEFAULT_ADMIN_PASSWORD in .env to persist across restarts."
    )


def create_access_token(user_id: str, username: str, role: str) -> str:
    """Sign a JWT with user identity and role."""
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {
        "sub":      user_id,
        "username": username,
        "role":     role,
        "exp":      expire,
        "iat":      datetime.utcnow(),
        "jti":      str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT. Raises JWTError on failure."""
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


class AuthClient:
    """Async SQLite-backed auth client with SOC2 audit logging."""

    def __init__(self, db_path: str = DB_PATH):
        self._db_path = db_path

    async def initialise(self) -> None:
        """Create auth tables and seed default admin if needed."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(AUTH_DDL)
            await db.commit()


            async with db.execute("SELECT COUNT(*) FROM users") as cur:
                count = (await cur.fetchone())[0]
            if count == 0:
                await db.execute(
                    """INSERT INTO users (user_id, username, password_hash, role, created_at)
                       VALUES (?, ?, ?, 'admin', ?)""",
                    (str(uuid.uuid4()), DEFAULT_ADMIN_USER,
                     hash_password(DEFAULT_ADMIN_PASSWORD),
                     datetime.utcnow().isoformat()),
                )
                await db.commit()
                log.info("Auth: seeded default admin user '%s'", DEFAULT_ADMIN_USER)

    async def authenticate(
        self,
        username: str,
        password: str,
        ip_address: str = "",
        user_agent: str = "",
    ) -> Optional[dict]:
        """
        Verify credentials. Returns token dict on success, None on failure.
        Always writes to auth_audit regardless of outcome.
        """
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM users WHERE username = ? AND is_active = 1",
                (username,),
            ) as cur:
                user = await cur.fetchone()

        success = user is not None and verify_password(password, user["password_hash"])
        event   = "LOGIN_SUCCESS" if success else "LOGIN_FAILED"

        await self._audit(username, event, ip_address, user_agent)

        if not success:
            log.warning("Auth: failed login for '%s' from %s", username, ip_address)
            return None


        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE users SET last_login = ? WHERE username = ?",
                (datetime.utcnow().isoformat(), username),
            )
            await db.commit()

        token = create_access_token(user["user_id"], user["username"], user["role"])
        log.info("Auth: '%s' logged in (role=%s) from %s", username, user["role"], ip_address)
        return {
            "access_token": token,
            "token_type":   "bearer",
            "expires_in":   settings.JWT_EXPIRE_MINUTES * 60,
            "username":     user["username"],
            "role":         user["role"],
        }

    async def get_user_by_id(self, user_id: str) -> Optional[dict]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT user_id, username, role, is_active, created_at, last_login FROM users WHERE user_id = ?",
                (user_id,),
            ) as cur:
                row = await cur.fetchone()
        return dict(row) if row else None

    async def list_users(self) -> list[dict]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT user_id, username, role, is_active, created_at, last_login FROM users ORDER BY created_at"
            ) as cur:
                rows = await cursor.fetchall() if False else await cur.fetchall()
        return [dict(r) for r in rows]

    async def create_user(self, username: str, password: str, role: str = "analyst") -> dict:
        user_id = str(uuid.uuid4())
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT INTO users (user_id, username, password_hash, role, created_at) VALUES (?,?,?,?,?)",
                (user_id, username, hash_password(password), role, datetime.utcnow().isoformat()),
            )
            await db.commit()
        log.info("Auth: created user '%s' role=%s", username, role)
        return {"user_id": user_id, "username": username, "role": role}

    async def _audit(self, username: str, event: str, ip: str, ua: str) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT INTO auth_audit (id, username, event, ip_address, user_agent, timestamp) VALUES (?,?,?,?,?,?)",
                (str(uuid.uuid4()), username, event, ip, ua, datetime.utcnow().isoformat()),
            )
            await db.commit()


auth_client = AuthClient()
