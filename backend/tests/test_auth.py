# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Security function tests for the auth module.
ATE_COV.2 — Analysis of Coverage.

Covers: password hashing, JWT lifecycle, AuthClient CRUD + audit logging,
and every auth API endpoint (login, /me, /users, /audit) with RBAC checks.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta

# Provide required env vars before any application imports.
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-that-is-at-least-32-chars!!")
os.environ.setdefault("SHUFFLE_API_KEY", "test-shuffle-key")

import pytest
import pytest_asyncio
from jose import JWTError, jwt

from config.settings import settings
from infrastructure.auth_client import (
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_USER,
    AuthClient,
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def auth_db(tmp_path):
    """Fresh AuthClient backed by a temp SQLite file, fully initialised."""
    client = AuthClient(db_path=str(tmp_path / "auth_test.db"))
    await client.initialise()
    return client


@pytest.fixture
def admin_creds():
    """Credentials that match the seeded default admin account."""
    return DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASSWORD


@pytest_asyncio.fixture
async def api_client(auth_db, monkeypatch):
    """Async HTTPX client for the auth router wired to the test AuthClient."""
    import api.auth_api as auth_api_module
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    monkeypatch.setattr(auth_api_module, "auth_client", auth_db)
    # Point the audit endpoint at the same test database.
    monkeypatch.setattr(auth_api_module, "SQLITE_DB_PATH", auth_db._db_path)

    app = FastAPI()
    app.include_router(auth_api_module.router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


async def _login_token(api_client, username: str, password: str) -> str:
    resp = await api_client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        assert hash_password("secret123") != "secret123"

    def test_bcrypt_work_factor_at_least_12(self):
        h = hash_password("password")
        rounds = int(h.split("$")[2])
        assert rounds >= 12

    def test_correct_password_verifies(self):
        plain = "correct-horse-battery-staple"
        assert verify_password(plain, hash_password(plain)) is True

    def test_wrong_password_rejected(self):
        assert verify_password("wrong", hash_password("correct")) is False

    def test_hashes_are_salted(self):
        """Same plaintext must produce distinct hashes each call."""
        assert hash_password("same") != hash_password("same")

    def test_empty_password_round_trips(self):
        h = hash_password("")
        assert verify_password("", h) is True
        assert verify_password("notempty", h) is False


# ---------------------------------------------------------------------------
# JWT token creation and decoding
# ---------------------------------------------------------------------------


class TestJwtTokens:
    def _make(self, role: str = "analyst") -> str:
        return create_access_token(str(uuid.uuid4()), "testuser", role)

    def test_token_is_non_empty_string(self):
        t = self._make()
        assert isinstance(t, str) and len(t) > 20

    def test_decoded_claims_are_present(self):
        uid = str(uuid.uuid4())
        payload = decode_token(create_access_token(uid, "alice", "admin"))
        assert payload["sub"] == uid
        assert payload["username"] == "alice"
        assert payload["role"] == "admin"
        for key in ("exp", "iat", "jti"):
            assert key in payload

    def test_jti_unique_across_tokens(self):
        """Each token must carry a distinct JTI — prevents replay attacks."""
        assert decode_token(self._make())["jti"] != decode_token(self._make())["jti"]

    def test_role_preserved(self):
        for role in ("admin", "analyst"):
            assert decode_token(create_access_token("id", "u", role))["role"] == role

    def test_expired_token_raises(self):
        expired = jwt.encode(
            {
                "sub": "uid",
                "username": "user",
                "role": "analyst",
                "exp": datetime.utcnow() - timedelta(seconds=1),
                "iat": datetime.utcnow() - timedelta(minutes=10),
                "jti": str(uuid.uuid4()),
            },
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )
        with pytest.raises(JWTError):
            decode_token(expired)

    def test_tampered_signature_raises(self):
        parts = self._make().split(".")
        parts[-1] = parts[-1][:-1] + ("A" if parts[-1][-1] != "A" else "B")
        with pytest.raises(JWTError):
            decode_token(".".join(parts))

    def test_wrong_secret_raises(self):
        alien = jwt.encode(
            {
                "sub": "uid",
                "username": "user",
                "role": "analyst",
                "exp": datetime.utcnow() + timedelta(hours=1),
                "iat": datetime.utcnow(),
                "jti": str(uuid.uuid4()),
            },
            "totally-different-secret-key-xyz!!",
            algorithm="HS256",
        )
        with pytest.raises(JWTError):
            decode_token(alien)


# ---------------------------------------------------------------------------
# AuthClient — initialisation
# ---------------------------------------------------------------------------


class TestAuthClientInitialise:
    async def test_tables_created(self, auth_db):
        import aiosqlite

        async with aiosqlite.connect(auth_db._db_path) as db:
            async with db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ) as cur:
                tables = {row[0] for row in await cur.fetchall()}
        assert {"users", "auth_audit"} <= tables

    async def test_default_admin_seeded(self, auth_db):
        users = await auth_db.list_users()
        assert any(u["role"] == "admin" for u in users)

    async def test_second_init_does_not_duplicate_admin(self, auth_db):
        await auth_db.initialise()
        admins = [u for u in await auth_db.list_users() if u["role"] == "admin"]
        assert len(admins) == 1


# ---------------------------------------------------------------------------
# AuthClient — authenticate
# ---------------------------------------------------------------------------


class TestAuthClientAuthenticate:
    async def test_success_returns_token_dict(self, auth_db, admin_creds):
        user, pw = admin_creds
        result = await auth_db.authenticate(user, pw)
        assert result is not None
        assert "access_token" in result
        assert result["token_type"] == "bearer"
        assert result["role"] == "admin"
        assert result["username"] == user
        assert isinstance(result["expires_in"], int)

    async def test_wrong_password_returns_none(self, auth_db, admin_creds):
        user, _ = admin_creds
        assert await auth_db.authenticate(user, "wrongpassword") is None

    async def test_unknown_user_returns_none(self, auth_db):
        assert await auth_db.authenticate("ghost", "anypassword") is None

    async def test_inactive_user_rejected(self, auth_db):
        import aiosqlite

        await auth_db.create_user("inactive_u", "pass123", "analyst")
        async with aiosqlite.connect(auth_db._db_path) as db:
            await db.execute(
                "UPDATE users SET is_active = 0 WHERE username = ?", ("inactive_u",)
            )
            await db.commit()
        assert await auth_db.authenticate("inactive_u", "pass123") is None

    async def test_audit_row_written_on_success(self, auth_db, admin_creds):
        import aiosqlite

        user, pw = admin_creds
        await auth_db.authenticate(user, pw)
        async with aiosqlite.connect(auth_db._db_path) as db:
            async with db.execute(
                "SELECT 1 FROM auth_audit WHERE username=? AND event='LOGIN_SUCCESS'",
                (user,),
            ) as cur:
                assert await cur.fetchone() is not None

    async def test_audit_row_written_on_failure(self, auth_db, admin_creds):
        import aiosqlite

        user, _ = admin_creds
        await auth_db.authenticate(user, "badpass")
        async with aiosqlite.connect(auth_db._db_path) as db:
            async with db.execute(
                "SELECT 1 FROM auth_audit WHERE username=? AND event='LOGIN_FAILED'",
                (user,),
            ) as cur:
                assert await cur.fetchone() is not None

    async def test_last_login_updated(self, auth_db, admin_creds):
        import aiosqlite

        user, pw = admin_creds
        before = datetime.utcnow().replace(microsecond=0)
        await auth_db.authenticate(user, pw)
        async with aiosqlite.connect(auth_db._db_path) as db:
            async with db.execute(
                "SELECT last_login FROM users WHERE username=?", (user,)
            ) as cur:
                row = await cur.fetchone()
        assert row and row[0] is not None
        assert datetime.fromisoformat(row[0]) >= before


# ---------------------------------------------------------------------------
# AuthClient — user management
# ---------------------------------------------------------------------------


class TestAuthClientUserManagement:
    async def test_create_user_returns_dict(self, auth_db):
        r = await auth_db.create_user("newuser", "password123", "analyst")
        assert r["username"] == "newuser"
        assert r["role"] == "analyst"
        assert "user_id" in r

    async def test_created_user_can_authenticate(self, auth_db):
        await auth_db.create_user("tester", "mypassword", "analyst")
        r = await auth_db.authenticate("tester", "mypassword")
        assert r is not None and r["username"] == "tester"

    async def test_duplicate_username_raises(self, auth_db):
        await auth_db.create_user("dup", "p1", "analyst")
        with pytest.raises(Exception):
            await auth_db.create_user("dup", "p2", "analyst")

    async def test_get_user_by_id_found(self, auth_db):
        info = await auth_db.create_user("byid", "pw", "analyst")
        user = await auth_db.get_user_by_id(info["user_id"])
        assert user is not None and user["username"] == "byid"

    async def test_get_user_by_id_missing(self, auth_db):
        assert await auth_db.get_user_by_id(str(uuid.uuid4())) is None

    async def test_list_users_contains_created_accounts(self, auth_db):
        await auth_db.create_user("u1", "pw1", "analyst")
        await auth_db.create_user("u2", "pw2", "admin")
        names = {u["username"] for u in await auth_db.list_users()}
        assert {"u1", "u2"} <= names

    async def test_list_users_excludes_password_hash(self, auth_db):
        for user in await auth_db.list_users():
            assert "password_hash" not in user


# ---------------------------------------------------------------------------
# API — POST /api/auth/login
# ---------------------------------------------------------------------------


class TestLoginEndpoint:
    async def test_success_returns_bearer_token(self, api_client, admin_creds):
        user, pw = admin_creds
        resp = await api_client.post("/api/auth/login", json={"username": user, "password": pw})
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["role"] == "admin"

    async def test_bad_password_returns_401(self, api_client, admin_creds):
        user, _ = admin_creds
        resp = await api_client.post(
            "/api/auth/login", json={"username": user, "password": "wrong"}
        )
        assert resp.status_code == 401

    async def test_unknown_user_returns_401(self, api_client):
        resp = await api_client.post(
            "/api/auth/login", json={"username": "ghost", "password": "pw"}
        )
        assert resp.status_code == 401

    async def test_missing_password_field_returns_422(self, api_client):
        resp = await api_client.post("/api/auth/login", json={"username": "admin"})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# API — GET /api/auth/me
# ---------------------------------------------------------------------------


class TestMeEndpoint:
    async def test_returns_user_profile(self, api_client, admin_creds):
        token = await _login_token(api_client, *admin_creds)
        resp = await api_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == admin_creds[0]
        assert "user_id" in body

    async def test_no_token_returns_401(self, api_client):
        assert (await api_client.get("/api/auth/me")).status_code == 401

    async def test_invalid_token_returns_401(self, api_client):
        resp = await api_client.get(
            "/api/auth/me", headers={"Authorization": "Bearer not.a.valid.token"}
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# API — POST /api/auth/users  (admin-only)
# ---------------------------------------------------------------------------


class TestCreateUserEndpoint:
    async def test_admin_creates_user(self, api_client, admin_creds):
        token = await _login_token(api_client, *admin_creds)
        resp = await api_client.post(
            "/api/auth/users",
            json={"username": "newanalyst", "password": "pass123", "role": "analyst"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201
        assert resp.json()["username"] == "newanalyst"

    async def test_analyst_is_forbidden(self, api_client, auth_db):
        await auth_db.create_user("an_analyst", "pass", "analyst")
        token = await _login_token(api_client, "an_analyst", "pass")
        resp = await api_client.post(
            "/api/auth/users",
            json={"username": "x", "password": "y", "role": "analyst"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    async def test_invalid_role_returns_422(self, api_client, admin_creds):
        token = await _login_token(api_client, *admin_creds)
        resp = await api_client.post(
            "/api/auth/users",
            json={"username": "badrole", "password": "pass123", "role": "superuser"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422

    async def test_unauthenticated_returns_401(self, api_client):
        resp = await api_client.post(
            "/api/auth/users",
            json={"username": "x", "password": "y", "role": "analyst"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# API — GET /api/auth/users  (admin-only)
# ---------------------------------------------------------------------------


class TestListUsersEndpoint:
    async def test_admin_receives_list(self, api_client, admin_creds):
        token = await _login_token(api_client, *admin_creds)
        resp = await api_client.get(
            "/api/auth/users", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    async def test_analyst_is_forbidden(self, api_client, auth_db):
        await auth_db.create_user("list_analyst", "pass", "analyst")
        token = await _login_token(api_client, "list_analyst", "pass")
        resp = await api_client.get(
            "/api/auth/users", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# API — GET /api/auth/audit  (admin-only)
# ---------------------------------------------------------------------------


class TestAuditEndpoint:
    async def test_admin_can_view_audit_log(self, api_client, auth_db, admin_creds):
        user, pw = admin_creds
        await api_client.post("/api/auth/login", json={"username": user, "password": pw})
        token = await _login_token(api_client, user, pw)
        resp = await api_client.get(
            "/api/auth/audit", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200
        entries = resp.json()
        assert isinstance(entries, list)
        assert any(e["event"] == "LOGIN_SUCCESS" for e in entries)

    async def test_analyst_is_forbidden(self, api_client, auth_db):
        await auth_db.create_user("audit_analyst", "pass", "analyst")
        token = await _login_token(api_client, "audit_analyst", "pass")
        resp = await api_client.get(
            "/api/auth/audit", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403

    async def test_unauthenticated_returns_401(self, api_client):
        assert (await api_client.get("/api/auth/audit")).status_code == 401
