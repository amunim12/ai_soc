# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Auth API — api/auth_api.py

SOC2-compliant RBAC endpoints.

POST /api/auth/login          — issue JWT
GET  /api/auth/me             — current user profile
POST /api/auth/users          — admin: create user
GET  /api/auth/users          — admin: list users
GET  /api/auth/audit          — admin: view auth audit log
"""
from __future__ import annotations

import logging
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from pydantic import BaseModel

from infrastructure.auth_client import auth_client, decode_token
from infrastructure.sqlite_client import sqlite_client, SQLITE_DB_PATH

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])
bearer = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type:   str
    expires_in:   int
    username:     str
    role:         str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role:     str = "analyst"


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
) -> dict:
    """FastAPI dependency — resolves JWT to user dict or raises 401."""
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = decode_token(credentials.credentials)
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")

    user = await auth_client.get_user_by_id(payload["sub"])
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Dependency that restricts endpoint to admin role only."""
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request) -> LoginResponse:
    """Authenticate and receive a JWT. Every attempt is SOC2 audit-logged."""
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")

    result = await auth_client.authenticate(body.username, body.password, ip, ua)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    return LoginResponse(**result)


@router.get("/me")
async def me(user: dict = Depends(get_current_user)) -> dict:
    """Return the current authenticated user's profile."""
    return {
        "user_id":    user["user_id"],
        "username":   user["username"],
        "role":       user["role"],
        "last_login": user.get("last_login"),
    }


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: CreateUserRequest,
    _: dict = Depends(require_admin),
) -> dict:
    """Admin: create a new user account."""
    if body.role not in ("admin", "analyst"):
        raise HTTPException(status_code=422, detail="role must be 'admin' or 'analyst'")
    try:
        return await auth_client.create_user(body.username, body.password, body.role)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/users")
async def list_users(_: dict = Depends(require_admin)) -> list:
    """Admin: list all user accounts."""
    return await auth_client.list_users()


@router.get("/audit")
async def auth_audit(
    limit: int = 100,
    _: dict = Depends(require_admin),
) -> list:
    """Admin: view the SOC2 authentication audit log."""
    async with aiosqlite.connect(SQLITE_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM auth_audit ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]
