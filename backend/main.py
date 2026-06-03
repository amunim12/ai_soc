# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
AI SOC — main.py

FastAPI application entry point.
Mounts all API routers and initialises shared resources on startup.

Start the API server:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from infrastructure.sqlite_client import sqlite_client
from infrastructure.kafka_client import kafka_producer


from api.hitl_api import app as _hitl_sub  # noqa: F401  (kept for reference)
from api.soar_routes import router as soar_router
from api.soar_routes import initialise_soar_tables
from api.auth_api import router as auth_router
from api.rag_api  import router as rag_router
from api.siem_api import router as siem_router
from api.soar_api import router as soar_dash_router
from api.log_source_api import router as log_source_router

load_dotenv()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger(__name__)

_jwt_secret = os.getenv("JWT_SECRET_KEY", "")
_is_insecure = (
    not _jwt_secret
    or _jwt_secret.startswith("change-me")
    or _jwt_secret.startswith("soc-pipeline-dev")
    or len(_jwt_secret) < 32
)
if _is_insecure:
    raise RuntimeError(
        "JWT_SECRET_KEY is not set or is still the insecure default. "
        "Generate a strong secret with: "
        "python -c \"import secrets; print(secrets.token_hex(64))\" "
        "and set it in your .env file before starting the server."
    )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Startup / shutdown lifecycle."""
    from infrastructure.auth_client import auth_client
    from infrastructure.log_source_store import log_source_store
    await sqlite_client.initialise()
    await log_source_store.initialise()
    await initialise_soar_tables()
    await auth_client.initialise()
    log.info("AI SOC API started")
    yield
    kafka_producer.flush()
    log.info("AI SOC API shutting down")


app = FastAPI(
    title="AI SOC API",
    description=(
        "Supervisor-directed multi-agent security pipeline. "
        "Exposes HITL decision and Shuffle SOAR integration endpoints."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:8000", "app://.", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from api.hitl_api import (
    submit_decision,
    get_review_status,
    health as hitl_health,
)
app.add_api_route(
    "/api/hitl/{review_id}/decision",
    submit_decision,
    methods=["POST"],
    tags=["hitl"],
)
app.add_api_route(
    "/api/hitl/{review_id}/status",
    get_review_status,
    methods=["GET"],
    tags=["hitl"],
)
app.add_api_route(
    "/health/hitl",
    hitl_health,
    methods=["GET"],
    tags=["health"],
)


app.include_router(soar_router)
app.include_router(auth_router)
app.include_router(rag_router)
app.include_router(siem_router)
app.include_router(soar_dash_router)
app.include_router(log_source_router)


@app.get("/health", tags=["health"])
async def health() -> dict:
    """Top-level health check."""
    return {"status": "ok", "service": "ai_soc_pipeline"}


@app.get("/api/hitl/pending", tags=["hitl"])
async def get_pending_reviews() -> list:
    """Return all pending HITL reviews for the dashboard."""
    return await sqlite_client.get_pending_reviews()


@app.get("/api/metrics", tags=["dashboard"])
async def get_metrics() -> dict:
    """Return aggregate SOC pipeline health metrics."""
    return await sqlite_client.get_metrics()


@app.get("/api/activity", tags=["dashboard"])
async def get_activity(hours: int = 24) -> list:
    """Return per-hour alert activity for the last N hours."""
    return await sqlite_client.get_activity(hours)


@app.get("/api/agents", tags=["dashboard"])
async def get_agents() -> list:
    """Return monitored agents derived from alert data."""
    return await sqlite_client.get_agents()


@app.get("/api/rules/top", tags=["dashboard"])
async def get_top_rules(limit: int = 10) -> list:
    """Return top N most frequently triggered rules."""
    return await sqlite_client.get_top_rules(limit)
