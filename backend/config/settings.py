# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Application Settings — config/settings.py

Single source of truth for all environment-driven configuration.
Uses pydantic-settings so every field is validated at startup.
Load order: environment variables → .env file → defaults.

Usage:
    from config.settings import settings
    print(settings.SHUFFLE_BASE_URL)
"""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All runtime configuration, sourced from environment / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


    KAFKA_BOOTSTRAP_SERVERS:  str = "localhost:9092"
    KAFKA_GROUP_ID:           str = "ai_soc_pipeline"

    KAFKA_LINGER_MS:          int = 5
    KAFKA_BATCH_SIZE_BYTES:   int = 65536
    KAFKA_COMPRESSION_TYPE:   str = "lz4"
    KAFKA_ACKS:               str = "all"


    REDIS_URL: str = "redis://localhost:6379/0"


    CHROMA_HOST: str = "localhost"
    CHROMA_PORT: int = 8000


    SQLITE_DB_PATH: str = "./data/hitl.db"


    WAZUH_API_URL:  str = "https://wazuh-manager:55000"
    WAZUH_USER:     str = "wazuh"
    WAZUH_PASSWORD: str = ""
    WAZUH_CA_CERT:  Optional[str] = Field(
        None,
        description="Path to Wazuh Manager CA certificate (PEM). "
                    "Use this for self-signed certs instead of disabling TLS verification.",
    )
    WAZUH_TLS_VERIFY: bool = Field(
        True,
        description="Set False only in isolated dev environments with no CA cert available. "
                    "Disabling TLS verification allows MITM attacks.",
    )


    HUGGING_FACE_HUB_TOKEN: Optional[str] = None


    VIRUSTOTAL_API_KEY: Optional[str] = None
    OTX_API_KEY:        Optional[str] = None
    SHODAN_API_KEY:     Optional[str] = None
    MISP_URL:           str = "https://misp.local"
    MISP_API_KEY:       Optional[str] = None
    MAXMIND_DB_PATH:    str = "./data/GeoLite2-City.mmdb"


    SLACK_WEBHOOK_URL: Optional[str] = None
    SMTP_HOST:         str = "smtp.gmail.com"
    SMTP_PORT:         int = 587
    SMTP_USER:         str = ""
    SMTP_PASSWORD:     str = ""
    SMTP_FROM:         str = "soc-pipeline@example.com"
    ANALYST_EMAIL:     str = "analyst@example.com"
    HITL_API_BASE:     str = "http://localhost:8080"


    USE_MOCK_TI:            bool  = True
    HITL_TIMEOUT_SECONDS:   int   = 900
    HITL_ESCALATE_SECONDS:  int   = 600
    CONFIDENCE_THRESHOLD:   float = 0.85
    LOG_LEVEL:              str   = "INFO"
    SOAR_ENABLED:           bool  = True

    # Pipeline concurrency & throughput
    PIPELINE_MAX_CONCURRENT_ALERTS: int   = 512
    KAFKA_NUM_CONSUMER_WORKERS:     int   = 16
    LLM_MAX_CONCURRENT_CALLS:       int   = 64
    LLM_CALL_TIMEOUT_SECONDS:       float = 30.0
    PLAYBOOK_CACHE_TTL_SECONDS:     int   = 3600
    RAG_CTX_CACHE_TTL_SECONDS:      int   = 3600

    # Wazuh bridge ingestion
    WAZUH_POLL_INTERVAL: int = 1
    WAZUH_BATCH_SIZE:    int = 1200


    SHUFFLE_BASE_URL: str = "http://127.0.0.1:5001"
    SHUFFLE_API_KEY:  str = Field(..., description="Shuffle SOAR API key (required)")
    SHUFFLE_WORKFLOW_IDS_PATH: str = "/opt/config/shuffle_workflow_ids.json"
    SHUFFLE_EXECUTION_TIMEOUT: int = 900
    SHUFFLE_POLL_INTERVAL:     int = 5


    FASTAPI_INTERNAL_URL: str = "http://localhost:8000"


    JWT_SECRET_KEY:     str = "change-me-in-production-use-strong-random-secret"
    JWT_ALGORITHM:      str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480


    POSTGRES_DSN: Optional[str] = None


    LOCAL_AI_ONLY:          bool = False
    LOCAL_EMBEDDING_MODEL:  str  = "all-MiniLM-L6-v2"

    LOCAL_LLM_BASE_URL:     Optional[str] = None

    LOCAL_LLM_MODEL:        str  = "Qwen/Qwen2.5-72B-Instruct-AWQ"

    LOCAL_LLM_API_KEY:      str  = "local-vllm-key"


    RAG_UPLOAD_MAX_MB:  int = 50
    RAG_CHUNK_SIZE:     int = 512
    RAG_CHUNK_OVERLAP:  int = 64


    WAZUH_DASHBOARD_URL:   str = "https://localhost:443"
    SHUFFLE_DASHBOARD_URL: str = "http://localhost:3001"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached Settings singleton. Call this everywhere."""
    return Settings()


settings: Settings = get_settings()
