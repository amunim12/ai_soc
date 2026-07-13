# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Redis client — deduplication and burst/sliding-window correlation.

Uses redis-py with async support. Falls back gracefully when Redis
is unavailable (logs warning, returns safe defaults).
"""
from __future__ import annotations

import os
import logging
import asyncio
from datetime import datetime
from typing import Optional

import redis.asyncio as aioredis
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
# Pool must cover full pipeline concurrency — each in-flight alert makes
# several Redis calls (dedup/burst/malicious-IP), so it needs to be at
# least as large as PIPELINE_MAX_CONCURRENT_ALERTS, not a small fixed cap.
PIPELINE_MAX_CONCURRENT_ALERTS = int(os.getenv("PIPELINE_MAX_CONCURRENT_ALERTS", "512"))
DEDUP_TTL_SECONDS = 86_400
BURST_WINDOW_SECONDS = 60
BURST_THRESHOLD = 3
MALICIOUS_IP_TTL = 3_600


class RedisClient:
    """Async Redis client with dedup, burst, and KV helpers."""

    def __init__(self, url: str = REDIS_URL):
        self._url = url
        self._client: Optional[aioredis.Redis] = None
        self._client_lock = asyncio.Lock()

    async def _get(self) -> aioredis.Redis:
        if self._client is None:
            async with self._client_lock:
                # Re-check: another coroutine may have created it while we
                # were waiting on the lock (was previously unguarded, which
                # let concurrent first-callers each spin up their own pool
                # under load and exhaust Redis's connection limit).
                if self._client is None:
                    self._client = await aioredis.from_url(
                        self._url, encoding="utf-8", decode_responses=True,
                        max_connections=PIPELINE_MAX_CONCURRENT_ALERTS,
                    )
        return self._client


    async def check_dedup(self, alert_id: str) -> bool:
        """
        Returns True if alert_id was already processed.
        Sets key with DEDUP_TTL_SECONDS if new.
        """
        try:
            client = await self._get()
            key = f"dedup:{alert_id}"
            result = await client.set(key, "1", nx=True, ex=DEDUP_TTL_SECONDS)

            return result is None
        except Exception as exc:
            log.warning("Redis dedup check failed: %s — treating as new", exc)
            return False


    async def check_burst(
        self,
        rule_id: int,
        alert_id: str,
        window_seconds: int = BURST_WINDOW_SECONDS,
    ) -> list[str]:
        """
        Adds alert_id to the sliding window for rule_id.
        Returns list of correlated alert_ids in the window.
        """
        try:
            client = await self._get()
            key = f"burst:{rule_id}"
            now_ts = datetime.utcnow().timestamp()

            pipe = client.pipeline()
            pipe.zadd(key, {alert_id: now_ts})
            pipe.zremrangebyscore(key, 0, now_ts - window_seconds)
            pipe.zrange(key, 0, -1)
            pipe.expire(key, window_seconds * 2)
            results = await pipe.execute()

            all_ids = results[2]
            correlated = [aid for aid in all_ids if aid != alert_id]
            return correlated
        except Exception as exc:
            log.warning("Redis burst check failed: %s", exc)
            return []


    async def is_known_malicious(self, ip: str) -> bool:
        """Check if an IP is cached as malicious from a prior TI lookup."""
        if not ip:
            return False
        try:
            client = await self._get()
            return await client.exists(f"malicious_ip:{ip}") > 0
        except Exception as exc:
            log.warning("Redis malicious-IP check failed: %s", exc)
            return False

    async def mark_malicious(self, ip: str, ttl: int = MALICIOUS_IP_TTL) -> None:
        """Cache an IP as malicious for ttl seconds."""
        try:
            client = await self._get()
            await client.set(f"malicious_ip:{ip}", "1", ex=ttl)
        except Exception as exc:
            log.warning("Redis mark_malicious failed: %s", exc)


    async def get(self, key: str) -> Optional[str]:
        try:
            client = await self._get()
            return await client.get(key)
        except Exception:
            return None

    async def set(self, key: str, value: str, ex: int = 3600) -> None:
        try:
            client = await self._get()
            await client.set(key, value, ex=ex)
        except Exception as exc:
            log.warning("Redis set failed: %s", exc)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()


redis_client = RedisClient()
