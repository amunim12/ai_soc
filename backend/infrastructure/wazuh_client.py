# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0
"""
Shared Wazuh REST API client — infrastructure/wazuh_client.py

Provides:
  wazuh_ssl()   — returns the correct httpx `verify` value based on settings.
  wazuh_token() — returns a cached, auto-refreshing JWT or None.
  wazuh_get()   — authenticated GET helper; returns parsed JSON or None.

Both siem_api and log_source_api should import from here so Wazuh auth
and TLS handling live in exactly one place.
"""
from __future__ import annotations

import logging
import time
from typing import Optional, Union

import httpx

from config.settings import settings

log = logging.getLogger(__name__)

# ── Token cache ──────────────────────────────────────────────────────────────

_token: Optional[str] = None
_token_expires: float = 0.0


def wazuh_ssl() -> Union[bool, str]:
    """
    Return the value to pass as httpx's ``verify`` keyword.

    Priority:
      1. WAZUH_CA_CERT path — validates against the supplied CA bundle.
      2. WAZUH_TLS_VERIFY=True (default) — validates against the system CA store.
      3. WAZUH_TLS_VERIFY=False — disables verification; logs a warning every call.

    The recommended production setup is to set WAZUH_CA_CERT to the path of
    the Wazuh Manager root CA (exported from /var/ossec/etc/sslmanager.cert).
    """
    if settings.WAZUH_CA_CERT:
        return settings.WAZUH_CA_CERT
    if settings.WAZUH_TLS_VERIFY:
        return True
    log.warning(
        "[Wazuh] TLS verification is DISABLED (WAZUH_TLS_VERIFY=false). "
        "Set WAZUH_CA_CERT to the manager CA certificate path instead."
    )
    return False


async def wazuh_token() -> Optional[str]:
    """Return a valid Wazuh JWT, re-authenticating when expired."""
    global _token, _token_expires

    if _token and time.time() < _token_expires:
        return _token

    if not settings.WAZUH_PASSWORD:
        return None

    try:
        async with httpx.AsyncClient(verify=wazuh_ssl(), timeout=5.0) as client:
            r = await client.post(
                f"{settings.WAZUH_API_URL}/security/user/authenticate",
                auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD),
            )
            r.raise_for_status()
            _token = r.json()["data"]["token"]
            _token_expires = time.time() + 840
            log.info("[Wazuh] Token refreshed")
            return _token
    except Exception as exc:
        log.warning("[Wazuh] Authentication failed: %s", exc)
        _token = None
        return None


async def wazuh_get(path: str, params: dict | None = None) -> Optional[dict]:
    """Authenticated GET against the Wazuh Manager REST API. Returns JSON or None."""
    token = await wazuh_token()
    if not token:
        return None
    try:
        async with httpx.AsyncClient(verify=wazuh_ssl(), timeout=8.0) as client:
            r = await client.get(
                f"{settings.WAZUH_API_URL}{path}",
                headers={"Authorization": f"Bearer {token}"},
                params=params or {},
            )
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("[Wazuh] GET %s failed: %s", path, exc)
        return None


async def wazuh_post(path: str, body: dict | None = None) -> Optional[httpx.Response]:
    """Authenticated POST against the Wazuh Manager REST API. Returns the Response or None."""
    token = await wazuh_token()
    if not token:
        return None
    try:
        async with httpx.AsyncClient(verify=wazuh_ssl(), timeout=8.0) as client:
            r = await client.post(
                f"{settings.WAZUH_API_URL}{path}",
                headers={"Authorization": f"Bearer {token}"},
                json=body or {},
            )
            return r
    except Exception as exc:
        log.warning("[Wazuh] POST %s failed: %s", path, exc)
        return None
