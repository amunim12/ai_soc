# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0
import pytest
from config.settings import Settings


def test_perf_settings_have_correct_defaults():
    s = Settings(
        SHUFFLE_API_KEY="test-key",
        LOCAL_LLM_BASE_URL="http://localhost:8001/v1",
    )
    assert s.PIPELINE_MAX_CONCURRENT_ALERTS == 512
    assert s.KAFKA_NUM_CONSUMER_WORKERS == 16
    assert s.LLM_MAX_CONCURRENT_CALLS == 64
    assert s.LLM_CALL_TIMEOUT_SECONDS == 30.0
    assert s.PLAYBOOK_CACHE_TTL_SECONDS == 3600
    assert s.RAG_CTX_CACHE_TTL_SECONDS == 3600
    assert s.WAZUH_POLL_INTERVAL == 1
    assert s.WAZUH_BATCH_SIZE == 1200
    assert s.SOAR_ENABLED is True


def test_perf_settings_are_overridable(monkeypatch):
    monkeypatch.setenv("PIPELINE_MAX_CONCURRENT_ALERTS", "128")
    monkeypatch.setenv("KAFKA_NUM_CONSUMER_WORKERS", "4")
    monkeypatch.setenv("LLM_MAX_CONCURRENT_CALLS", "8")
    monkeypatch.setenv("LLM_CALL_TIMEOUT_SECONDS", "5.0")
    monkeypatch.setenv("PLAYBOOK_CACHE_TTL_SECONDS", "60")
    monkeypatch.setenv("RAG_CTX_CACHE_TTL_SECONDS", "120")
    monkeypatch.setenv("WAZUH_POLL_INTERVAL", "10")
    monkeypatch.setenv("WAZUH_BATCH_SIZE", "50")
    monkeypatch.setenv("SOAR_ENABLED", "false")

    from importlib import reload
    import config.settings as settings_module
    reload(settings_module)

    s = settings_module.Settings(
        SHUFFLE_API_KEY="test-key",
        LOCAL_LLM_BASE_URL="http://localhost:8001/v1",
    )
    assert s.PIPELINE_MAX_CONCURRENT_ALERTS == 128
    assert s.KAFKA_NUM_CONSUMER_WORKERS == 4
    assert s.LLM_MAX_CONCURRENT_CALLS == 8
    assert s.LLM_CALL_TIMEOUT_SECONDS == 5.0
    assert s.PLAYBOOK_CACHE_TTL_SECONDS == 60
    assert s.RAG_CTX_CACHE_TTL_SECONDS == 120
    assert s.WAZUH_POLL_INTERVAL == 10
    assert s.WAZUH_BATCH_SIZE == 50
    assert s.SOAR_ENABLED is False
