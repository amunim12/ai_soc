# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0
import pytest
from config.settings import Settings


def test_perf_settings_have_correct_defaults(monkeypatch):
    for var in (
        "PIPELINE_MAX_CONCURRENT_ALERTS", "KAFKA_NUM_CONSUMER_WORKERS",
        "LLM_MAX_CONCURRENT_CALLS", "LLM_CALL_TIMEOUT_SECONDS",
        "PLAYBOOK_CACHE_TTL_SECONDS", "RAG_CTX_CACHE_TTL_SECONDS",
        "WAZUH_POLL_INTERVAL", "WAZUH_BATCH_SIZE", "SOAR_ENABLED",
    ):
        monkeypatch.delenv(var, raising=False)
    s = Settings(
        SHUFFLE_API_KEY="test-key",
        LOCAL_LLM_BASE_URL="http://localhost:8001/v1",
    )
    assert s.PIPELINE_MAX_CONCURRENT_ALERTS == 512
    assert s.KAFKA_NUM_CONSUMER_WORKERS == 16
    assert s.LLM_MAX_CONCURRENT_CALLS == 16
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


def test_graph_reads_concurrency_from_settings(monkeypatch):
    """graph.py module-level constants must honour settings values."""
    monkeypatch.setenv("PIPELINE_MAX_CONCURRENT_ALERTS", "999")
    monkeypatch.setenv("KAFKA_NUM_CONSUMER_WORKERS", "7")

    import importlib
    import config.settings as settings_mod
    importlib.reload(settings_mod)
    import orchestration.graph as graph_module
    importlib.reload(graph_module)

    assert graph_module.MAX_CONCURRENT_ALERTS == 999
    assert graph_module.NUM_CONSUMER_WORKERS == 7


def test_llm_client_reads_concurrency_from_settings(monkeypatch):
    """LLM module-level constants must honour settings values."""
    monkeypatch.setenv("LLM_MAX_CONCURRENT_CALLS", "7")
    monkeypatch.setenv("LLM_CALL_TIMEOUT_SECONDS", "5.0")

    import importlib
    import config.settings as settings_mod
    importlib.reload(settings_mod)
    import infrastructure.llm_client as llm_module
    importlib.reload(llm_module)

    assert llm_module.LLM_MAX_CONCURRENT_CALLS == 7
    assert llm_module.LLM_CALL_TIMEOUT_SECONDS == 5.0


def test_bridge_reads_poll_settings_from_settings(monkeypatch):
    monkeypatch.setenv("WAZUH_POLL_INTERVAL", "2")
    monkeypatch.setenv("WAZUH_BATCH_SIZE", "500")

    import importlib
    import config.settings as settings_mod
    importlib.reload(settings_mod)
    import bridge.wazuh_kafka_bridge as bridge_module
    importlib.reload(bridge_module)

    assert bridge_module.POLL_INTERVAL_SECONDS == 2
    assert bridge_module.BATCH_SIZE == 500
