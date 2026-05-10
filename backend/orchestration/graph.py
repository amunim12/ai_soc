# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
LangGraph DAG — orchestration/graph.py

Assembles the StateGraph using SupervisorAgent routing and
the four sub-agent run() methods as graph nodes.

Usage:
  python -m orchestration.graph                  # runs the Kafka consumer loop
  from orchestration.graph import compiled_graph  # import in tests
"""
from __future__ import annotations

import asyncio
import logging
import os

from langgraph.graph import StateGraph, START, END

from orchestration.state import PipelineState, initial_state
from schemas.alert import WazuhAlert
from agents.supervisor import supervisor_agent
from agents.log_analysis_agent import log_analysis_agent
from agents.threat_intel_agent import threat_intel_agent
from agents.playbook_gen_agent import playbook_gen_agent
from agents.hitl_agent import hitl_agent
from agents.soar_agent import soar_agent
from infrastructure.kafka_client import KafkaConsumerClient, kafka_producer
from infrastructure.sqlite_client import sqlite_client

log = logging.getLogger(__name__)


def build_graph() -> StateGraph:
    """Construct and return the compiled LangGraph StateGraph."""
    graph = StateGraph(PipelineState)


    async def _run_analyse(s):       return await log_analysis_agent.run(s)
    async def _run_enrich(s):        return await threat_intel_agent.run(s)
    async def _run_playbook(s):      return await playbook_gen_agent.run(s)
    async def _run_hitl(s):          return await hitl_agent.run(s)
    async def _run_execute(s):       return await supervisor_agent.publish_to_soar(s)
    async def _run_soar(s):          return await soar_agent.run(s)
    async def _run_drop(s):          return await supervisor_agent.drop_and_log(s)
    async def _run_escalate(s):      return await supervisor_agent.escalate_to_senior(s)

    graph.add_node("analyse",           _run_analyse)
    graph.add_node("enrich",            _run_enrich)
    graph.add_node("generate_playbook", _run_playbook)
    graph.add_node("hitl",              _run_hitl)
    graph.add_node("execute",           _run_execute)
    graph.add_node("soar",              _run_soar)
    graph.add_node("drop",              _run_drop)
    graph.add_node("escalate",          _run_escalate)


    graph.add_edge(START, "analyse")

    graph.add_conditional_edges(
        "analyse",
        supervisor_agent.route_after_analysis,
        {
            "enrich":           "enrich",
            "skip_to_playbook": "generate_playbook",
            "drop":             "drop",
        },
    )

    graph.add_conditional_edges(
        "enrich",
        supervisor_agent.route_after_enrichment,
        {"generate_playbook": "generate_playbook"},
    )

    graph.add_conditional_edges(
        "generate_playbook",
        supervisor_agent.route_after_playbook,
        {
            "hitl":    "hitl",
            "execute": "execute",
        },
    )

    graph.add_conditional_edges(
        "hitl",
        supervisor_agent.route_after_hitl,
        {
            "execute":          "execute",
            "generate_playbook": "generate_playbook",
            "drop":             "drop",
            "escalate":         "escalate",
            "park":             END,
        },
    )

    graph.add_edge("execute",  "soar")
    graph.add_edge("soar",     END)
    graph.add_edge("drop",     END)
    graph.add_edge("escalate", END)

    return graph


compiled_graph = build_graph().compile()


async def process_alert(alert: WazuhAlert) -> PipelineState:
    """Run a single alert through the full pipeline."""
    state = initial_state(alert)
    log.info("[Pipeline] Starting alert %s (%s)", alert.id, alert.severity)

    final_state = await compiled_graph.ainvoke(state)

    log.info(
        "[Pipeline] Finished alert %s → stage=%s",
        alert.id, final_state.get("pipeline_stage", "unknown"),
    )
    return final_state


from config.settings import settings as _settings

MAX_CONCURRENT_ALERTS  = _settings.PIPELINE_MAX_CONCURRENT_ALERTS
NUM_CONSUMER_WORKERS   = _settings.KAFKA_NUM_CONSUMER_WORKERS


async def _consumer_worker(worker_id: int, semaphore: asyncio.Semaphore) -> None:
    """
    Single Kafka consumer in the shared group.  Kafka assigns a subset of
    wazuh.raw partitions to each worker (48 partitions / 16 workers = 3 each).
    The semaphore is shared across all workers for global concurrency control.
    """
    consumer = KafkaConsumerClient(
        topics=["wazuh.raw"],
        group_id="ai_soc_pipeline_supervisor",
    )
    inflight: set[asyncio.Task] = set()
    log.info("[Pipeline] Consumer worker %d started", worker_id)

    async def _handle(raw_msg: dict) -> None:
        async with semaphore:
            try:
                alert = WazuhAlert.model_validate(raw_msg)
                await process_alert(alert)
            except Exception as exc:
                log.error(
                    "[Pipeline] Worker %d failed: %s — %s", worker_id, raw_msg, exc
                )

    try:
        async for msg in consumer:
            task = asyncio.create_task(_handle(msg))
            inflight.add(task)
            task.add_done_callback(inflight.discard)
    finally:
        if inflight:
            await asyncio.gather(*inflight, return_exceptions=True)
        consumer.close()


async def run_kafka_consumer_loop() -> None:
    """
    Spawns NUM_CONSUMER_WORKERS consumers in the same group so Kafka
    distributes the 24 wazuh.raw partitions across them (3 each at 8 workers).
    All workers share one semaphore capped at MAX_CONCURRENT_ALERTS in-flight.
    """
    await sqlite_client.initialise()
    log.info(
        "[Pipeline] Starting %d consumer workers → topic=wazuh.raw concurrency=%d",
        NUM_CONSUMER_WORKERS, MAX_CONCURRENT_ALERTS,
    )
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_ALERTS)
    try:
        await asyncio.gather(
            *[_consumer_worker(i, semaphore) for i in range(NUM_CONSUMER_WORKERS)]
        )
    finally:
        kafka_producer.flush()


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    await run_kafka_consumer_loop()


if __name__ == "__main__":
    asyncio.run(main())
