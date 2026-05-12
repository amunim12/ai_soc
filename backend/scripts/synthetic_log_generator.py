# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Synthetic Log Generator — scripts/synthetic_log_generator.py

Publishes randomized variants of the 20 MOCK_ALERTS directly to the
`wazuh.raw` Kafka topic at a configurable events-per-second (EPS) rate.

Use this to demo or stress-test the pipeline without running Wazuh.

USAGE
-----
  # Realistic demo — 10 alerts/sec for 60 seconds
  python -m scripts.synthetic_log_generator --eps 10 --duration 60

  # Ingestion stress test — 2000 alerts/sec, 30 seconds
  python -m scripts.synthetic_log_generator --eps 2000 --duration 30

  # Infinite burst until Ctrl+C
  python -m scripts.synthetic_log_generator --eps 50

NOTES
-----
- At EPS > ~20, the downstream pipeline (LLM + TI) will NOT keep up.
  Kafka consumer lag will grow — this is expected and demonstrates
  back-pressure handling. Watch consumer lag in the logs.
- Each generated alert is a randomized variant of MOCK_ALERTS: new
  agent id, new timestamp, jittered source IP. This keeps dedup from
  collapsing the stream into a single alert.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import random
import signal
import time
import uuid
from datetime import datetime, timezone

from bridge.mock_alert_generator import MOCK_ALERTS
from infrastructure.kafka_client import kafka_producer
from schemas.alert import WazuhAlert

log = logging.getLogger("synthetic_gen")

TOPIC = "wazuh.raw"
AGENT_POOL = [f"agent-{i:03d}" for i in range(1, 51)]
HOST_POOL = [f"host-{i:02d}.example.local" for i in range(1, 51)]


def _jitter_ip(ip: str | None) -> str | None:
    """Mutate the last octet of an IPv4 so each alert looks distinct."""
    if not ip or ip.count(".") != 3:
        return ip
    parts = ip.split(".")
    parts[3] = str(random.randint(1, 254))
    return ".".join(parts)


def _random_variant(template: WazuhAlert) -> WazuhAlert:
    """Return a new WazuhAlert derived from a template with fresh ids/timestamps."""
    idx = random.randint(0, len(AGENT_POOL) - 1)
    return template.model_copy(
        update={
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "agent_id": AGENT_POOL[idx],
            "agent_name": HOST_POOL[idx],
            "source_ip": _jitter_ip(template.source_ip),
            "destination_ip": _jitter_ip(template.destination_ip),
        }
    )


def _produce_batch(alerts: list[WazuhAlert]) -> None:
    """Synchronously produce a batch of alerts — runs in a thread."""
    producer = kafka_producer._producer  # direct access for zero-overhead batching
    for alert in alerts:
        producer.produce(
            TOPIC,
            value=alert.model_dump_json().encode(),
            key=alert.agent_id.encode() if alert.agent_id else None,
        )
    producer.poll(0)


async def generate(eps: float, duration: float | None) -> None:
    batch_size = max(1, min(int(eps / 10), 1000))  # ~10 batches/sec, cap 1000
    batch_interval = batch_size / eps if eps > 0 else 0

    sent = 0
    start = time.perf_counter()
    last_report = start
    stop_at = start + duration if duration else None
    next_tick = start

    log.info(
        "Generating synthetic alerts → %s  eps=%s  duration=%ss  batch=%d",
        TOPIC, eps, duration or "∞", batch_size,
    )

    try:
        while True:
            now = time.perf_counter()
            if stop_at and now >= stop_at:
                break

            remaining = int((stop_at - now) * eps) if stop_at else batch_size
            this_batch = min(batch_size, remaining) if stop_at else batch_size
            if this_batch <= 0:
                break

            batch = [_random_variant(random.choice(MOCK_ALERTS)) for _ in range(this_batch)]
            await asyncio.to_thread(_produce_batch, batch)
            sent += this_batch

            if now - last_report >= 2.0:
                elapsed = now - start
                actual_eps = sent / elapsed if elapsed > 0 else 0
                log.info("sent=%d elapsed=%.1fs actual_eps=%.1f", sent, elapsed, actual_eps)
                last_report = now

            next_tick += batch_interval
            delay = next_tick - time.perf_counter()
            if delay > 0:
                await asyncio.sleep(delay)
            else:
                next_tick = time.perf_counter()
    finally:
        elapsed = time.perf_counter() - start
        actual_eps = sent / elapsed if elapsed > 0 else 0
        log.info("DONE sent=%d elapsed=%.1fs actual_eps=%.1f", sent, elapsed, actual_eps)
        kafka_producer.flush(timeout=10)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Inject synthetic Wazuh alerts into Kafka.")
    p.add_argument("--eps", type=float, default=10.0, help="Events per second (default: 10)")
    p.add_argument("--duration", type=float, default=None, help="Seconds to run (default: infinite)")
    p.add_argument("--log-level", default="INFO")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    task = loop.create_task(generate(args.eps, args.duration))

    def _cancel(*_):
        log.info("Interrupt received — stopping generator")
        task.cancel()

    try:
        signal.signal(signal.SIGINT, _cancel)
        signal.signal(signal.SIGTERM, _cancel)
    except ValueError:
        pass

    try:
        loop.run_until_complete(task)
    except asyncio.CancelledError:
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    main()
