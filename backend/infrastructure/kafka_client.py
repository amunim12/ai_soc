# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Kafka client — async producer / consumer wrappers.

Uses confluent-kafka-python with a JSON serialiser.
Module-level singleton `kafka_producer` is imported by all agents.

If confluent_kafka is not installed (e.g. in unit test environments without
the C extension), falls back to a no-op MockKafkaProducer so that all agents
can be imported and tested without a running Kafka broker.
"""
from __future__ import annotations

import json
import os
import logging
from typing import Any, AsyncIterator, Optional

from dotenv import load_dotenv
from pydantic import BaseModel

try:
    from confluent_kafka import Producer, Consumer, KafkaException, KafkaError
    from confluent_kafka.admin import AdminClient, NewTopic
    _CONFLUENT_AVAILABLE = True
except ImportError:
    _CONFLUENT_AVAILABLE = False

load_dotenv()
log = logging.getLogger(__name__)

BOOTSTRAP_SERVERS   = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
GROUP_ID            = os.getenv("KAFKA_GROUP_ID",           "ai_soc_pipeline")
LINGER_MS           = int(os.getenv("KAFKA_LINGER_MS",             "50"))
BATCH_SIZE_BYTES    = int(os.getenv("KAFKA_BATCH_SIZE_BYTES",  "524288"))
COMPRESSION_TYPE    = os.getenv("KAFKA_COMPRESSION_TYPE",         "lz4")
ACKS                = os.getenv("KAFKA_ACKS",                       "1")

CONSUMER_FETCH_MIN_BYTES     = int(os.getenv("KAFKA_FETCH_MIN_BYTES",      "65536"))
CONSUMER_FETCH_WAIT_MAX_MS   = int(os.getenv("KAFKA_FETCH_WAIT_MAX_MS",      "200"))
CONSUMER_QUEUED_MAX_KBYTES   = int(os.getenv("KAFKA_QUEUED_MAX_KBYTES",  "1048576"))
CONSUMER_MAX_PART_FETCH_KB   = int(os.getenv("KAFKA_MAX_PART_FETCH_KB",    "1024"))


def _to_json(obj: Any) -> bytes:
    """Serialise to JSON bytes, handling Pydantic models."""
    if isinstance(obj, BaseModel):
        return obj.model_dump_json().encode()
    return json.dumps(obj, default=str).encode()


class MockKafkaProducer:
    """
    Drop-in replacement for KafkaProducerClient when confluent_kafka
    is not available. Logs messages instead of sending to Kafka.
    """

    async def send(self, topic: str, payload: Any, key: Optional[str] = None) -> None:
        value_preview = str(_to_json(payload))[:120]
        log.debug("[MockKafka] → %s key=%s value=%s...", topic, key, value_preview)

    def flush(self, timeout: float = 5.0) -> None:
        pass

    def close(self) -> None:
        pass


class MockKafkaConsumer:
    """No-op consumer for tests."""

    def __init__(self, *args, **kwargs):
        pass

    async def __aiter__(self) -> AsyncIterator[dict[str, Any]]:
        return
        yield

    def close(self) -> None:
        pass


class KafkaProducerClient:
    """
    Sync confluent-kafka Producer wrapped for async-friendly use.
    Only instantiated when confluent_kafka is available.
    """

    def __init__(self, bootstrap_servers: str = BOOTSTRAP_SERVERS):
        self._producer = Producer({     # type: ignore[name-defined]
            "bootstrap.servers":  bootstrap_servers,
            "acks":               ACKS,
            "retries":            5,
            "retry.backoff.ms":   500,

            "linger.ms":          LINGER_MS,
            "batch.size":         BATCH_SIZE_BYTES,
            "compression.type":   COMPRESSION_TYPE,

            "queue.buffering.max.messages": 500000,
            "queue.buffering.max.kbytes":  1048576,
        })
        log.info("KafkaProducerClient initialised → %s", bootstrap_servers)

    async def send(self, topic: str, payload: Any, key: Optional[str] = None) -> None:
        """Produce a message to Kafka (fire-and-forget with delivery callback)."""
        value = _to_json(payload)
        key_bytes = key.encode() if key else None

        def _delivery(err, msg):
            if err:
                log.error("Delivery failed [%s]: %s", topic, err)
            else:
                log.debug("Delivered → %s [%d]", msg.topic(), msg.partition())

        self._producer.produce(
            topic, value=value, key=key_bytes, on_delivery=_delivery
        )
        self._producer.poll(0)

    def flush(self, timeout: float = 5.0) -> None:
        self._producer.flush(timeout)

    def close(self) -> None:
        self.flush()


class KafkaConsumerClient:
    """Async-iterable consumer wrapping confluent-kafka Consumer."""

    def __init__(
        self,
        topics: list[str],
        group_id: str = GROUP_ID,
        bootstrap_servers: str = BOOTSTRAP_SERVERS,
        auto_commit: bool = True,
    ):
        self._consumer = Consumer({     # type: ignore[name-defined]
            "bootstrap.servers": bootstrap_servers,
            "group.id": group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": str(auto_commit).lower(),

            "max.poll.interval.ms": 1800000,
            "session.timeout.ms":     60000,

            "fetch.min.bytes":            CONSUMER_FETCH_MIN_BYTES,
            "fetch.wait.max.ms":          CONSUMER_FETCH_WAIT_MAX_MS,
            "queued.max.messages.kbytes": CONSUMER_QUEUED_MAX_KBYTES,
            "max.partition.fetch.bytes":  CONSUMER_MAX_PART_FETCH_KB * 1024,
        })
        self._consumer.subscribe(topics)
        log.info("KafkaConsumerClient subscribed → %s", topics)

    async def __aiter__(self) -> AsyncIterator[dict[str, Any]]:
        import asyncio
        while True:
            msg = await asyncio.to_thread(self._consumer.poll, 0.25)
            if msg is None:
                await asyncio.sleep(0)
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:    # type: ignore[union-attr]
                    continue
                raise KafkaException(msg.error())                        # type: ignore[name-defined]
            try:
                yield json.loads(msg.value().decode())
            except json.JSONDecodeError as exc:
                log.warning("Failed to decode Kafka message: %s", exc)

    def close(self) -> None:
        self._consumer.close()


def create_topics_if_missing(topics: list[tuple[str, int, int]]) -> None:
    """Creates topics that don't already exist. Used in dev."""
    if not _CONFLUENT_AVAILABLE:
        log.warning("confluent_kafka not available — skipping topic creation")
        return
    admin = AdminClient({"bootstrap.servers": BOOTSTRAP_SERVERS})    # type: ignore[name-defined]
    new_topics = [NewTopic(t, num_partitions=p, replication_factor=r)   # type: ignore[name-defined]
                  for t, p, r in topics]
    fs = admin.create_topics(new_topics)
    for topic, f in fs.items():
        try:
            f.result()
            log.info("Topic created: %s", topic)
        except Exception as exc:
            if "already exists" in str(exc).lower():
                log.debug("Topic already exists: %s", topic)
            else:
                log.error("Failed to create topic %s: %s", topic, exc)


if _CONFLUENT_AVAILABLE:
    kafka_producer: Any = KafkaProducerClient()
else:
    log.warning("confluent_kafka unavailable — kafka_producer is a no-op MockKafkaProducer")
    kafka_producer: Any = MockKafkaProducer()
