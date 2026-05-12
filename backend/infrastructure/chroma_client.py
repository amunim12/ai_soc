# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
ChromaDB client — persistent vector store wrapper.

Collections:
  mitre_attack    — MITRE ATT&CK technique descriptions
  nvd_cves        — NVD CVE summaries
  wazuh_rules     — Wazuh rule descriptions
  past_incidents  — Historical SOC incident summaries
  nist_csf        — NIST CSF 2.0 control descriptions

BUG FIX: Added try/except import guards for chromadb and
sentence_transformers so that the module can be safely imported
in test environments where these heavy packages are not installed.
A MockChromaClient is used as fallback (returns empty docs).
"""
from __future__ import annotations

import os
import logging
from typing import Optional

from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))

COLLECTION_NAMES = [
    "mitre_attack",
    "nvd_cves",
    "wazuh_rules",
    "past_incidents",
    "nist_csf",
]


try:
    import chromadb
    from chromadb import Collection
    _CHROMA_AVAILABLE = True
except Exception:
    chromadb = None  # type: ignore[assignment]
    Collection = None  # type: ignore[assignment,misc]
    _CHROMA_AVAILABLE = False
    log.warning("chromadb unavailable — ChromaClient will use mock (no RAG context)")


import hashlib
import re
import numpy as np

_EMBED_DIM = 384
_EMBEDDING_CACHE: dict[str, list[float]] = {}
_EMBEDDING_CACHE_MAX = 10_000


def _hash_embed(text: str) -> list[float]:
    """
    Simple hash-based embedding: tokenise, hash each token into a bucket,
    accumulate counts, L2-normalise.  No DLL required.
    Results are cached in-process — same query text always yields the same
    vector, so repeated RAG queries for the same category/MITRE skip the
    computation entirely.
    """
    cached = _EMBEDDING_CACHE.get(text)
    if cached is not None:
        return cached
    tokens = re.findall(r"[a-zA-Z0-9]+", text.lower())
    vec = np.zeros(_EMBED_DIM, dtype=np.float32)
    for tok in tokens:
        idx = int(hashlib.md5(tok.encode()).hexdigest(), 16) % _EMBED_DIM
        vec[idx] += 1.0
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    result = vec.tolist()
    if len(_EMBEDDING_CACHE) < _EMBEDDING_CACHE_MAX:
        _EMBEDDING_CACHE[text] = result
    return result


_ST_AVAILABLE = True


class MockChromaClient:
    """No-op fallback used when chromadb/sentence-transformers are not installed."""

    def get_or_create_collection(self, name: str) -> None:  # type: ignore[return]
        return None

    def embed(self, text: str) -> list[float]:
        return [0.0] * 384

    def query_collection(
        self, collection_name: str, query_text: str, n_results: int = 3
    ) -> list[str]:
        return []

    def upsert_documents(
        self,
        collection_name: str,
        ids: list[str],
        documents: list[str],
        metadatas: Optional[list[dict]] = None,
    ) -> None:
        log.warning("MockChromaClient.upsert_documents called — no-op")

    def collection_count(self, collection_name: str) -> int:
        return 0


class ChromaClient:
    """
    Thin wrapper around chromadb.HttpClient.
    Provides query_collection() helper used by PlaybookGenAgent.
    """

    def __init__(
        self,
        host: str = CHROMA_HOST,
        port: int = CHROMA_PORT,
    ):
        self._host = host
        self._port = port
        self._client: Optional[object] = None
        log.info("ChromaClient configured → %s:%s (server-side embeddings)", host, port)

    def _get_client(self):
        if not _CHROMA_AVAILABLE:
            raise RuntimeError("chromadb not installed")
        if self._client is None:
            self._client = chromadb.HttpClient(host=self._host, port=self._port)
        return self._client

    def get_or_create_collection(self, name: str):
        client = self._get_client()


        return client.get_or_create_collection(
            name=name,
            embedding_function=None,  # type: ignore[arg-type]
            metadata={"hnsw:space": "cosine"},
        )

    def query_collection(
        self,
        collection_name: str,
        query_text: str,
        n_results: int = 3,
    ) -> list[str]:
        """
        Query a ChromaDB collection using pre-computed hash embeddings.
        Returns list of document strings.
        """
        try:
            client = self._get_client()
            coll = client.get_collection(
                collection_name,
                embedding_function=None,  # type: ignore[arg-type]
            )
            result = coll.query(
                query_embeddings=[_hash_embed(query_text)],
                n_results=n_results,
                include=["documents", "metadatas"],
            )
            docs = result.get("documents", [[]])[0]
            return docs
        except Exception as exc:
            log.warning("ChromaDB query failed [%s]: %s", collection_name, exc)
            return []

    def upsert_documents(
        self,
        collection_name: str,
        ids: list[str],
        documents: list[str],
        metadatas: Optional[list[dict]] = None,
    ) -> None:
        """Upsert documents with pre-computed hash embeddings (no DLL required)."""
        coll = self.get_or_create_collection(collection_name)
        embeddings = [_hash_embed(doc) for doc in documents]
        coll.upsert(
            ids=ids,
            documents=documents,
            embeddings=embeddings,
            metadatas=metadatas or [{} for _ in documents],
        )
        log.info("Upserted %d docs → collection '%s'", len(documents), collection_name)

    def collection_count(self, collection_name: str) -> int:
        try:
            client = self._get_client()
            coll = client.get_collection(collection_name)
            return coll.count()
        except Exception:
            return 0


if _CHROMA_AVAILABLE and _ST_AVAILABLE:
    chroma_client: ChromaClient | MockChromaClient = ChromaClient()
else:
    log.warning("chroma_client is a no-op MockChromaClient")
    chroma_client = MockChromaClient()
