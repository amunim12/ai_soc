# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
RAG Ingestion API — api/rag_api.py

POST /api/rag/upload   — upload PDF or DOCX into a ChromaDB collection
GET  /api/rag/collections — list collections and document counts

All embeddings use local sentence-transformers (air-gapped).
Max upload size: configured via RAG_UPLOAD_MAX_MB (default 50 MB).
"""
from __future__ import annotations

import hashlib
import io
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from api.auth_api import get_current_user, require_admin
from config.settings import settings
from infrastructure.chroma_client import chroma_client

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/rag", tags=["rag"])

MAX_BYTES = settings.RAG_UPLOAD_MAX_MB * 1024 * 1024

ALLOWED_COLLECTIONS = [
    "mitre_attack",
    "nvd_cves",
    "wazuh_rules",
    "past_incidents",
    "nist_csf",
    "custom_intel",
]


def _extract_pdf(data: bytes) -> str:
    """Extract plain text from a PDF using PyMuPDF."""
    try:
        import fitz
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="PyMuPDF not installed. Run: pip install pymupdf",
        )
    doc = fitz.open(stream=data, filetype="pdf")
    return "\n".join(page.get_text() for page in doc)


def _extract_docx(data: bytes) -> str:
    """Extract plain text from a DOCX using python-docx."""
    try:
        import docx as _docx
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="python-docx not installed. Run: pip install python-docx",
        )
    doc = _docx.Document(io.BytesIO(data))
    return "\n".join(p.text for p in doc.paragraphs if p.text.strip())


def _chunk_text(text: str, chunk_size: int, overlap: int) -> list[str]:
    """Split text into overlapping word-count chunks."""
    words = text.split()
    chunks: list[str] = []
    i = 0
    while i < len(words):
        chunk = " ".join(words[i: i + chunk_size])
        if chunk.strip():
            chunks.append(chunk)
        i += chunk_size - overlap
    return chunks


@router.post("/upload", status_code=status.HTTP_202_ACCEPTED)
async def upload_document(
    file:       UploadFile = File(...),
    collection: str        = Form("custom_intel"),
    source:     Optional[str] = Form(None),
    _user:      dict       = Depends(require_admin),
) -> dict:
    """
    Upload a PDF or DOCX threat intelligence document into ChromaDB.

    - Extracts text using PyMuPDF / python-docx (local, no external calls)
    - Chunks into overlapping segments
    - Embeds via local sentence-transformers through ChromaDB
    - Stores with metadata: source, filename, chunk_index, sha256

    Returns: { ingested_chunks, collection, filename, sha256 }
    """
    if collection not in ALLOWED_COLLECTIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid collection. Choose from: {ALLOWED_COLLECTIONS}",
        )

    filename = file.filename or "unknown"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ("pdf", "docx"):
        raise HTTPException(status_code=422, detail="Only PDF and DOCX files are supported")


    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {settings.RAG_UPLOAD_MAX_MB} MB limit",
        )

    sha256 = hashlib.sha256(data).hexdigest()
    log.info("[RAG] Ingesting %s → collection=%s sha256=%s…", filename, collection, sha256[:12])


    if ext == "pdf":
        text = _extract_pdf(data)
    else:
        text = _extract_docx(data)

    if not text.strip():
        raise HTTPException(status_code=422, detail="No extractable text found in document")


    chunks = _chunk_text(text, settings.RAG_CHUNK_SIZE, settings.RAG_CHUNK_OVERLAP)
    if not chunks:
        raise HTTPException(status_code=422, detail="Document produced no text chunks")


    doc_base_id = str(uuid.uuid4())
    col = chroma_client.get_or_create_collection(collection)

    ids        = [f"{doc_base_id}_{i}" for i in range(len(chunks))]
    metadatas  = [
        {
            "source":      source or filename,
            "filename":    filename,
            "sha256":      sha256,
            "chunk_index": i,
            "total_chunks": len(chunks),
        }
        for i in range(len(chunks))
    ]

    col.add(documents=chunks, ids=ids, metadatas=metadatas)

    log.info("[RAG] Ingested %d chunks from %s into %s", len(chunks), filename, collection)
    return {
        "ingested_chunks": len(chunks),
        "collection":      collection,
        "filename":        filename,
        "sha256":          sha256,
        "doc_id":          doc_base_id,
    }


@router.get("/collections")
async def list_collections(_user: dict = Depends(get_current_user)) -> list:
    """Return all ChromaDB collections with document counts."""
    try:
        cols = chroma_client.list_collections()
        return [
            {"name": c.name, "count": c.count()}
            for c in cols
        ]
    except Exception as e:
        log.error("[RAG] Failed to list collections: %s", e)
        return []
