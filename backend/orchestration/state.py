# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""PipelineState — shared LangGraph state TypedDict."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from typing_extensions import TypedDict

from schemas.alert import WazuhAlert
from schemas.analysis import AnalysisResult
from schemas.enrichment import TIEnrichment
from schemas.playbook import Playbook
from schemas.hitl import ApprovalDecision
from schemas.audit import StepLog


class PipelineState(TypedDict, total=False):

    alert: WazuhAlert


    analysis: Optional[AnalysisResult]
    enrichment: Optional[TIEnrichment]
    playbook: Optional[Playbook]
    hitl_decision: Optional[ApprovalDecision]


    confidence: float
    pipeline_stage: str
    requires_hitl: bool
    approved: bool
    hitl_timeout_at: Optional[datetime]


    soar_execution_id: Optional[str]
    soar_result: Optional[dict[str, Any]]


    audit_trail: list[StepLog]


def initial_state(alert: WazuhAlert) -> PipelineState:
    """Create a fresh PipelineState for a given alert."""
    return PipelineState(
        alert=alert,
        analysis=None,
        enrichment=None,
        playbook=None,
        hitl_decision=None,
        confidence=0.0,
        pipeline_stage="init",
        requires_hitl=False,
        approved=False,
        hitl_timeout_at=None,
        audit_trail=[],
    )
