# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Playbook — OASIS CACAO v2.0 compliant incident-response playbook schema.

References:
  https://docs.oasis-open.org/cacao/security-playbooks/v2.0/

Key CACAO concepts mapped here:
  Playbook        → cacao_playbook (top-level object)
  PlaybookStep    → WorkflowStep (action step)
  PlaybookPhase   → logical grouping (containment / eradication / recovery)

Legacy fields kept for internal pipeline compatibility are marked # compat.
"""
from __future__ import annotations

import uuid
import yaml
from datetime import datetime
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, field_serializer, model_validator


SOAR_ACTION_TYPES = Literal[
    "BLOCK_IP",
    "ISOLATE_HOST",
    "DISABLE_USER",
    "RESET_PASSWORD",
    "KILL_PROCESS",
    "CREATE_TICKET",
    "NOTIFY_ANALYST",
    "COLLECT_FORENSICS",
    "PATCH_CVE",
    "REVOKE_TOKEN",
]


IRREVERSIBLE_ACTIONS: set[str] = {"ISOLATE_HOST", "DISABLE_USER", "REVOKE_TOKEN"}


CACAO_STEP_TYPES = Literal[
    "action",
    "playbook-action",
    "parallel",
    "if-condition",
    "while-condition",
    "switch-condition",
    "end",
    "start",
]


class CacaoTarget(BaseModel):
    """CACAO target object — asset/system the step acts on."""
    type: str = "net-address"
    name: Optional[str] = None
    address: Optional[dict[str, list[str]]] = None
    description: Optional[str] = None


class PlaybookStep(BaseModel):
    """CACAO workflow step — maps to an action step in the playbook."""


    type: CACAO_STEP_TYPES = "action"
    id: str = Field(default_factory=lambda: f"action--{uuid.uuid4()}")
    name: str = ""
    description: str = ""


    step_id:     str = ""
    action_type: str = "CREATE_TICKET"
    target:      Optional[str] = None
    mitre_technique: Optional[str] = None
    estimated_duration_minutes: int = 5
    requires_confirmation: bool = False
    parameters: dict[str, Any] = Field(default_factory=dict)


    commands: list[dict[str, Any]] = Field(default_factory=list)


    targets: list[CacaoTarget] = Field(default_factory=list)


    on_completion: Optional[str] = None
    on_failure:    Optional[str] = None

    @model_validator(mode="after")
    def _sync_name(self) -> "PlaybookStep":
        if not self.name and self.step_id:
            self.name = self.step_id
        if not self.step_id and self.name:
            self.step_id = self.name.lower().replace(" ", "_")
        return self

    @property
    def is_irreversible(self) -> bool:
        return self.action_type in IRREVERSIBLE_ACTIONS


class PlaybookPhase(BaseModel):
    phase_name: str
    steps: list[PlaybookStep] = Field(default_factory=list)

    @property
    def total_steps(self) -> int:
        return len(self.steps)

    @property
    def has_irreversible(self) -> bool:
        return any(s.is_irreversible for s in self.steps)


class Playbook(BaseModel):
    """
    CACAO Security Playbook v2.0 top-level object.

    Required CACAO fields: type, spec_version, id, name, created, modified.
    Additional pipeline fields kept for internal routing.
    """


    type:         str = "playbook"
    spec_version: str = "cacao-2.0"
    id:           str = Field(default_factory=lambda: f"playbook--{uuid.uuid4()}")
    name:         str = ""
    description:  str = ""
    created:      datetime = Field(default_factory=datetime.utcnow)
    modified:     datetime = Field(default_factory=datetime.utcnow)


    playbook_types: list[str] = Field(default_factory=lambda: ["investigation"])
    severity:       Optional[int] = None
    priority:       Optional[int] = None
    labels:         list[str] = Field(default_factory=list)


    workflow_start: Optional[str] = None
    workflow:       dict[str, PlaybookStep] = Field(default_factory=dict)


    alert_id:     str   = ""
    title:        str   = ""
    summary:      str   = ""
    phases:       dict[str, PlaybookPhase] = Field(default_factory=dict)
    confidence_score:              float = 0.0
    estimated_duration_minutes:    int   = 30
    auto_approve:                  bool  = False
    generated_at:                  Optional[datetime] = None
    rag_chunks_used:               int   = 0

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _sync_aliases(self) -> "Playbook":

        if self.title and not self.name:
            self.name = self.title
        if self.name and not self.title:
            self.title = self.name
        if self.summary and not self.description:
            self.description = self.summary
        if self.description and not self.summary:
            self.summary = self.description
        return self

    @field_serializer("generated_at", "created", "modified")
    def _ser_dt(self, v: Optional[datetime]) -> Optional[str]:
        return v.isoformat() if v else None

    @property
    def total_steps(self) -> int:
        return sum(p.total_steps for p in self.phases.values())

    @property
    def has_irreversible_steps(self) -> bool:
        return any(p.has_irreversible for p in self.phases.values())

    @classmethod
    def from_yaml(cls, yaml_text: str) -> "Playbook":
        """
        Parse Claude's YAML output into a CACAO-compliant Playbook.
        Handles both flat and nested phase structures.
        """
        clean = yaml_text.strip()
        if clean.startswith("```"):
            lines = clean.split("\n")
            clean = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        data = yaml.safe_load(clean)
        if not isinstance(data, dict):
            raise ValueError(f"Playbook YAML root must be a mapping, got: {type(data)}")

        phases: dict[str, PlaybookPhase] = {}

        for phase_name in ["containment", "eradication", "recovery"]:
            phase_data = data.get(phase_name, data.get(f"{phase_name}_phase", {}))
            if not phase_data:
                continue

            raw_steps = phase_data.get("steps", [])
            steps: list[PlaybookStep] = []
            for i, s in enumerate(raw_steps):
                slug = s.get("step_id", f"{phase_name}_{i + 1}")
                steps.append(PlaybookStep(
                    step_id=slug,
                    name=slug,
                    action_type=s.get("action_type", "CREATE_TICKET"),
                    description=s.get("description", ""),
                    target=s.get("target"),
                    mitre_technique=s.get("mitre_technique"),
                    estimated_duration_minutes=s.get("estimated_duration_minutes", 5),
                    requires_confirmation=s.get("requires_confirmation", False),
                    parameters=s.get("parameters", {}),
                ))
            phases[phase_name] = PlaybookPhase(phase_name=phase_name, steps=steps)

        title = data.get("title", "Incident Response Playbook")
        summary = data.get("summary", "")
        conf = float(data.get("confidence_score", 0.75))

        return cls(
            name=title,
            title=title,
            description=summary,
            summary=summary,
            phases=phases,
            confidence_score=conf,
            estimated_duration_minutes=int(data.get("estimated_duration_minutes", 30)),
            auto_approve=bool(data.get("auto_approve", False)),
            playbook_types=data.get("playbook_types", ["investigation"]),
            labels=data.get("labels", []),
        )
