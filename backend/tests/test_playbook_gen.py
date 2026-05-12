# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Tests — Playbook Schema and Parsing

pytest tests/test_playbook_gen.py -v
"""
from __future__ import annotations

import pytest
from schemas.playbook import Playbook, PlaybookStep, IRREVERSIBLE_ACTIONS


VALID_YAML = """
title: SSH Brute Force Response
summary: Respond to SSH brute force from 185.220.101.47
confidence_score: 0.87
estimated_duration_minutes: 20
auto_approve: false
containment:
  steps:
    - step_id: C1
      action_type: BLOCK_IP
      description: Block attacking IP at firewall
      target: 185.220.101.47
      mitre_technique: T1110
      estimated_duration_minutes: 2
      requires_confirmation: false
      parameters:
        firewall: pf
eradication:
  steps:
    - step_id: E1
      action_type: RESET_PASSWORD
      description: Reset root password
      target: root@web-server-01
      mitre_technique: T1078
      estimated_duration_minutes: 5
      requires_confirmation: false
      parameters: {}
recovery:
  steps:
    - step_id: R1
      action_type: CREATE_TICKET
      description: Open post-incident ticket
      mitre_technique: null
      estimated_duration_minutes: 3
      requires_confirmation: false
      parameters: {}
"""

YAML_WITH_FENCE = f"```yaml\n{VALID_YAML.strip()}\n```"
YAML_WITH_ISOLATE = VALID_YAML.replace("BLOCK_IP", "ISOLATE_HOST")


def test_parse_valid_yaml():
    pb = Playbook.from_yaml(VALID_YAML)
    assert pb.title == "SSH Brute Force Response"
    assert pb.confidence_score == 0.87
    assert "containment" in pb.phases
    assert "eradication" in pb.phases
    assert "recovery" in pb.phases


def test_parse_strips_markdown_fence():
    pb = Playbook.from_yaml(YAML_WITH_FENCE)
    assert pb.confidence_score == 0.87


def test_phase_has_steps():
    pb = Playbook.from_yaml(VALID_YAML)
    containment = pb.phases["containment"]
    assert len(containment.steps) == 1
    assert containment.steps[0].action_type == "BLOCK_IP"
    assert containment.steps[0].target == "185.220.101.47"


def test_total_steps():
    pb = Playbook.from_yaml(VALID_YAML)
    assert pb.total_steps == 3


def test_no_irreversible_steps():
    pb = Playbook.from_yaml(VALID_YAML)
    assert not pb.has_irreversible_steps


def test_has_irreversible_steps():
    pb = Playbook.from_yaml(YAML_WITH_ISOLATE)
    assert pb.has_irreversible_steps


def test_step_is_irreversible():
    step = PlaybookStep(step_id="C1", action_type="ISOLATE_HOST", description="Isolate")
    assert step.is_irreversible is True


def test_step_is_not_irreversible():
    step = PlaybookStep(step_id="C1", action_type="BLOCK_IP", description="Block")
    assert step.is_irreversible is False


def test_invalid_yaml_raises():
    with pytest.raises(Exception):
        Playbook.from_yaml("this is not yaml: {{{{")


def test_auto_approve_false_by_default():
    pb = Playbook.from_yaml(VALID_YAML)

    assert pb.auto_approve is False


def test_irreversible_actions_constant():
    assert "ISOLATE_HOST" in IRREVERSIBLE_ACTIONS
    assert "DISABLE_USER" in IRREVERSIBLE_ACTIONS
    assert "REVOKE_TOKEN" in IRREVERSIBLE_ACTIONS
    assert "BLOCK_IP" not in IRREVERSIBLE_ACTIONS
