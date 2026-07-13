# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path


def test_alert_api_module_exists() -> None:
    assert (Path(__file__).resolve().parents[1] / "api" / "alert_api.py").exists()
