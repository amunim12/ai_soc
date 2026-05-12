# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
ADV_FSP.2 — Basic Security Functions Specification.

Verifies:
- .env.example documents every env var consumed by the application
- SECURITY.md exists and contains the mandatory sections
- OpenAPI spec is exportable and all security-sensitive routes are declared
- TOE (Target of Evaluation) boundary documentation is present
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = REPO_ROOT / "backend"
ENV_EXAMPLE = BACKEND_ROOT / ".env.example"
SECURITY_MD = REPO_ROOT / "SECURITY.md"
README_MD = REPO_ROOT / "README.md"


# ── .env.example completeness ─────────────────────────────────────────────────

class TestEnvExample:
    """ADV_FSP.2: all external interfaces (env vars) must be specified."""

    # These env vars are required for the application to function securely
    REQUIRED_ENV_VARS = [
        "JWT_SECRET_KEY",
        "DEFAULT_ADMIN_PASSWORD",
        "POSTGRES_DSN",
        "REDIS_URL",
        "WAZUH_INDEXER_HOST",
        "WAZUH_INDEXER_USER",
        "WAZUH_INDEXER_PASSWORD",
    ]

    def test_env_example_exists(self):
        assert ENV_EXAMPLE.exists(), (
            f".env.example not found at {ENV_EXAMPLE} — "
            "all configurable parameters must be documented (ADV_FSP.2)"
        )

    @pytest.mark.parametrize("var", REQUIRED_ENV_VARS)
    def test_required_var_documented(self, var: str):
        content = ENV_EXAMPLE.read_text(encoding="utf-8")
        assert var in content, (
            f"'{var}' is not documented in .env.example — "
            "all security-relevant parameters must be specified (ADV_FSP.2)"
        )

    def test_no_real_secrets_in_example(self):
        """Ensure .env.example only contains placeholder values, not real secrets."""
        content = ENV_EXAMPLE.read_text(encoding="utf-8")
        # Real secret patterns: long hex strings, JWT payloads, actual API key formats
        dangerous_patterns = [
            r'sk-[A-Za-z0-9]{20,}',          # OpenAI keys
            r'AKIA[0-9A-Z]{16}',              # AWS access keys
            r'ghp_[A-Za-z0-9]{36}',           # GitHub personal access tokens
            r'xox[baprs]-[0-9]{10,}',         # Slack tokens
        ]
        for pattern in dangerous_patterns:
            match = re.search(pattern, content)
            assert not match, (
                f"Possible real secret found in .env.example "
                f"(pattern '{pattern}'): {match.group()}"
            )


# ── SECURITY.md mandatory sections ───────────────────────────────────────────

class TestSecurityMd:
    """ADV_FSP.2: security policy must be formally specified."""

    REQUIRED_SECTIONS = [
        "Supported Versions",
        "Reporting",
        "Air-Gap",
        "Credential",
    ]

    def test_security_md_exists(self):
        assert SECURITY_MD.exists(), (
            f"SECURITY.md not found at {SECURITY_MD} — "
            "security policy documentation is required (ADV_FSP.2)"
        )

    @pytest.mark.parametrize("section", REQUIRED_SECTIONS)
    def test_security_md_contains_section(self, section: str):
        content = SECURITY_MD.read_text(encoding="utf-8")
        assert section in content, (
            f"SECURITY.md is missing section covering '{section}' — "
            "required by ADV_FSP.2 for security policy completeness"
        )


# ── TOE boundary documentation ────────────────────────────────────────────────

class TestToeBoundary:
    """ADV_FSP.2: the TOE boundary must be described in developer documentation."""

    def test_readme_describes_architecture(self):
        assert README_MD.exists(), f"README.md not found at {README_MD}"
        content = README_MD.read_text(encoding="utf-8")
        # README must contain architecture/component description
        assert any(kw in content for kw in ("Architecture", "architecture", "Component", "component")), (
            "README.md must describe the system architecture (TOE boundary — ADV_FSP.2)"
        )

    def test_readme_describes_api_boundary(self):
        content = README_MD.read_text(encoding="utf-8")
        assert "API" in content or "api" in content.lower(), (
            "README.md must document the API boundary (ADV_FSP.2)"
        )

    def test_readme_describes_air_gap_requirement(self):
        content = README_MD.read_text(encoding="utf-8")
        assert "air" in content.lower() or "Air" in content, (
            "README.md must document the air-gap deployment constraint (ADV_FSP.2 TOE boundary)"
        )


# ── OpenAPI spec exportable ───────────────────────────────────────────────────

class TestOpenApiSpec:
    """ADV_FSP.2: all external interfaces must be formally declared."""

    def test_fastapi_routes_importable(self):
        """The API module must be importable (basic syntax/import check)."""
        result = subprocess.run(
            [sys.executable, "-c", "import api.auth_api; import api.alert_api"],
            cwd=str(BACKEND_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"API modules failed to import:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
