# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
ALC_LCD.2 — Developer-Defined Life-Cycle Model.

Verifies:
- LICENSE file exists and declares Apache-2.0
- CONTRIBUTING.md exists and describes the review/merge process
- Pre-commit hook exists and is executable
- CODEOWNERS exists and covers security-critical paths
- Dependabot configuration exists
"""
from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
LICENSE_FILE = REPO_ROOT / "LICENSE"
CONTRIBUTING_MD = REPO_ROOT / "CONTRIBUTING.md"
PRE_COMMIT_HOOK = REPO_ROOT / "deploy" / "hooks" / "pre-commit"
CODEOWNERS = REPO_ROOT / ".github" / "CODEOWNERS"
DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"


# ── LICENSE ───────────────────────────────────────────────────────────────────

class TestLicense:
    """ALC_LCD.2: the TOE must be distributed under a defined licence."""

    def test_license_file_exists(self):
        assert LICENSE_FILE.exists(), (
            f"LICENSE not found at {LICENSE_FILE} — required by ALC_LCD.2"
        )

    def test_license_is_apache2(self):
        content = LICENSE_FILE.read_text(encoding="utf-8")
        assert "Apache License" in content and "Version 2.0" in content, (
            "LICENSE must be Apache 2.0 (ALC_LCD.2)"
        )

    def test_license_has_copyright_notice(self):
        content = LICENSE_FILE.read_text(encoding="utf-8")
        assert re.search(r"Copyright\s+20\d\d", content), (
            "LICENSE must contain a dated copyright notice (ALC_LCD.2)"
        )


# ── CONTRIBUTING.md ───────────────────────────────────────────────────────────

class TestContributing:
    """ALC_LCD.2: life-cycle procedures must be documented."""

    REQUIRED_KEYWORDS = [
        "review",
        "branch",
        "pull request",
        "security",
    ]

    def test_contributing_exists(self):
        assert CONTRIBUTING_MD.exists(), (
            f"CONTRIBUTING.md not found at {CONTRIBUTING_MD} — required by ALC_LCD.2"
        )

    @pytest.mark.parametrize("keyword", REQUIRED_KEYWORDS)
    def test_contributing_covers_topic(self, keyword: str):
        content = CONTRIBUTING_MD.read_text(encoding="utf-8").lower()
        assert keyword in content, (
            f"CONTRIBUTING.md must cover '{keyword}' to satisfy ALC_LCD.2 "
            "life-cycle documentation requirements"
        )


# ── Pre-commit hook ───────────────────────────────────────────────────────────

class TestPreCommitHook:
    """ALC_LCD.2: development tools must enforce security controls at commit time."""

    def test_pre_commit_hook_exists(self):
        assert PRE_COMMIT_HOOK.exists(), (
            f"Pre-commit hook not found at {PRE_COMMIT_HOOK} — "
            "secret scanning at commit time is required (ALC_LCD.2)"
        )

    def test_pre_commit_hook_is_executable(self):
        mode = PRE_COMMIT_HOOK.stat().st_mode
        assert mode & stat.S_IXUSR, (
            f"Pre-commit hook at {PRE_COMMIT_HOOK} is not executable — "
            "run: chmod +x deploy/hooks/pre-commit"
        )

    def test_pre_commit_hook_scans_credentials(self):
        content = PRE_COMMIT_HOOK.read_text(encoding="utf-8")
        # Must check for at least one credential pattern
        assert any(
            kw in content for kw in ("AKIA", "sk-", "ghp_", "xox", "password", "secret", "api.key", "API_KEY")
        ), (
            "Pre-commit hook must include credential pattern scanning (ALC_LCD.2)"
        )


# ── CODEOWNERS ────────────────────────────────────────────────────────────────

class TestCodeowners:
    """ALC_LCD.2: security-critical changes must require authorised review."""

    REQUIRED_PATHS = [
        ".github/workflows/",
        "backend/infrastructure/auth_client.py",
        "backend/requirements.txt",
    ]

    def test_codeowners_exists(self):
        assert CODEOWNERS.exists(), (
            f"CODEOWNERS not found at {CODEOWNERS} — "
            "mandatory reviewer assignment is required (ALC_LCD.2)"
        )

    @pytest.mark.parametrize("path", REQUIRED_PATHS)
    def test_codeowners_covers_security_path(self, path: str):
        content = CODEOWNERS.read_text(encoding="utf-8")
        # Match on the path itself or a parent glob that would cover it
        path_base = path.rstrip("/").split("/")[-1]
        assert path in content or path_base in content, (
            f"CODEOWNERS must cover '{path}' — required security-critical path (ALC_LCD.2)"
        )


# ── Dependabot ────────────────────────────────────────────────────────────────

class TestDependabot:
    """ALC_LCD.2: dependency updates must follow a controlled process."""

    def test_dependabot_config_exists(self):
        assert DEPENDABOT.exists(), (
            f"dependabot.yml not found at {DEPENDABOT} — "
            "automated dependency update configuration is required (ALC_LCD.2)"
        )

    def test_dependabot_covers_pip(self):
        content = DEPENDABOT.read_text(encoding="utf-8")
        assert "pip" in content, (
            "dependabot.yml must include pip ecosystem (ALC_LCD.2)"
        )

    def test_dependabot_covers_npm(self):
        content = DEPENDABOT.read_text(encoding="utf-8")
        assert "npm" in content, (
            "dependabot.yml must include npm ecosystem (ALC_LCD.2)"
        )
