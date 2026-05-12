# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
ACM_CAP.4 — Configuration Management Capabilities.

Verifies:
- All Python dependencies are exactly pinned (== operator, no ranges)
- .gitignore exists and covers credential file patterns
- All backend Python source files carry SPDX license headers
- Dockerfile exists for the API service
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# Repo root is three levels above this file: backend/tests/eal4/test_acm.py
REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = REPO_ROOT / "backend"
REQUIREMENTS = BACKEND_ROOT / "requirements.txt"
GITIGNORE = REPO_ROOT / ".gitignore"
DOCKERFILE = BACKEND_ROOT / "Dockerfile.api"

SPDX_HEADER = "SPDX-License-Identifier: Apache-2.0"

# Directories that are not first-party source code
_EXCLUDED_DIRS = {".venv314", "__pycache__", ".pytest_cache", "node_modules", "data"}


# ── Requirements pinning ─────────────────────────────────────────────────────

class TestDependencyPinning:
    """ACM_CAP.4 §3: all configuration items must be uniquely identified."""

    def test_requirements_file_exists(self):
        assert REQUIREMENTS.exists(), f"requirements.txt not found at {REQUIREMENTS}"

    def test_all_packages_exactly_pinned(self):
        unpinned: list[str] = []
        with REQUIREMENTS.open() as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                if not re.search(r"==", line):
                    unpinned.append(f"  line {lineno}: {line}")

        assert not unpinned, (
            "Unpinned dependencies found in requirements.txt "
            "(ACM_CAP.4 requires exact version locking):\n"
            + "\n".join(unpinned)
        )

    def test_no_wildcard_pins(self):
        """Reject version ranges like >=, ~=, !=, ^."""
        bad: list[str] = []
        with REQUIREMENTS.open() as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                if re.search(r"[><!~^]=", line) and "==" not in line:
                    bad.append(f"  line {lineno}: {line}")

        assert not bad, (
            "Version range operators found — all deps must use == :\n"
            + "\n".join(bad)
        )


# ── .gitignore coverage ──────────────────────────────────────────────────────

class TestGitignore:
    """ACM_CAP.4 §4: sensitive items must be excluded from version control."""

    REQUIRED_PATTERNS = [
        ".env",
        "*.key",
        "*.pem",
        "*.db",
        ".venv",
        "node_modules",
    ]

    def test_gitignore_exists(self):
        assert GITIGNORE.exists(), f".gitignore not found at {GITIGNORE}"

    @pytest.mark.parametrize("pattern", REQUIRED_PATTERNS)
    def test_gitignore_covers_pattern(self, pattern: str):
        content = GITIGNORE.read_text(encoding="utf-8")
        # Accept the exact pattern or a glob that would cover it
        base = pattern.lstrip("*.")
        assert pattern in content or base in content, (
            f".gitignore must cover '{pattern}' to satisfy ACM_CAP.4 §4"
        )


# ── SPDX license headers ─────────────────────────────────────────────────────

class TestSpdxHeaders:
    """ACM_CAP.4 §5: each configuration item must be identified with its licence."""

    def _python_sources(self) -> list[Path]:
        files = []
        for path in BACKEND_ROOT.rglob("*.py"):
            if any(part in _EXCLUDED_DIRS for part in path.parts):
                continue
            # Skip migration/generated files
            if "alembic" in path.parts or "migrations" in path.parts:
                continue
            files.append(path)
        return files

    def test_spdx_header_on_all_sources(self):
        missing: list[str] = []
        for src in self._python_sources():
            text = src.read_text(encoding="utf-8", errors="replace")
            if SPDX_HEADER not in text:
                missing.append(f"  {src.relative_to(REPO_ROOT)}")

        assert not missing, (
            f"{len(missing)} Python file(s) missing SPDX header "
            f"'{SPDX_HEADER}':\n" + "\n".join(sorted(missing))
        )


# ── Dockerfile presence ───────────────────────────────────────────────────────

class TestDockerfile:
    """ACM_CAP.4 §6: deployment artefact definition must be version-controlled."""

    def test_dockerfile_exists(self):
        assert DOCKERFILE.exists(), (
            f"Dockerfile.api not found at {DOCKERFILE} — "
            "container build definition must be in version control (ACM_CAP.4)"
        )

    def test_dockerfile_has_nonroot_user(self):
        content = DOCKERFILE.read_text(encoding="utf-8")
        assert re.search(r"^USER\s+(?!root)", content, re.MULTILINE), (
            "Dockerfile.api must specify a non-root USER for least-privilege (ACM_CAP.4)"
        )
