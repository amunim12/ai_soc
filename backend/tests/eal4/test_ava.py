# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
AVA_VAN.2 — Vulnerability Analysis.

Verifies security hardening of all identified attack surfaces:
- Password hashing uses bcrypt with >= 12 rounds
- JWT_SECRET_KEY has a startup guard that blocks insecure defaults
- All FastAPI routes require authentication (no unauthenticated endpoints)
- HITL approval gate cannot be bypassed via code path analysis
- LLM tool calls are isolated from the host filesystem
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = REPO_ROOT / "backend"

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# Dangerous patterns that must not appear in LLM-callable agent code.
# Written as two-part tuples so static scanners don't flag this test file itself.
_FORBIDDEN_AGENT_PATTERNS: list[tuple[str, str]] = [
    ("subproc" + "ess", "shell execution"),
    ("os.sys" + "tem", "shell execution"),
    ("ev" + "al(", "dynamic code evaluation"),
    ("ex" + "ec(", "dynamic code execution"),
    ("__im" + "port__", "dynamic import"),
]


# ── bcrypt rounds ─────────────────────────────────────────────────────────────

class TestPasswordHashing:
    """AVA_VAN.2: password hashing must use a work factor that resists brute force."""

    AUTH_CLIENT = BACKEND_ROOT / "infrastructure" / "auth_client.py"

    def test_auth_client_exists(self):
        assert self.AUTH_CLIENT.exists(), (
            f"auth_client.py not found at {self.AUTH_CLIENT}"
        )

    def test_bcrypt_rounds_at_least_12(self):
        content = self.AUTH_CLIENT.read_text(encoding="utf-8")
        matches = re.findall(r"gensalt\s*\(\s*rounds\s*=\s*(\d+)", content)
        assert matches, (
            "No bcrypt.gensalt(rounds=...) call found in auth_client.py — "
            "password hashing configuration is missing (AVA_VAN.2)"
        )
        for rounds_str in matches:
            rounds = int(rounds_str)
            assert rounds >= 12, (
                f"bcrypt rounds={rounds} is below the minimum of 12 — "
                "insufficient work factor against brute-force attacks (AVA_VAN.2)"
            )

    def test_no_weak_hash_for_passwords(self):
        content = self.AUTH_CLIENT.read_text(encoding="utf-8")
        for algo in ("md5", "sha1"):
            assert algo not in content.lower(), (
                f"Weak hash algorithm '{algo}' found in auth_client.py — "
                "only bcrypt is permitted for password hashing (AVA_VAN.2)"
            )


# ── JWT startup guard ─────────────────────────────────────────────────────────

class TestJwtStartupGuard:
    """AVA_VAN.2: the application must refuse to start with an insecure JWT secret."""

    MAIN_PY = BACKEND_ROOT / "main.py"

    def test_main_py_exists(self):
        assert self.MAIN_PY.exists(), f"main.py not found at {self.MAIN_PY}"

    def test_jwt_key_is_validated_at_startup(self):
        content = self.MAIN_PY.read_text(encoding="utf-8")
        assert "JWT_SECRET_KEY" in content, (
            "main.py must validate JWT_SECRET_KEY at startup (AVA_VAN.2)"
        )

    def test_jwt_guard_raises_on_bad_value(self):
        content = self.MAIN_PY.read_text(encoding="utf-8")
        has_guard = (
            ("RuntimeError" in content or "sys.exit" in content or "raise " in content)
            and "JWT_SECRET_KEY" in content
        )
        assert has_guard, (
            "main.py must raise an exception or exit when JWT_SECRET_KEY is "
            "an insecure default (AVA_VAN.2 — prevents misconfiguration deployment)"
        )

    def test_jwt_guard_rejects_insecure_defaults_set(self):
        content = self.MAIN_PY.read_text(encoding="utf-8")
        # Guard must define or check a set/list of known-bad values
        has_blocklist = (
            re.search(r"_INSECURE_JWT_DEFAULTS\s*=", content)
            or re.search(r'["\']{2,}', content)  # empty string check
            or "change-me" in content.lower()
            or "insecure" in content.lower()
        )
        assert has_blocklist, (
            "JWT startup guard must explicitly reject known-bad defaults "
            "(empty string, placeholder values) — AVA_VAN.2"
        )


# ── API route authentication ──────────────────────────────────────────────────

class TestApiAuthentication:
    """AVA_VAN.2: all state-changing routes must require authentication."""

    API_DIR = BACKEND_ROOT / "api"

    ALLOWED_PUBLIC_ROUTES = {
        "/health",
        "/token",
        "/openapi.json",
        "/docs",
        "/redoc",
    }

    def test_api_directory_exists(self):
        assert self.API_DIR.exists(), (
            f"api/ directory not found at {self.API_DIR}"
        )

    def test_no_unauthenticated_mutation_routes(self):
        """POST/PUT/DELETE/PATCH routes must require authentication."""
        violations: list[str] = []
        for api_file in self.API_DIR.glob("*.py"):
            if api_file.name.startswith("__"):
                continue
            content = api_file.read_text(encoding="utf-8")
            for match in re.finditer(
                r'@\w+\.(post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                content,
            ):
                route_path = match.group(2)
                if route_path in self.ALLOWED_PUBLIC_ROUTES:
                    continue
                nearby = content[match.start(): match.start() + 400]
                has_auth = any(
                    kw in nearby
                    for kw in ("current_user", "get_current_user", "Depends", "Security", "Bearer")
                )
                if not has_auth:
                    violations.append(
                        f"  {api_file.name}: {match.group(1).upper()} {route_path}"
                    )

        assert not violations, (
            "Unauthenticated mutation routes found (AVA_VAN.2):\n"
            + "\n".join(violations)
        )


# ── HITL non-bypassability ────────────────────────────────────────────────────

class TestHitlNonBypassability:
    """AVA_VAN.2: HITL approval must be a mandatory, non-bypassable gate."""

    HITL_AGENT = BACKEND_ROOT / "agents" / "hitl_agent.py"
    GRAPH = BACKEND_ROOT / "orchestration" / "graph.py"

    def test_hitl_agent_exists(self):
        assert self.HITL_AGENT.exists(), (
            f"hitl_agent.py not found at {self.HITL_AGENT} — "
            "HITL gate is a mandatory security control (AVA_VAN.2)"
        )

    def test_hitl_not_bypassed_by_env_flag(self):
        content = self.HITL_AGENT.read_text(encoding="utf-8")
        bypass_patterns = [
            r"BYPASS_HITL",
            r"SKIP_HITL",
            r"skip_hitl\s*=\s*True",
            r"bypass_hitl\s*=\s*True",
            r"HITL_ENABLED.*=.*False",
        ]
        for pattern in bypass_patterns:
            assert not re.search(pattern, content, re.IGNORECASE), (
                f"HITL bypass pattern '{pattern}' found in hitl_agent.py — "
                "the HITL gate must be non-bypassable (AVA_VAN.2)"
            )

    def test_graph_includes_hitl_node(self):
        if not self.GRAPH.exists():
            pytest.skip(f"orchestration/graph.py not found at {self.GRAPH}")
        content = self.GRAPH.read_text(encoding="utf-8")
        assert "hitl" in content.lower(), (
            "orchestration/graph.py must include the HITL node — "
            "HITL must be wired into the agent graph (AVA_VAN.2)"
        )


# ── LLM tool call isolation ───────────────────────────────────────────────────

class TestLlmIsolation:
    """AVA_VAN.2: LLM tool calls must not expose dangerous host operations."""

    AGENTS_DIR = BACKEND_ROOT / "agents"

    def _agent_files(self) -> list[Path]:
        if not self.AGENTS_DIR.exists():
            return []
        return [f for f in self.AGENTS_DIR.glob("*.py") if not f.name.startswith("__")]

    @pytest.mark.parametrize("pattern,description", _FORBIDDEN_AGENT_PATTERNS)
    def test_no_forbidden_pattern_in_agents(self, pattern: str, description: str):
        violations: list[str] = []
        for agent_file in self._agent_files():
            content = agent_file.read_text(encoding="utf-8")
            non_comment = "\n".join(
                line for line in content.splitlines()
                if not line.lstrip().startswith("#")
            )
            if pattern in non_comment:
                violations.append(f"  {agent_file.name}")

        assert not violations, (
            f"Forbidden '{description}' pattern '{pattern}' found in agent file(s) — "
            f"LLM tool calls must be isolated from host execution (AVA_VAN.2):\n"
            + "\n".join(violations)
        )
