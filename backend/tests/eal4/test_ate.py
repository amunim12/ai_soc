# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
ATE_COV.2 — Analysis of Coverage.

Verifies that the test suite provides adequate coverage of security functions:
- Per-module coverage meets the defined gates
- Security-critical modules have dedicated test files
- The EAL4 test suite itself covers all five assurance classes
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = REPO_ROOT / "backend"
COVERAGE_XML = BACKEND_ROOT / "coverage.xml"

# Module → minimum line-rate percentage
COVERAGE_GATES: dict[str, float] = {
    "agents":         80.0,
    "orchestration":  80.0,
    "schemas":        85.0,
    "api":            65.0,
    "infrastructure": 65.0,
}

# Security-critical modules that must have dedicated test files
SECURITY_MODULES = [
    "auth",
    "alert",
    "hitl",
    "supervisor",
]

# EAL4 assurance classes that must have test files
EAL4_CLASSES = ["test_acm", "test_adv", "test_alc", "test_ate", "test_ava"]


# ── Coverage XML gates ────────────────────────────────────────────────────────

class TestCoverageGates:
    """ATE_COV.2: coverage of security functions must meet defined thresholds."""

    def _load_packages(self) -> dict[str, float]:
        if not COVERAGE_XML.exists():
            pytest.skip(
                "coverage.xml not found — run pytest --cov first. "
                "This check is enforced by the CI pipeline."
            )
        tree = ET.parse(str(COVERAGE_XML))
        root = tree.getroot()
        return {
            p.get("name", ""): float(p.get("line-rate", 0)) * 100
            for p in root.iter("package")
        }

    @pytest.mark.parametrize("module,minimum", COVERAGE_GATES.items())
    def test_module_coverage_gate(self, module: str, minimum: float):
        packages = self._load_packages()
        matched = [(name, rate) for name, rate in packages.items() if module in name]

        if not matched:
            pytest.skip(f"No coverage data found for module '{module}'")

        failures = [
            f"  {name}: {rate:.1f}% < {minimum:.0f}% required"
            for name, rate in matched
            if rate < minimum
        ]
        assert not failures, (
            f"Coverage gate not met for '{module}' (ATE_COV.2):\n"
            + "\n".join(failures)
        )


# ── Security function test coverage ──────────────────────────────────────────

class TestSecurityFunctionCoverage:
    """ATE_COV.2: each security function must have a dedicated test file."""

    def _test_files(self) -> set[str]:
        return {
            p.stem
            for p in (BACKEND_ROOT / "tests").rglob("test_*.py")
        }

    @pytest.mark.parametrize("module", SECURITY_MODULES)
    def test_security_module_has_tests(self, module: str):
        test_files = self._test_files()
        matching = [f for f in test_files if module in f]
        assert matching, (
            f"No test file found covering security module '{module}' "
            f"(ATE_COV.2 requires tests for each security function). "
            f"Expected a file matching 'test_*{module}*.py' in tests/"
        )


# ── EAL4 test suite completeness ─────────────────────────────────────────────

class TestEal4SuiteCompleteness:
    """ATE_COV.2: the EAL4 compliance suite must cover all assurance classes."""

    EAL4_DIR = BACKEND_ROOT / "tests" / "eal4"

    @pytest.mark.parametrize("test_file", EAL4_CLASSES)
    def test_eal4_class_has_test_file(self, test_file: str):
        expected = self.EAL4_DIR / f"{test_file}.py"
        assert expected.exists(), (
            f"EAL4 test file '{test_file}.py' is missing from tests/eal4/ — "
            "all five CC assurance classes must be covered (ATE_COV.2)"
        )

    def test_eal4_dir_has_init(self):
        assert (self.EAL4_DIR / "__init__.py").exists(), (
            "tests/eal4/__init__.py is missing — required for pytest discovery"
        )
