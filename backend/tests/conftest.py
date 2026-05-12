# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Global pytest configuration — tests/conftest.py

Provides shared fixtures that apply to ALL test files to prevent
live infrastructure calls in unit and e2e tests.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch


@pytest.fixture(autouse=True)
def mock_redis_globally(request):
    """
    Auto-mock Redis for every test.

    The real Redis client raises a ConnectionError when no Redis server
    is running locally. Since all Redis methods have safe fallbacks
    (return False / [] / None on error), mocking them directly is the
    cleanest approach for test isolation.

    Tests that explicitly test Redis behaviour can override this by
    using pytest.mark or patching again at a lower scope.
    """

    if request.node.get_closest_marker("redis_integration"):
        yield
        return

    with (
        patch(
            "infrastructure.redis_client.redis_client.check_dedup",
            new=AsyncMock(return_value=False),
        ),
        patch(
            "infrastructure.redis_client.redis_client.check_burst",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "infrastructure.redis_client.redis_client.is_known_malicious",
            new=AsyncMock(return_value=False),
        ),
        patch(
            "infrastructure.redis_client.redis_client.mark_malicious",
            new=AsyncMock(return_value=None),
        ),
    ):
        yield
