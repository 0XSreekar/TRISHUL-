"""Fixtures for gateway integration tests."""

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from fastmcp import Client

from tests.integration.test_gateway_harness import Env, make_env_sync


@pytest.fixture
async def env(tmp_path: Path) -> AsyncIterator[Env]:
    gw, conn, ids, keys, clock, events = make_env_sync(tmp_path)
    async with Client(gw.mcp) as client:
        yield Env(gw, client, conn, ids, keys, clock, events)
    conn.close()
