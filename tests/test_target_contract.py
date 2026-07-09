import pytest

from asi_scan.target import InMemoryTarget
from asi_scan.selftest import build_vulnerable_server


@pytest.mark.asyncio
async def test_list_tools_reports_names():
    target = InMemoryTarget(build_vulnerable_server())
    names = {t["name"] for t in await target.list_tools()}
    assert {"read_secret", "run", "save_note", "get_notes", "search"} <= names


@pytest.mark.asyncio
async def test_call_tool_returns_text():
    target = InMemoryTarget(build_vulnerable_server())
    out = await target.call_tool("read_secret", {})
    assert "SECRET" in out
