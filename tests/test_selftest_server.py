import pytest
from mcp.shared.memory import create_connected_server_and_client_session as client_session

from asi_scan.selftest import build_vulnerable_server


async def _call(server, name, args):
    async with client_session(server._mcp_server) as client:
        await client.initialize()
        result = await client.call_tool(name, args)
        return "".join(c.text for c in result.content if c.type == "text")


@pytest.mark.asyncio
async def test_vulnerable_server_leaks_secret():
    server = build_vulnerable_server(hardened=False)
    out = await _call(server, "read_secret", {})
    assert "SECRET" in out


@pytest.mark.asyncio
async def test_hardened_server_refuses_secret():
    server = build_vulnerable_server(hardened=True)
    out = await _call(server, "read_secret", {})
    assert "SECRET" not in out
    assert "denied" in out.lower()
