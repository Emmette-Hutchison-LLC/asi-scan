from __future__ import annotations

from typing import Any, Protocol, TypedDict, runtime_checkable

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session as client_session


class ToolInfo(TypedDict):
    name: str
    description: str


@runtime_checkable
class Target(Protocol):
    ref: str

    async def list_tools(self) -> list[ToolInfo]: ...
    async def call_tool(self, name: str, args: dict[str, Any]) -> str: ...


class InMemoryTarget:
    """Target backed by an in-process FastMCP server (deterministic; test + fixture use)."""

    def __init__(self, server: FastMCP) -> None:
        self._server = server
        self.ref = f"mock://{server.name}"

    async def list_tools(self) -> list[ToolInfo]:
        async with client_session(self._server._mcp_server) as client:
            await client.initialize()
            result = await client.list_tools()
            return [
                ToolInfo(name=t.name, description=t.description or "")
                for t in result.tools
            ]

    async def call_tool(self, name: str, args: dict[str, Any]) -> str:
        async with client_session(self._server._mcp_server) as client:
            await client.initialize()
            result = await client.call_tool(name, args)
            return "".join(c.text for c in result.content if c.type == "text")
