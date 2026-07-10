import pytest

from asi_scan.models import VerdictStatus
from asi_scan.probes.asi02_tool_misuse import UnauthInvokeProbe
from asi_scan.target import InMemoryTarget
from asi_scan.selftest import build_vulnerable_server


@pytest.mark.asyncio
async def test_asi02_flags_vulnerable_server():
    finding = await UnauthInvokeProbe().execute(InMemoryTarget(build_vulnerable_server(hardened=False)))
    assert finding.verdict.status is VerdictStatus.VULNERABLE
    assert "ASI02" in finding.asi_categories


@pytest.mark.asyncio
async def test_asi02_safe_on_hardened_server():
    finding = await UnauthInvokeProbe().execute(InMemoryTarget(build_vulnerable_server(hardened=True)))
    assert finding.verdict.status is VerdictStatus.SAFE
