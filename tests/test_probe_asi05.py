import pytest

from asi_scan.models import VerdictStatus
from asi_scan.probes.asi05_code_exec import ArgInjectionProbe
from asi_scan.target import InMemoryTarget
from asi_scan.selftest import build_vulnerable_server


@pytest.mark.asyncio
async def test_asi05_flags_arg_injection():
    finding = await ArgInjectionProbe().execute(InMemoryTarget(build_vulnerable_server(hardened=False)))
    assert finding.verdict.status is VerdictStatus.VULNERABLE


@pytest.mark.asyncio
async def test_asi05_safe_on_hardened():
    finding = await ArgInjectionProbe().execute(InMemoryTarget(build_vulnerable_server(hardened=True)))
    assert finding.verdict.status is VerdictStatus.SAFE
