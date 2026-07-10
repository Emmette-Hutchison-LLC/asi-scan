import pytest

from asi_scan.models import VerdictStatus
from asi_scan.probes.asi06_memory_poisoning import MemoryPoisonProbe
from asi_scan.target import InMemoryTarget
from asi_scan.selftest import build_vulnerable_server


@pytest.mark.asyncio
async def test_asi06_flags_persisted_injection():
    finding = await MemoryPoisonProbe().execute(InMemoryTarget(build_vulnerable_server(hardened=False)))
    assert finding.verdict.status is VerdictStatus.VULNERABLE


@pytest.mark.asyncio
async def test_asi06_safe_when_sanitized():
    finding = await MemoryPoisonProbe().execute(InMemoryTarget(build_vulnerable_server(hardened=True)))
    assert finding.verdict.status is VerdictStatus.SAFE
