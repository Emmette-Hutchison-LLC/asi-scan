import pytest

from asi_scan.models import VerdictStatus
from asi_scan.probes.asi07_shadowing import ShadowingProbe
from asi_scan.target import InMemoryTarget
from asi_scan.selftest import build_shadow_server, build_vulnerable_server


@pytest.mark.asyncio
async def test_asi07_flags_shadow_serving_result():
    finding = await ShadowingProbe().execute(InMemoryTarget(build_shadow_server()))
    assert finding.verdict.status is VerdictStatus.VULNERABLE


@pytest.mark.asyncio
async def test_asi07_safe_on_trusted_only():
    finding = await ShadowingProbe().execute(InMemoryTarget(build_vulnerable_server()))
    assert finding.verdict.status is VerdictStatus.SAFE
