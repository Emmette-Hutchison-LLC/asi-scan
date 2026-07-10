import pytest

from asi_scan.detectors import SubstringLeakDetector
from asi_scan.models import ProbeResult, Severity, VerdictStatus
from asi_scan.engine import scan
from asi_scan.probes.base import Probe, register
from asi_scan.target import InMemoryTarget
from asi_scan.selftest import build_vulnerable_server


@register
class _EngineProbe(Probe):
    id = "engine.asi02"
    asi_categories = ["ASI02"]
    severity = Severity.HIGH
    remediation = "auth"

    async def run(self, target):
        out = await target.call_tool("read_secret", {})
        return ProbeResult(self.id, self.asi_categories, observed={"response": out})

    def detector(self):
        return SubstringLeakDetector("SECRET", "response")


@pytest.mark.asyncio
async def test_scan_collects_findings_for_asi():
    report = await scan(InMemoryTarget(build_vulnerable_server()), asi="ASI02")
    ids = {f.probe_id for f in report.findings}
    assert "engine.asi02" in ids
    assert any(f.verdict.status is VerdictStatus.VULNERABLE for f in report.findings)
