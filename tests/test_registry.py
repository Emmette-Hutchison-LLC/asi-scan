import pytest

from asi_scan.detectors import SubstringLeakDetector
from asi_scan.models import ProbeResult, Severity, VerdictStatus
from asi_scan.probes.base import Probe, probes_for, register
from asi_scan.target import InMemoryTarget
from asi_scan.selftest import build_vulnerable_server


@register
class _DemoProbe(Probe):
    id = "demo.asi02"
    asi_categories = ["ASI02"]
    severity = Severity.HIGH
    remediation = "add auth"

    async def run(self, target):
        out = await target.call_tool("read_secret", {})
        return ProbeResult(self.id, self.asi_categories, observed={"response": out})

    def detector(self):
        return SubstringLeakDetector(needle="SECRET", observed_key="response")


def test_registry_indexes_by_asi():
    assert _DemoProbe in probes_for("ASI02")
    assert _DemoProbe in probes_for(None)
    assert _DemoProbe not in probes_for("ASI99")


@pytest.mark.asyncio
async def test_execute_returns_finding():
    finding = await _DemoProbe().execute(InMemoryTarget(build_vulnerable_server()))
    assert finding.probe_id == "demo.asi02"
    assert finding.verdict.status is VerdictStatus.VULNERABLE
