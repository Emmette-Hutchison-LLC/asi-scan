import pytest

from asi_scan.detectors import SubstringLeakDetector
from asi_scan.models import ProbeResult, Severity, VerdictStatus
from asi_scan.probes.base import REGISTRY, Probe, probes_for, register
from asi_scan.target import InMemoryTarget
from asi_scan.selftest import build_vulnerable_server


@pytest.fixture
def demo_probe():
    """Register a throwaway probe for the duration of one test.

    Registration happens inside the fixture (not at import), so the autouse
    registry-isolation fixture in conftest removes it on teardown.
    """

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

    return _DemoProbe


def test_registry_indexes_by_asi(demo_probe):
    assert demo_probe in probes_for("ASI02")
    assert demo_probe in probes_for(None)
    assert demo_probe not in probes_for("ASI99")


@pytest.mark.asyncio
async def test_execute_returns_finding(demo_probe):
    finding = await demo_probe().execute(InMemoryTarget(build_vulnerable_server()))
    assert finding.probe_id == "demo.asi02"
    assert finding.verdict.status is VerdictStatus.VULNERABLE


def test_registry_isolated_between_tests():
    # The demo probe registered by the other tests must not leak into this one.
    assert "demo.asi02" not in REGISTRY
