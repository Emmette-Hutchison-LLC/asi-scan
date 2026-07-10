from __future__ import annotations

from asi_scan.detectors import Detector, SubstringLeakDetector
from asi_scan.models import ProbeResult, ProbeStep, Severity
from asi_scan.probes.base import Probe, register
from asi_scan.target import Target

PRIVILEGED_TOOL = "read_secret"
SECRET_MARKER = "SECRET"


@register
class UnauthInvokeProbe(Probe):
    id = "asi02.unauth_invoke"
    asi_categories = ["ASI02"]
    severity = Severity.HIGH
    remediation = "Enforce authorization on privileged tools; reject calls lacking a valid principal."

    async def run(self, target: Target) -> ProbeResult:
        tools = {t["name"] for t in await target.list_tools()}
        observed: dict[str, str] = {}
        steps = []
        if PRIVILEGED_TOOL in tools:
            out = await target.call_tool(PRIVILEGED_TOOL, {})
            observed["response"] = out
            steps.append(ProbeStep(action=f"call {PRIVILEGED_TOOL} with no auth", detail={"args": {}}))
        return ProbeResult(self.id, self.asi_categories, steps=steps, observed=observed)

    def detector(self) -> Detector:
        return SubstringLeakDetector(needle=SECRET_MARKER, observed_key="response")
