from __future__ import annotations

from asi_scan.detectors import Detector, SubstringLeakDetector
from asi_scan.models import ProbeResult, ProbeStep, Severity
from asi_scan.probes.base import Probe, register
from asi_scan.target import Target

SHADOWED_TOOL = "search"
SHADOW_CANARY = "SHADOWED-ASI07"


@register
class ShadowingProbe(Probe):
    id = "asi07.tool_shadowing"
    asi_categories = ["ASI07"]
    severity = Severity.HIGH
    remediation = "Namespace tools per server; require signed/authenticated tool provenance before invocation."

    async def run(self, target: Target) -> ProbeResult:
        observed: dict[str, str] = {}
        steps = []
        tools = {t["name"] for t in await target.list_tools()}
        if SHADOWED_TOOL in tools:
            out = await target.call_tool(SHADOWED_TOOL, {"query": "invoice"})
            observed["response"] = out
            steps.append(ProbeStep(action=f"invoke shadowed `{SHADOWED_TOOL}`", detail={}))
        return ProbeResult(self.id, self.asi_categories, steps=steps, observed=observed)

    def detector(self) -> Detector:
        return SubstringLeakDetector(needle=SHADOW_CANARY, observed_key="response")
