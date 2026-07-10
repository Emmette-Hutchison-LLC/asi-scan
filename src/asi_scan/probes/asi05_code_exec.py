from __future__ import annotations

from asi_scan.detectors import Detector, RoundTripDetector
from asi_scan.models import ProbeResult, ProbeStep, Severity
from asi_scan.probes.base import Probe, register
from asi_scan.target import Target

EXEC_TOOL = "run"
CANARY = "CANARY-EXEC"
PAYLOAD = "echo hello; printf INJECTED"


@register
class ArgInjectionProbe(Probe):
    id = "asi05.arg_injection"
    asi_categories = ["ASI05"]
    severity = Severity.CRITICAL
    remediation = "Never pass tool arguments to a shell; use argument arrays and strict input validation."

    async def run(self, target: Target) -> ProbeResult:
        tools = {t["name"] for t in await target.list_tools()}
        observed: dict[str, str] = {}
        steps = []
        if EXEC_TOOL in tools:
            out = await target.call_tool(EXEC_TOOL, {"cmd": PAYLOAD})
            observed["response"] = out
            steps.append(ProbeStep(action=f"inject ';' segment into {EXEC_TOOL}", detail={"payload": PAYLOAD}))
        return ProbeResult(self.id, self.asi_categories, steps=steps, observed=observed)

    def detector(self) -> Detector:
        return RoundTripDetector(canary=CANARY, observed_key="response")
