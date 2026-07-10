from __future__ import annotations

from asi_scan.detectors import Detector, RoundTripDetector
from asi_scan.models import ProbeResult, ProbeStep, Severity
from asi_scan.probes.base import Probe, register
from asi_scan.target import Target

WRITE_TOOL = "save_note"
READ_TOOL = "get_notes"
# Detect whether the *raw* markup round-trips. The hardened server escapes "<" -> "&lt;",
# so the exact INJECTION substring only survives when the store is unsanitized (the vuln).
# (Do NOT key on the bare token "INJECTED-ASI06" -- that has no "<" and survives escaping,
#  which would make the hardened server look vulnerable.)
INJECTION = "<img src=x onerror=INJECTED-ASI06>"


@register
class MemoryPoisonProbe(Probe):
    id = "asi06.memory_poisoning"
    asi_categories = ["ASI06"]
    severity = Severity.HIGH
    remediation = "Sanitize/encode content on write and on read; treat stored memory as untrusted input."

    async def run(self, target: Target) -> ProbeResult:
        tools = {t["name"] for t in await target.list_tools()}
        observed: dict[str, str] = {}
        steps = []
        if WRITE_TOOL in tools and READ_TOOL in tools:
            await target.call_tool(WRITE_TOOL, {"text": INJECTION})
            steps.append(ProbeStep(action=f"write poisoned note via {WRITE_TOOL}", detail={"payload": INJECTION}))
            later = await target.call_tool(READ_TOOL, {})
            observed["later"] = later
            steps.append(ProbeStep(action=f"re-read via {READ_TOOL} (separate turn)", detail={}))
        return ProbeResult(self.id, self.asi_categories, steps=steps, observed=observed)

    def detector(self) -> Detector:
        return RoundTripDetector(canary=INJECTION, observed_key="later")
