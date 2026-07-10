from __future__ import annotations

from asi_scan import __version__
from asi_scan.models import ScanReport
from asi_scan.probes.base import probes_for
from asi_scan.target import Target


async def scan(target: Target, asi: str | None = None) -> ScanReport:
    findings = []
    for probe_cls in probes_for(asi):
        findings.append(await probe_cls().execute(target))
    return ScanReport(target_ref=target.ref, findings=findings, tool_version=__version__)
