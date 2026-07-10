from __future__ import annotations

from asi_scan import __version__
from asi_scan.models import Finding, ScanReport, Verdict, VerdictStatus
from asi_scan.probes.base import Probe, probes_for
from asi_scan.target import Target


def _error_finding(probe: Probe, target: Target, exc: Exception) -> Finding:
    """Represent a probe that raised as an INCONCLUSIVE finding rather than
    letting it abort the whole scan."""
    return Finding(
        probe_id=probe.id,
        asi_categories=probe.asi_categories,
        severity=probe.severity,
        verdict=Verdict(
            status=VerdictStatus.INCONCLUSIVE,
            evidence={"error": str(exc), "error_type": type(exc).__name__},
        ),
        remediation=probe.remediation,
        target_ref=target.ref,
    )


async def scan(target: Target, asi: str | None = None) -> ScanReport:
    findings: list[Finding] = []
    for probe_cls in probes_for(asi):
        probe = probe_cls()
        try:
            findings.append(await probe.execute(target))
        except Exception as exc:  # isolate one probe's failure from the rest
            findings.append(_error_finding(probe, target, exc))
    return ScanReport(target_ref=target.ref, findings=findings, tool_version=__version__)
