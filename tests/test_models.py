from asi_scan.models import (
    Finding, ProbeResult, ScanReport, Severity, Verdict, VerdictStatus,  # noqa: F401
)


def _finding(asi: str, status: VerdictStatus) -> Finding:
    return Finding(
        probe_id=f"probe.{asi.lower()}",
        asi_categories=[asi],
        severity=Severity.HIGH,
        verdict=Verdict(status=status, evidence={"k": "v"}),
        remediation="fix it",
        target_ref="mock://vuln",
    )


def test_pass_rate_by_asi_counts_safe_over_total():
    report = ScanReport(
        target_ref="mock://vuln",
        findings=[
            _finding("ASI02", VerdictStatus.VULNERABLE),
            _finding("ASI02", VerdictStatus.SAFE),
            _finding("ASI06", VerdictStatus.SAFE),
        ],
        tool_version="0.1.0",
    )
    rates = report.pass_rate_by_asi()
    assert rates["ASI02"] == 0.5
    assert rates["ASI06"] == 1.0


def test_to_dict_is_json_serializable():
    import json
    report = ScanReport("mock://vuln", [_finding("ASI02", VerdictStatus.VULNERABLE)], "0.1.0")
    json.dumps(report.to_dict())  # must not raise
