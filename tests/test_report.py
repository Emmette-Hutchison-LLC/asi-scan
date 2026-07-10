import json

from asi_scan.models import Finding, ScanReport, Severity, Verdict, VerdictStatus
from asi_scan.report import to_json, to_markdown, to_sarif


def _report() -> ScanReport:
    f = Finding(
        probe_id="asi02.unauth_invoke",
        asi_categories=["ASI02"],
        severity=Severity.HIGH,
        verdict=Verdict(VerdictStatus.VULNERABLE, {"needle": "SECRET"}),
        remediation="require auth",
        target_ref="mock://vulnerable-mcp",
    )
    return ScanReport("mock://vulnerable-mcp", [f], "0.1.0")


def test_json_roundtrips():
    data = json.loads(to_json(_report()))
    assert data["findings"][0]["probe_id"] == "asi02.unauth_invoke"


def test_markdown_groups_by_asi():
    md = to_markdown(_report())
    assert "ASI02" in md
    assert "asi02.unauth_invoke" in md


def test_markdown_distinguishes_inconclusive_from_safe():
    def _f(status: VerdictStatus) -> Finding:
        return Finding(
            probe_id=f"p.{status.value.lower()}",
            asi_categories=["ASI02"],
            severity=Severity.HIGH,
            verdict=Verdict(status, {}),
            remediation="x",
            target_ref="mock://t",
        )

    md = to_markdown(ScanReport("mock://t", [_f(VerdictStatus.INCONCLUSIVE), _f(VerdictStatus.SAFE)], "0"))
    # INCONCLUSIVE and SAFE must not share the same marker (🟢 was previously used for both).
    inconclusive_line = next(ln for ln in md.splitlines() if "p.inconclusive" in ln)
    safe_line = next(ln for ln in md.splitlines() if "p.safe" in ln)
    assert "🟢" in safe_line
    assert "🟢" not in inconclusive_line


def test_sarif_has_one_result_per_vuln():
    sarif = json.loads(to_sarif(_report()))
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "asi02.unauth_invoke"
    assert results[0]["properties"]["asi_categories"] == ["ASI02"]
