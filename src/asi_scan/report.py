from __future__ import annotations

import json
from collections import defaultdict

from asi_scan.models import ScanReport, Severity, VerdictStatus

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


_MARK = {
    VerdictStatus.VULNERABLE: "🔴",
    VerdictStatus.SAFE: "🟢",
    VerdictStatus.INCONCLUSIVE: "⚪",
}


def to_markdown(report: ScanReport) -> str:
    by_asi: dict[str, list[str]] = defaultdict(list)
    for f in report.findings:
        for asi in f.asi_categories:
            mark = _MARK[f.verdict.status]
            by_asi[asi].append(
                f"- {mark} `{f.probe_id}` ({f.verdict.status.value}) — {f.remediation}"
            )
    lines = ["# asi-scan report", "", f"**Target:** `{report.target_ref}`", ""]
    for asi in sorted(by_asi):
        lines.append(f"## {asi}")
        lines.extend(by_asi[asi])
        lines.append("")
    return "\n".join(lines)


def to_sarif(report: ScanReport) -> str:
    results = [
        {
            "ruleId": f.probe_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.probe_id}: {f.verdict.status.value}"},
            "properties": {"asi_categories": f.asi_categories, "evidence": f.verdict.evidence},
        }
        for f in report.findings
        if f.verdict.status is VerdictStatus.VULNERABLE
    ]
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "asi-scan", "version": report.tool_version}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
