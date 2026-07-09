from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class VerdictStatus(str, Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    INCONCLUSIVE = "INCONCLUSIVE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Verdict:
    status: VerdictStatus
    evidence: dict[str, Any]
    confidence: float = 1.0


@dataclass
class ProbeStep:
    action: str
    detail: dict[str, Any]


@dataclass
class ProbeResult:
    probe_id: str
    asi_categories: list[str]
    steps: list[ProbeStep] = field(default_factory=list)
    observed: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    probe_id: str
    asi_categories: list[str]
    severity: Severity
    verdict: Verdict
    remediation: str
    target_ref: str


@dataclass
class ScanReport:
    target_ref: str
    findings: list[Finding]
    tool_version: str

    def pass_rate_by_asi(self) -> dict[str, float]:
        totals: dict[str, int] = {}
        safe: dict[str, int] = {}
        for f in self.findings:
            for asi in f.asi_categories:
                totals[asi] = totals.get(asi, 0) + 1
                if f.verdict.status is VerdictStatus.SAFE:
                    safe[asi] = safe.get(asi, 0) + 1
        return {asi: safe.get(asi, 0) / totals[asi] for asi in totals}

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_ref": self.target_ref,
            "tool_version": self.tool_version,
            "pass_rate_by_asi": self.pass_rate_by_asi(),
            "findings": [asdict(f) for f in self.findings],
        }
