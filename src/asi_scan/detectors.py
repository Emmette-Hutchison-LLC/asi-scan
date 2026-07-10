from __future__ import annotations

from typing import Protocol

from asi_scan.models import ProbeResult, Verdict, VerdictStatus


class Detector(Protocol):
    def evaluate(self, result: ProbeResult) -> Verdict: ...


_ABSENT_REASON = "observed value absent — probe could not exercise the target"


class SubstringLeakDetector:
    def __init__(self, needle: str, observed_key: str) -> None:
        self.needle = needle
        self.observed_key = observed_key

    def evaluate(self, result: ProbeResult) -> Verdict:
        evidence = {"needle": self.needle, "observed_key": self.observed_key}
        if self.observed_key not in result.observed:
            return Verdict(
                status=VerdictStatus.INCONCLUSIVE,
                evidence={**evidence, "reason": _ABSENT_REASON},
            )
        leaked = self.needle in str(result.observed[self.observed_key])
        return Verdict(
            status=VerdictStatus.VULNERABLE if leaked else VerdictStatus.SAFE,
            evidence=evidence,
        )


class RoundTripDetector:
    def __init__(self, canary: str, observed_key: str) -> None:
        self.canary = canary
        self.observed_key = observed_key

    def evaluate(self, result: ProbeResult) -> Verdict:
        evidence = {"canary": self.canary, "observed_key": self.observed_key}
        if self.observed_key not in result.observed:
            return Verdict(
                status=VerdictStatus.INCONCLUSIVE,
                evidence={**evidence, "reason": _ABSENT_REASON},
            )
        seen = self.canary in str(result.observed[self.observed_key])
        return Verdict(
            status=VerdictStatus.VULNERABLE if seen else VerdictStatus.SAFE,
            evidence=evidence,
        )
