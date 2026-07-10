from __future__ import annotations

from typing import Protocol

from asi_scan.models import ProbeResult, Verdict, VerdictStatus


class Detector(Protocol):
    def evaluate(self, result: ProbeResult) -> Verdict: ...


class SubstringLeakDetector:
    def __init__(self, needle: str, observed_key: str) -> None:
        self.needle = needle
        self.observed_key = observed_key

    def evaluate(self, result: ProbeResult) -> Verdict:
        haystack = str(result.observed.get(self.observed_key, ""))
        leaked = self.needle in haystack
        return Verdict(
            status=VerdictStatus.VULNERABLE if leaked else VerdictStatus.SAFE,
            evidence={"needle": self.needle, "observed_key": self.observed_key},
        )


class RoundTripDetector:
    def __init__(self, canary: str, observed_key: str) -> None:
        self.canary = canary
        self.observed_key = observed_key

    def evaluate(self, result: ProbeResult) -> Verdict:
        seen = self.canary in str(result.observed.get(self.observed_key, ""))
        return Verdict(
            status=VerdictStatus.VULNERABLE if seen else VerdictStatus.SAFE,
            evidence={"canary": self.canary, "observed_key": self.observed_key},
        )
