from __future__ import annotations

from abc import ABC, abstractmethod

from asi_scan.detectors import Detector
from asi_scan.models import Finding, ProbeResult, Severity
from asi_scan.target import Target

REGISTRY: dict[str, type["Probe"]] = {}


class Probe(ABC):
    id: str
    asi_categories: list[str]
    severity: Severity
    remediation: str

    @abstractmethod
    async def run(self, target: Target) -> ProbeResult: ...

    @abstractmethod
    def detector(self) -> Detector: ...

    async def execute(self, target: Target) -> Finding:
        result = await self.run(target)
        verdict = self.detector().evaluate(result)
        return Finding(
            probe_id=self.id,
            asi_categories=self.asi_categories,
            severity=self.severity,
            verdict=verdict,
            remediation=self.remediation,
            target_ref=target.ref,
        )


def register(cls: type[Probe]) -> type[Probe]:
    REGISTRY[cls.id] = cls
    return cls


def probes_for(asi: str | None) -> list[type[Probe]]:
    if asi is None:
        return list(REGISTRY.values())
    return [c for c in REGISTRY.values() if asi in c.asi_categories]
