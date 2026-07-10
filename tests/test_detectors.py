from asi_scan.detectors import RoundTripDetector, SubstringLeakDetector
from asi_scan.models import ProbeResult, VerdictStatus


def _result(observed: dict) -> ProbeResult:
    return ProbeResult(probe_id="p", asi_categories=["ASI02"], observed=observed)


def test_substring_leak_flags_when_present():
    d = SubstringLeakDetector(needle="SECRET", observed_key="response")
    v = d.evaluate(_result({"response": "here is the SECRET-x"}))
    assert v.status is VerdictStatus.VULNERABLE
    assert v.evidence["needle"] == "SECRET"


def test_substring_leak_safe_when_absent():
    d = SubstringLeakDetector(needle="SECRET", observed_key="response")
    v = d.evaluate(_result({"response": "access denied"}))
    assert v.status is VerdictStatus.SAFE


def test_round_trip_flags_canary():
    d = RoundTripDetector(canary="CANARY-EXEC", observed_key="later")
    v = d.evaluate(_result({"later": "...CANARY-EXEC..."}))
    assert v.status is VerdictStatus.VULNERABLE
