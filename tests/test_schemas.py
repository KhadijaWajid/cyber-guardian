import pytest
from pydantic import ValidationError
from src.schemas import ThreatSignals, ThreatReport, SuspiciousUrl


def test_threat_signals_valid():
    signals = ThreatSignals(
        urgency_detected=True,
        urgency_explanation="Account locked within 24 hours.",
        sensitive_info_requested=True,
        sensitive_info_details=["password", "OTP"],
        impersonation_target="Netflix",
        suspicious_urls=[
            SuspiciousUrl(
                original_url="https://netflix-update.xyz",
                defanged_url="hxxps://netflix-update[.]xyz",
                risk_reason="Suspicious TLD and brand spoofing",
            )
        ],
        key_findings=["Urgency driver detected", "Phishing link detected"],
    )
    assert signals.urgency_detected is True
    assert signals.impersonation_target == "Netflix"
    assert len(signals.suspicious_urls) == 1
    assert signals.suspicious_urls[0].defanged_url == "hxxps://netflix-update[.]xyz"


def test_threat_report_valid_risks():
    signals = ThreatSignals(
        urgency_detected=False,
        sensitive_info_requested=False,
        key_findings=["No threats found"],
    )
    for risk in ["LOW", "MEDIUM", "HIGH"]:
        report = ThreatReport(
            overall_risk=risk,
            summary="Test summary explanation.",
            threat_signals=signals,
            recommended_actions=["DO delete if unknown"],
        )
        assert report.overall_risk == risk


def test_threat_report_invalid_risk_literal_raises():
    signals = ThreatSignals(
        urgency_detected=False,
        sensitive_info_requested=False,
        key_findings=["No threats found"],
    )
    # "CRITICAL" is not allowed by Literal["LOW", "MEDIUM", "HIGH"]
    with pytest.raises(ValidationError) as excinfo:
        ThreatReport(
            overall_risk="CRITICAL",  # Invalid literal
            summary="Invalid risk report",
            threat_signals=signals,
            recommended_actions=["DO nothing"],
        )
    assert "overall_risk" in str(excinfo.value)


def test_threat_signals_missing_required_fields_raises():
    with pytest.raises(ValidationError):
        # Missing required fields like urgency_detected, sensitive_info_requested, key_findings
        ThreatSignals()
