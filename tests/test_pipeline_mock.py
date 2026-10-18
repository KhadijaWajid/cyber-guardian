import os
import json
import pytest
from unittest.mock import MagicMock
from src.analyzer import analyze_text
from src.advisor import generate_advice
from src.schemas import ThreatSignals, ThreatReport


@pytest.fixture
def mock_analyzer_json():
    return json.dumps({
        "urgency_detected": True,
        "urgency_explanation": "Demands verification within 1 hour.",
        "sensitive_info_requested": True,
        "sensitive_info_details": ["Credit Card Number", "CVV"],
        "impersonation_target": "Amazon",
        "suspicious_urls": [
            {
                "original_url": "https://amazon-orders.fraudulent-link.com/auth",
                "defanged_url": "https://amazon-orders.fraudulent-link.com/auth",  # Un-defanged, to verify post-processing
                "risk_reason": "Spoofed brand domain on third-party host"
            }
        ],
        "key_findings": [
            "High urgency timer detected",
            "Credit card data requested via untrusted link"
        ],
        "disclaimer": "Automated scan disclaimer"
    })


@pytest.fixture
def mock_advisor_json():
    return json.dumps({
        "overall_risk": "HIGH",
        "summary": "Someone is pretending to be Amazon to trick you into entering your credit card number.",
        "threat_signals": {
            "urgency_detected": True,
            "urgency_explanation": "Demands verification within 1 hour.",
            "sensitive_info_requested": True,
            "sensitive_info_details": ["Credit Card Number", "CVV"],
            "impersonation_target": "Amazon",
            "suspicious_urls": [],
            "key_findings": ["High urgency timer detected"],
            "disclaimer": "Automated scan disclaimer"
        },
        "recommended_actions": [
            "DO NOT click on the link or submit credit card info.",
            "DO check your Amazon orders directly via the official Amazon app.",
            "DO report and delete the message."
        ],
        "disclaimer": "Standard safety disclaimer"
    })


def test_analyzer_mocked(mock_analyzer_json):
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = mock_analyzer_json
    mock_client.models.generate_content.return_value = mock_response

    signals = analyze_text("Sample suspicious text", client=mock_client)

    assert isinstance(signals, ThreatSignals)
    assert signals.urgency_detected is True
    assert signals.impersonation_target == "Amazon"
    assert "Credit Card Number" in signals.sensitive_info_details
    # Verify defensive defanging was applied
    assert len(signals.suspicious_urls) == 1
    assert signals.suspicious_urls[0].defanged_url == "hxxps://amazon-orders[.]fraudulent-link[.]com/auth"
    assert mock_client.models.generate_content.called


def test_advisor_mocked(mock_advisor_json):
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = mock_advisor_json
    mock_client.models.generate_content.return_value = mock_response

    input_signals = ThreatSignals(
        urgency_detected=True,
        sensitive_info_requested=True,
        key_findings=["Test red flag"],
    )

    report = generate_advice(input_signals, client=mock_client)

    assert isinstance(report, ThreatReport)
    assert report.overall_risk == "HIGH"
    assert "Amazon" in report.summary
    assert len(report.recommended_actions) == 3
    assert report.threat_signals == input_signals
    assert mock_client.models.generate_content.called


def test_end_to_end_pipeline_mocked(mock_analyzer_json, mock_advisor_json):
    """Verifies analyzer -> advisor flow end-to-end with mocked LLM calls."""
    mock_client = MagicMock()

    # Return analyzer JSON on first call, advisor JSON on second call
    resp1 = MagicMock()
    resp1.text = mock_analyzer_json
    resp2 = MagicMock()
    resp2.text = mock_advisor_json
    mock_client.models.generate_content.side_effect = [resp1, resp2]

    # Stage 1: Security Analyzer Agent
    signals = analyze_text("Suspicious phishing email text", client=mock_client)
    assert signals.urgency_detected is True
    assert signals.impersonation_target == "Amazon"

    # Stage 2: Safety Advisor Agent
    report = generate_advice(signals, client=mock_client)
    assert report.overall_risk == "HIGH"
    assert report.threat_signals.impersonation_target == "Amazon"
    assert any("DO NOT" in action for action in report.recommended_actions)

    assert mock_client.models.generate_content.call_count == 2


def test_503_unavailable_triggers_retry_and_succeeds():
    from src.utils import generate_with_fallback
    from google.genai import types

    mock_client = MagicMock()
    success_resp = MagicMock()
    success_resp.text = "success"

    # First call raises 503 UNAVAILABLE, second call succeeds
    mock_client.models.generate_content.side_effect = [
        Exception("503 UNAVAILABLE: Model experiencing high demand"),
        success_resp,
    ]

    res = generate_with_fallback(
        client=mock_client,
        contents="ping",
        config=types.GenerateContentConfig(),
        model_chain=["gemini-test-primary"],
        backoff_delays=[0.01],  # fast backoff for tests
    )

    assert res == success_resp
    assert mock_client.models.generate_content.call_count == 2


def test_model_fallback_chain_on_persistent_failure():
    from src.utils import generate_with_fallback
    from google.genai import types

    mock_client = MagicMock()
    success_resp = MagicMock()
    success_resp.text = "fallback_success"

    # Primary model fails on both initial and retry attempts; fallback model succeeds
    mock_client.models.generate_content.side_effect = [
        Exception("503 UNAVAILABLE"),
        Exception("503 UNAVAILABLE"),
        success_resp,
    ]

    res = generate_with_fallback(
        client=mock_client,
        contents="ping",
        config=types.GenerateContentConfig(),
        model_chain=["gemini-primary", "gemini-secondary"],
        backoff_delays=[0.01],
    )

    assert res == success_resp
    # 2 calls on primary, 1 on secondary
    assert mock_client.models.generate_content.call_count == 3


def test_all_fallback_models_fail_raises_runtime_error():
    from src.utils import generate_with_fallback
    from google.genai import types

    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception("503 UNAVAILABLE")

    with pytest.raises(RuntimeError) as excinfo:
        generate_with_fallback(
            client=mock_client,
            contents="ping",
            config=types.GenerateContentConfig(),
            model_chain=["model-a", "model-b"],
            backoff_delays=[0.01],
        )

    assert "All models in fallback chain" in str(excinfo.value)


def test_429_rate_limit_swaps_to_backup_key(monkeypatch):
    import os
    from src.utils import generate_with_fallback
    from google.genai import types

    monkeypatch.setenv("GEMINI_API_KEY", "primary-key-123")
    monkeypatch.setenv("GEMINI_API_KEY_BACKUP", "backup-key-456")

    mock_client = MagicMock()
    success_resp = MagicMock()
    success_resp.text = "recovered_with_backup"

    # First call raises 429 Rate Limit, second call succeeds with backup key
    mock_client.models.generate_content.side_effect = [
        Exception("429 RESOURCE_EXHAUSTED: Rate limit exceeded for quota"),
        success_resp,
    ]

    res = generate_with_fallback(
        client=mock_client,
        contents="ping",
        config=types.GenerateContentConfig(),
        model_chain=["gemini-primary"],
        backoff_delays=[0.01],
    )

    assert res == success_resp
    assert mock_client.models.generate_content.call_count == 2
    # Verify GEMINI_API_KEY was swapped to GEMINI_API_KEY_BACKUP
    assert os.getenv("GEMINI_API_KEY") == "backup-key-456"


def test_default_model_chain_values():
    from src.utils import DEFAULT_MODEL_CHAIN
    from src.analyzer import ANALYZER_MODEL_CHAIN
    from src.honeypot import HONEYPOT_MODEL_CHAIN
    from src.advisor import ADVISOR_MODEL_CHAIN

    expected = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
    assert DEFAULT_MODEL_CHAIN == expected
    assert ANALYZER_MODEL_CHAIN == expected
    assert HONEYPOT_MODEL_CHAIN == expected
    assert ADVISOR_MODEL_CHAIN == expected


def test_404_not_found_immediately_falls_forward_to_next_model():
    from src.utils import generate_with_fallback
    from google.genai import types

    mock_client = MagicMock()
    success_resp = MagicMock()
    success_resp.text = "active_model_success"

    # Primary model returns 404 deprecated/retired; secondary model succeeds immediately
    mock_client.models.generate_content.side_effect = [
        Exception("404 NOT_FOUND: This model models/gemini-retired-model is no longer available to new users."),
        success_resp,
    ]

    res = generate_with_fallback(
        client=mock_client,
        contents="ping",
        config=types.GenerateContentConfig(),
        model_chain=["gemini-retired-model", "gemini-2.0-flash"],
        backoff_delays=[1.0, 2.0],
    )

    assert res == success_resp
    # Exactly 2 calls: 1 on deprecated model (no wasteful retries), 1 on fallback model
    assert mock_client.models.generate_content.call_count == 2


def test_get_api_key_from_env(monkeypatch):
    from src.app import get_api_key

    monkeypatch.setenv("GEMINI_API_KEY", "test-env-key-789")
    assert get_api_key() == "test-env-key-789"


def test_get_api_key_from_secrets(monkeypatch):
    import streamlit as st
    from src.app import get_api_key

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(st, "secrets", {"GEMINI_API_KEY": "test-secret-key-456"})
    assert get_api_key() == "test-secret-key-456"


def test_get_api_key_none_when_empty(monkeypatch):
    import streamlit as st
    from src.app import get_api_key

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(st, "secrets", {})
    assert get_api_key() is None


def test_analyzer_get_genai_client_with_secrets_fallback(monkeypatch):
    import streamlit as st
    from src.analyzer import get_genai_client

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(st, "secrets", {"GEMINI_API_KEY": "test-genai-secret-key"})
    client = get_genai_client()
    assert client is not None
    assert os.getenv("GEMINI_API_KEY") == "test-genai-secret-key"


def test_preset_lures_configured():
    from src.app import (
        SAMPLE_PHISHING,
        SAMPLE_FAMILY_EMERGENCY,
        SAMPLE_DISCOUNT,
        SAMPLE_BENIGN,
    )

    assert len(SAMPLE_PHISHING) > 0
    assert "https://" in SAMPLE_PHISHING
    assert len(SAMPLE_FAMILY_EMERGENCY) > 0
    assert len(SAMPLE_DISCOUNT) > 0
    assert len(SAMPLE_BENIGN) > 0


def test_analyzer_429_quota_exhausted_heuristic_fallback():
    """Verifies that 429 Rate Limit / Quota Exceeded does not raise and returns heuristic fallback signals."""
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception(
        "429 RESOURCE_EXHAUSTED: Rate limit exceeded for quota metric 'Generate Content API'"
    )

    sample = (
        "URGENT: Your account has been locked. Verify immediately at "
        "http://wells-fargo-security.update-account.com/login and input your password and OTP."
    )

    signals = analyze_text(sample, client=mock_client)

    assert isinstance(signals, ThreatSignals)
    assert signals.is_fallback is True
    assert signals.urgency_detected is True
    assert signals.sensitive_info_requested is True
    assert len(signals.suspicious_urls) > 0
    assert "hxxp://" in signals.suspicious_urls[0].defanged_url
    assert "[.]" in signals.suspicious_urls[0].defanged_url
    assert any("Heuristic Offline Mode Active" in kf for kf in signals.key_findings)


def test_advisor_429_quota_exhausted_heuristic_fallback():
    """Verifies that 429 Rate Limit in advisor does not raise and returns heuristic report."""
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception(
        "429 RESOURCE_EXHAUSTED: Quota exceeded"
    )

    input_signals = ThreatSignals(
        urgency_detected=True,
        urgency_explanation="Immediate action required",
        sensitive_info_requested=True,
        sensitive_info_details=["password", "OTP"],
        impersonation_target="Bank",
        key_findings=["Urgent password request"],
    )

    report = generate_advice(input_signals, client=mock_client)

    assert isinstance(report, ThreatReport)
    assert report.is_fallback is True
    assert report.overall_risk == "HIGH"
    assert len(report.recommended_actions) > 0
    assert any("DO NOT" in act for act in report.recommended_actions)


def test_end_to_end_pipeline_with_429_quota_exhaustion():
    """Verifies that full analyzer -> advisor pipeline succeeds seamlessly under 429 quota exhaustion."""
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception(
        "429 RESOURCE_EXHAUSTED: Quota exhausted on free tier"
    )

    sample = (
        "URGENT: Immediate action required! Your Chase account will be suspended within 2 hours. "
        "Visit http://chase-security-alert.xyz/verify and submit your 6-digit OTP."
    )

    signals = analyze_text(sample, client=mock_client)
    assert signals.is_fallback is True

    report = generate_advice(signals, client=mock_client)
    assert report.is_fallback is True
    assert report.overall_risk == "HIGH"
    assert "DO NOT" in " ".join(report.recommended_actions)





