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
    assert DEFAULT_MODEL_CHAIN == ["gemini-3.8-flash", "gemini-3.1-pro-preview"]


def test_404_not_found_immediately_falls_forward_to_next_model():
    from src.utils import generate_with_fallback
    from google.genai import types

    mock_client = MagicMock()
    success_resp = MagicMock()
    success_resp.text = "active_model_success"

    # Primary model returns 404 deprecated/retired; secondary model succeeds immediately
    mock_client.models.generate_content.side_effect = [
        Exception("404 NOT_FOUND: This model models/gemini-2.5-flash is no longer available to new users."),
        success_resp,
    ]

    res = generate_with_fallback(
        client=mock_client,
        contents="ping",
        config=types.GenerateContentConfig(),
        model_chain=["gemini-2.5-flash", "gemini-3.8-flash"],
        backoff_delays=[1.0, 2.0],
    )

    assert res == success_resp
    # Exactly 2 calls: 1 on deprecated model (no wasteful retries), 1 on fallback model
    assert mock_client.models.generate_content.call_count == 2



