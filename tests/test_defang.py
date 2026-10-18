import pytest
from src.utils import defang_url


def test_defang_https_url():
    raw = "https://paypal-security.fake-domain.com/login"
    expected = "hxxps://paypal-security[.]fake-domain[.]com/login"
    assert defang_url(raw) == expected


def test_defang_http_url():
    raw = "http://insecure-phish.net/verify"
    expected = "hxxp://insecure-phish[.]net/verify"
    assert defang_url(raw) == expected


def test_defang_naked_domain():
    raw = "malicious-bank.xyz"
    expected = "malicious-bank[.]xyz"
    assert defang_url(raw) == expected


def test_defang_already_defanged():
    raw = "hxxps://safe-defanged[.]com"
    # Should not double defang dots into [[.]]
    assert defang_url(raw) == "hxxps://safe-defanged[.]com"


def test_defang_empty_or_none():
    assert defang_url("") == ""
    assert defang_url(None) == ""


def test_no_active_probing_or_network(monkeypatch):
    """Ensure defanging performs zero network calls or socket connections."""
    import socket

    def mock_socket_forbidden(*args, **kwargs):
        raise RuntimeError("Network probe attempted during defanging!")

    monkeypatch.setattr(socket, "socket", mock_socket_forbidden)
    # Defanging suspicious link must be strictly static string manipulation
    result = defang_url("https://evil-hacker.top/steal")
    assert result == "hxxps://evil-hacker[.]top/steal"


def test_highlight_evidence_color_chips():
    from src.utils import highlight_evidence
    from src.schemas import ThreatSignals, SuspiciousUrl

    signals = ThreatSignals(
        urgency_detected=True,
        sensitive_info_requested=True,
        sensitive_info_details=["password", "6-digit OTP"],
        suspicious_urls=[
            SuspiciousUrl(
                original_url="https://fake-login.com",
                defanged_url="hxxps://fake-login[.]com",
                risk_reason="Phishing",
            )
        ],
        key_findings=["Urgency", "Credential harvesting"],
    )

    text = "URGENT: Please enter your password and OTP at https://fake-login.com immediately."
    highlighted = highlight_evidence(text, signals)

    # Check chips are present
    assert 'class="chip-urgency"' in highlighted
    assert 'class="chip-sensitive"' in highlighted
    assert 'class="chip-url"' in highlighted
    # Check words are wrapped
    assert ">URGENT<" in highlighted
    assert ">password<" in highlighted
    assert ">https://fake-login.com<" in highlighted


def test_highlight_evidence_no_urls():
    """Ensure highlight_evidence does not raise IndexError when suspicious_urls is empty."""
    from src.utils import highlight_evidence
    from src.schemas import ThreatSignals

    signals = ThreatSignals(
        urgency_detected=True,
        sensitive_info_requested=True,
        sensitive_info_details=["social security number", "pin"],
        suspicious_urls=[],
        key_findings=["Urgency driver", "Credential harvesting"],
    )

    text = "IMMEDIATELY send your pin and social security number or account will be suspended."
    # Should not raise IndexError: no such group
    highlighted = highlight_evidence(text, signals)

    assert 'class="chip-urgency"' in highlighted
    assert 'class="chip-sensitive"' in highlighted
    assert 'class="chip-url"' not in highlighted
    assert ">IMMEDIATELY<" in highlighted or ">immediately<" in highlighted.lower()
    assert ">pin<" in highlighted.lower()


def test_highlight_evidence_benign():
    """Ensure highlight_evidence gracefully formats text with zero signals."""
    from src.utils import highlight_evidence
    from src.schemas import ThreatSignals

    signals = ThreatSignals(
        urgency_detected=False,
        sensitive_info_requested=False,
        sensitive_info_details=[],
        suspicious_urls=[],
        key_findings=[],
    )

    text = "Hello Team,\nPlease review the minutes from our meeting.\nBest regards."
    highlighted = highlight_evidence(text, signals)

    assert "chip-" not in highlighted
    assert "<br>" in highlighted
    assert "Hello Team," in highlighted

