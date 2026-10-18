import pytest
from src.utils import parse_eml_bytes


def test_parse_eml_plain_text():
    eml_raw = (
        b"From: security-alert@paypal-update.com\r\n"
        b"Reply-To: attacker-inbox@mail-drop.ru\r\n"
        b"To: victim@example.com\r\n"
        b"Date: Sat, 17 Oct 2026 10:00:00 +0000\r\n"
        b"Subject: URGENT: Your PayPal account has been limited\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please click https://paypal-security.fake.com to restore access immediately."
    )

    parsed = parse_eml_bytes(eml_raw)

    assert "From: security-alert@paypal-update.com" in parsed
    assert "Reply-To: attacker-inbox@mail-drop.ru" in parsed
    assert "Subject: URGENT: Your PayPal account has been limited" in parsed
    assert "--- Body ---" in parsed
    assert "https://paypal-security.fake.com" in parsed


def test_parse_eml_html_multipart():
    eml_multipart = (
        b"From: support@bank.com\r\n"
        b"Subject: Statement Ready\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/alternative; boundary=\"BOUNDARY\"\r\n"
        b"\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Your statement is ready.\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<p>Your statement is <b>ready</b>.</p>\r\n"
        b"--BOUNDARY--"
    )

    parsed = parse_eml_bytes(eml_multipart)
    assert "From: support@bank.com" in parsed
    assert "Subject: Statement Ready" in parsed
    assert "Your statement is ready." in parsed
