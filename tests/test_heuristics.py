import json
import pytest
from src.heuristics import (
    levenshtein_distance,
    is_ip_host,
    is_high_risk_tld,
    check_typosquatting,
    analyze_url_heuristics,
    extract_urls,
    analyze_all_heuristics,
    TOP_TARGETED_BRANDS,
    HIGH_RISK_TLDS,
)
from src.exporter import (
    generate_stix_threat_bundle,
    generate_executive_html_report,
)
from src.schemas import ThreatSignals, ThreatReport, SuspiciousUrl, HeuristicResult


# ==============================================================================
# 1. Levenshtein Distance Algorithm Unit Tests
# ==============================================================================

def test_levenshtein_identical():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("", "") == 0


def test_levenshtein_single_substitution():
    # 1 edit: substitution '1' for 'l'
    assert levenshtein_distance("paypa1", "paypal") == 1
    # '0' for 'o'
    assert levenshtein_distance("wellsfarg0", "wellsfargo") == 1


def test_levenshtein_single_insertion_and_deletion():
    # insertion
    assert levenshtein_distance("paypals", "paypal") == 1
    # deletion
    assert levenshtein_distance("paypa", "paypal") == 1


def test_levenshtein_double_edit():
    # 'g00gle' vs 'google': 2 substitutions
    assert levenshtein_distance("g00gle", "google") == 2
    # 'wellsfarg00' vs 'wellsfargo': 2 edits
    assert levenshtein_distance("wellsfarg00", "wellsfargo") == 2


def test_levenshtein_distant_strings():
    assert levenshtein_distance("microsoft", "apple") > 3
    assert levenshtein_distance("paypal", "chase") > 3


# ==============================================================================
# 2. Raw IP Detection Tests
# ==============================================================================

def test_ip_detection_standard_ipv4():
    assert is_ip_host("192.168.1.1") is True
    assert is_ip_host("10.0.0.1") is True
    assert is_ip_host("172.16.254.1") is True


def test_ip_detection_ipv6():
    assert is_ip_host("2001:db8::1") is True
    assert is_ip_host("[2001:db8::1]") is True


def test_ip_detection_integer_decimal():
    # 2130706433 is 127.0.0.1
    assert is_ip_host("2130706433") is True


def test_ip_detection_hostname_not_ip():
    assert is_ip_host("google.com") is False
    assert is_ip_host("paypal.com") is False
    assert is_ip_host("phish-site.xyz") is False
    assert is_ip_host("") is False


# ==============================================================================
# 3. High-Risk TLD Tests
# ==============================================================================

def test_high_risk_tlds_flagged():
    for tld in [".xyz", ".top", ".click", ".buzz", ".fit", ".work", ".tk"]:
        flagged, matched = is_high_risk_tld(f"phishing-update{tld}")
        assert flagged is True
        assert matched == tld


def test_benign_standard_tlds_not_flagged():
    for domain in ["example.com", "mybank.org", "university.edu", "service.net", "company.co.uk"]:
        flagged, _ = is_high_risk_tld(domain)
        assert flagged is False


# ==============================================================================
# 4. Typosquatting & Brand Impersonation Tests
# ==============================================================================

def test_typosquatting_levenshtein_distance_1():
    target, reason = check_typosquatting("paypa1.com")
    assert target == "paypal"
    assert "paypa1" in reason

    target2, reason2 = check_typosquatting("wellsfarg0.com")
    assert target2 == "wells fargo"
    assert "wellsfarg0" in reason2


def test_typosquatting_levenshtein_distance_2():
    target, reason = check_typosquatting("g00gle.com")
    assert target == "google"
    assert "g00gle" in reason


def test_typosquatting_subdomain_spoofing():
    # Brand appears as a subdomain on untrusted apex domain
    target, reason = check_typosquatting("paypal.verify-account.com")
    assert target == "paypal"
    assert "subdomain" in reason.lower()

    target2, reason2 = check_typosquatting("wellsfargo-security-alert.verify-account88.com")
    assert target2 == "wells fargo"


def test_typosquatting_embedded_brand_in_domain():
    target, reason = check_typosquatting("paypal-security.com")
    assert target == "paypal"
    assert "paypal" in reason.lower()


def test_legitimate_domains_never_flagged():
    # paypal.com and subdomains of paypal.com should not be flagged
    assert check_typosquatting("paypal.com") == (None, None)
    assert check_typosquatting("www.paypal.com") == (None, None)
    assert check_typosquatting("login.paypal.com") == (None, None)

    # wellsfargo.com
    assert check_typosquatting("wellsfargo.com") == (None, None)
    assert check_typosquatting("connect.wellsfargo.com") == (None, None)

    # google.com
    assert check_typosquatting("google.com") == (None, None)
    assert check_typosquatting("accounts.google.com") == (None, None)


# ==============================================================================
# 5. Full URL Heuristics Analysis Tests
# ==============================================================================

def test_analyze_url_heuristics_high_severity_typosquat():
    res = analyze_url_heuristics("https://paypa1.com/signin")
    assert res["severity"] == "HIGH"
    assert res["typosquat_target"] == "paypal"
    assert res["defanged_url"] == "hxxps://paypa1[.]com/signin"
    assert any("Typosquatting" in f for f in res["findings"])


def test_analyze_url_heuristics_high_severity_ip():
    res = analyze_url_heuristics("http://192.168.1.1:8080/auth")
    assert res["severity"] == "HIGH"
    assert res["is_ip_address"] is True
    assert res["defanged_url"] == "hxxp://192[.]168[.]1[.]1:8080/auth"
    assert any("raw numeric IP" in f for f in res["findings"])


def test_analyze_url_heuristics_medium_severity_tld():
    res = analyze_url_heuristics("https://unrelated-domain.xyz/page")
    assert res["severity"] == "MEDIUM"
    assert res["is_high_risk_tld"] is True
    assert res["typosquat_target"] is None


def test_analyze_url_heuristics_low_severity_benign():
    res = analyze_url_heuristics("https://www.google.com/search")
    assert res["severity"] == "LOW"
    assert res["is_ip_address"] is False
    assert res["is_high_risk_tld"] is False
    assert res["typosquat_target"] is None
    assert any("No static heuristic red flags" in f for f in res["findings"])


def test_analyze_url_heuristics_empty():
    res = analyze_url_heuristics("")
    assert res["severity"] == "LOW"
    assert res["original_url"] == ""


# ==============================================================================
# 6. Extract URLs From Raw Text Tests
# ==============================================================================

def test_extract_urls_from_text():
    sample = (
        "Check your account at https://paypa1.com/login immediately. "
        "Also visit http://192.168.1.5/portal or google.com."
    )
    urls = extract_urls(sample)
    assert "https://paypa1.com/login" in urls
    assert "http://192.168.1.5/portal" in urls


def test_analyze_all_heuristics_batch():
    sample = "Click https://paypa1.com and https://wellsfargo.com"
    results = analyze_all_heuristics(sample)
    assert len(results) == 2
    targets = [r["typosquat_target"] for r in results]
    assert "paypal" in targets
    assert None in targets  # legitimate wellsfargo has None


# ==============================================================================
# 7. STIX 2.1 Threat Intel Bundle Exporter Tests
# ==============================================================================

def test_stix_threat_bundle_structure():
    signals = ThreatSignals(
        urgency_detected=True,
        urgency_explanation="Account locked in 2 hours",
        sensitive_info_requested=True,
        sensitive_info_details=["password", "OTP"],
        impersonation_target="Wells Fargo",
        suspicious_urls=[
            SuspiciousUrl(
                original_url="https://wellsfargo-verify.click/login",
                defanged_url="hxxps://wellsfargo-verify[.]click/login",
                risk_reason="Brand spoofing and high risk TLD",
            )
        ],
        key_findings=["Artificial urgency", "Spoofed banking domain"],
    )
    report = ThreatReport(
        overall_risk="HIGH",
        summary="Wells Fargo phishing attempt soliciting banking credentials.",
        threat_signals=signals,
        recommended_actions=[
            "DO NOT click the link.",
            "DO contact Wells Fargo fraud desk directly.",
        ],
    )

    bundle = generate_stix_threat_bundle(report, raw_text="Sample message text")

    # STIX 2.1 bundle requirements
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert isinstance(bundle["objects"], list)

    sdo_types = [obj["type"] for obj in bundle["objects"]]
    assert "identity" in sdo_types
    assert "indicator" in sdo_types
    assert "course-of-action" in sdo_types
    assert "malware-analysis" in sdo_types

    # Validate indicator SDO attributes
    indicator = next(obj for obj in bundle["objects"] if obj["type"] == "indicator")
    assert indicator["spec_version"] == "2.1"
    assert indicator["pattern_type"] == "stix"
    assert "[url:value =" in indicator["pattern"] or "[ipv4-addr:value =" in indicator["pattern"]
    assert "malicious-activity" in indicator["indicator_types"]

    # Validate malware-analysis SDO
    analysis = next(obj for obj in bundle["objects"] if obj["type"] == "malware-analysis")
    assert analysis["result"] == "malicious"
    assert analysis["product"] == "Cyber Guardian Static & LLM Security Engine"


# ==============================================================================
# 8. Executive Forensic HTML Report Exporter Tests
# ==============================================================================

def test_executive_html_report_generation():
    signals = ThreatSignals(
        urgency_detected=True,
        urgency_explanation="2 hour timer",
        sensitive_info_requested=True,
        sensitive_info_details=["password"],
        impersonation_target="PayPal",
        suspicious_urls=[],
        key_findings=["Credential harvesting"],
    )
    report = ThreatReport(
        overall_risk="HIGH",
        summary="Phishing attempt targeting PayPal credentials.",
        threat_signals=signals,
        recommended_actions=["DO NOT enter password."],
    )

    heuristics = [
        analyze_url_heuristics("https://paypa1.com/login"),
    ]

    html_out = generate_executive_html_report(
        report=report,
        heuristics_results=heuristics,
        raw_text="URGENT: Click https://paypa1.com/login",
    )

    assert "<!DOCTYPE html>" in html_out
    assert "Cyber Guardian Executive Incident Report" in html_out
    # Must have high-contrast @media print
    assert "@media print" in html_out
    # Must have print/PDF trigger button
    assert "window.print()" in html_out
    # Must contain defanged URL and plain-English summary
    assert "hxxps://paypa1[.]com/login" in html_out
    assert "Phishing attempt targeting PayPal credentials." in html_out


# ==============================================================================
# 9. ThreatSignals Schema Integration Test
# ==============================================================================

def test_threat_signals_schema_with_heuristics():
    heuristics_item = {
        "original_url": "https://paypa1.xyz",
        "defanged_url": "hxxps://paypa1[.]xyz",
        "is_ip_address": False,
        "is_high_risk_tld": True,
        "typosquat_target": "paypal",
        "severity": "HIGH",
        "findings": ["High risk TLD", "Typosquatting"],
    }
    signals = ThreatSignals(
        urgency_detected=False,
        sensitive_info_requested=False,
        key_findings=["Test"],
        heuristics_results=[heuristics_item],
    )
    assert len(signals.heuristics_results) == 1
    assert isinstance(signals.heuristics_results[0], HeuristicResult)
    assert signals.heuristics_results[0].typosquat_target == "paypal"
    dumped = signals.model_dump()
    assert "heuristics_results" in dumped
    assert dumped["heuristics_results"][0]["severity"] == "HIGH"
