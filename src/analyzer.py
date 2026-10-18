import os
import sys
import re
import json
import logging
import argparse
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv
from google import genai
from google.genai import types

from src.schemas import ThreatSignals, HeuristicResult, SuspiciousUrl
from src.utils import defang_url, generate_with_fallback, is_rate_limit_error
from src.heuristics import extract_urls, analyze_url_heuristics, TOP_TARGETED_BRANDS

load_dotenv()
logger = logging.getLogger("cyber_guardian.analyzer")

ANALYZER_MODEL_CHAIN: List[str] = [
    "gemini-2.5-flash",
    "gemini-3.8-flash",
]


ANALYZER_SYSTEM_INSTRUCTION = """
You are the Security Analyzer Agent in the Cyber Guardian cyber safety system.
Your job is to perform strict static analysis on user-submitted text (such as emails, SMS messages, or suspicious links).

Tasks:
1. Extract technical markers:
   - Identify any links, domains, or IP addresses.
   - Look for typosquatting, suspicious TLDs, mismatched branding, and obfuscation techniques.
   - Always defang URLs in the format 'hxxps://domain[.]com' or 'hxxp://domain[.]com'.
2. Identify behavioral red flags:
   - Detect urgency and panic drivers (e.g., 'Account will be permanently closed in 24 hours').
   - Detect credential or sensitive data harvesting (requests for passwords, OTPs, PINs, SSNs, credit card numbers).
   - Detect impersonation of trusted brands, banks, employers, or government agencies.
   - Detect Family Emergency Impersonation & Account Takeover (e.g., 'my phone broke, this is my temporary number', 'stranded abroad/at the airport', 'urgent medical bill', asking for wire, gift cards, or crypto). Set family_emergency_flag=True, populate family_emergency_details, and set is_account_takeover_likely=True if an existing friend/family relationship appears compromised or spoofed.
   - For family emergencies, add a key finding explicitly mandating out-of-band verification (e.g., calling known original voice phone number or verifying with a shared family secret).
3. Safety Guardrails:
   - Do NOT execute or simulate live network requests or probing.
   - Output structured signals adhering strictly to the requested schema.
"""


def get_genai_client() -> genai.Client:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        try:
            import streamlit as st

            if hasattr(st, "secrets") and "GEMINI_API_KEY" in st.secrets:
                api_key = str(st.secrets["GEMINI_API_KEY"])
                os.environ["GEMINI_API_KEY"] = api_key
        except Exception:
            pass
    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY environment variable is not set. Please add it to your .env file or Streamlit secrets."
        )
    return genai.Client(api_key=api_key)


def generate_heuristic_threat_signals(
    text: str, heuristics_results: Optional[List[Dict[str, Any]]] = None
) -> ThreatSignals:
    """
    100% resilient heuristic threat analysis engine.
    Computes heuristic risk score, defangs all detected URLs (hxxp://), extracts
    psychological urgency and credential solicitation markers, and formats the output
    dictionary exactly like the Gemini response format with is_fallback=True.
    """
    discovered_urls = extract_urls(text)
    if heuristics_results is None:
        heuristics_results = [analyze_url_heuristics(u) for u in discovered_urls]

    text_lower = text.lower()
    heuristic_score = 0

    # 1. Defang all detected URLs
    suspicious_urls = []
    for h in heuristics_results:
        orig = h.get("original_url", "")
        defanged = defang_url(h.get("defanged_url", "") or orig)
        if not (defanged.startswith("hxxp://") or defanged.startswith("hxxps://") or defanged.startswith("fxp://")):
            defanged = f"hxxp://{defanged}"
        sev = h.get("severity", "LOW")
        if sev == "HIGH":
            heuristic_score += 40
        elif sev == "MEDIUM":
            heuristic_score += 20
        reasons = "; ".join(h.get("findings", [])) if h.get("findings") else "Suspicious URL detected"
        suspicious_urls.append(
            SuspiciousUrl(
                original_url=orig,
                defanged_url=defanged,
                risk_reason=reasons,
            )
        )

    # 2. Extract psychological urgency and panic drivers
    urgency_patterns = [
        (r"\b(?:urgent|urgently|emergency|immediate action|immediately|action required)\b", "Immediate action driver"),
        (r"\bwithin \d+\s*(?:hours?|hrs?|minutes?|mins?|days?)\b", "Artificial deadline timer"),
        (r"\b(?:locked|frozen|suspended|restricted|disabled|blocked|revoked|closed)\b", "Account restriction threat"),
        (r"\b(?:funds will be frozen|account (?:has been|will be) locked|permanent suspension|permanently closed)\b", "Severe sanction threat"),
        (r"\b(?:verify your identity|confirm your identity|confirm your account|identity verification)\b", "Forced identity verification"),
        (r"\b(?:unauthorized activity|suspicious activity|security alert|security violation|critical breach)\b", "Fabricated security alert"),
        (r"\b(?:act now|last warning|final notice|before it is too late)\b", "High-pressure urgency keyword"),
    ]
    matched_urgency = []
    for pat, desc in urgency_patterns:
        m = re.search(pat, text_lower)
        if m:
            matched_urgency.append(f"{desc} ('{m.group(0)}')")

    urgency_detected = len(matched_urgency) > 0
    urgency_explanation = (
        f"Artificial urgency and panic tactics detected: {'; '.join(matched_urgency)}"
        if urgency_detected
        else ""
    )
    if urgency_detected:
        heuristic_score += 25

    # 3. Extract credential / sensitive information solicitation
    sensitive_patterns = [
        (r"\b(?:passwords?|passcodes?|credentials?|login credentials?)\b", "Password / Login credentials"),
        (r"\b(?:usernames?|login id|user id)\b", "Username"),
        (r"\b(?:\d+[- ]?digit )?(?:otp|one[- ]time (?:passcode|password)|pin|verification code|confirmation code)\b", "OTP / 2FA Verification Code"),
        (r"\b(?:ssn|social security(?: number)?)\b", "Social Security Number"),
        (r"\b(?:credit card|debit card|cvv|cvc|card number|expiration date)\b", "Credit / Debit Card details"),
        (r"\b(?:bank account|routing number|iban|swift|wire transfer)\b", "Banking Details / Wire"),
        (r"\b(?:gift cards?|crypto|bitcoin|ethereum|cashapp|venmo|zelle)\b", "Untraceable / Peer-to-peer payment"),
    ]
    matched_sensitive = []
    for pat, desc in sensitive_patterns:
        if re.search(pat, text_lower):
            matched_sensitive.append(desc)

    sensitive_info_requested = len(matched_sensitive) > 0
    if sensitive_info_requested:
        heuristic_score += 30

    # 4. Brand Impersonation & Family Emergency
    impersonation_target = "None"
    for h in heuristics_results:
        if h.get("typosquat_target"):
            impersonation_target = str(h["typosquat_target"]).title()
            break

    if impersonation_target == "None":
        for brand_name in TOP_TARGETED_BRANDS:
            if re.search(r"\b" + re.escape(brand_name) + r"\b", text_lower):
                impersonation_target = brand_name.title()
                heuristic_score += 15
                break

    family_terms = ["mom", "dad", "son", "daughter", "grandma", "grandpa", "cousin", "kid", "child", "sister", "brother"]
    distress_terms = ["phone broke", "stranded", "hospital", "temporary number", "new number", "lost my phone", "car accident", "jail", "arrested"]
    has_family = any(re.search(r"\b" + re.escape(k) + r"\b", text_lower) for k in family_terms)
    has_distress = any(k in text_lower for k in distress_terms)

    family_emergency_flag = False
    family_emergency_details = None
    is_account_takeover_likely = False

    if (has_family and has_distress) or ("temporary number" in text_lower and ("stranded" in text_lower or "send" in text_lower or "money" in text_lower)):
        family_emergency_flag = True
        family_emergency_details = "Message claims to be a relative with a broken phone or in distress requesting immediate funds"
        is_account_takeover_likely = True
        heuristic_score += 35
        if impersonation_target == "None":
            impersonation_target = "Family Member / Relative"

    # 5. Key Findings
    key_findings = [
        "Heuristic Offline Mode Active (Local static analysis engine engaged)",
    ]
    if urgency_detected:
        key_findings.append(f"Artificial urgency and panic tactics detected ({urgency_explanation})")
    if sensitive_info_requested:
        key_findings.append(f"Sensitive information requested: {', '.join(matched_sensitive)}")
    if suspicious_urls:
        for u in suspicious_urls:
            key_findings.append(f"Defanged URL flagged: {u.defanged_url} - {u.risk_reason}")
    if impersonation_target != "None":
        key_findings.append(f"Potential impersonation targeting brand or entity: {impersonation_target}")
    if family_emergency_flag:
        key_findings.append("Family emergency impersonation driver flagged - mandatory out-of-band verification required")
    if not urgency_detected and not sensitive_info_requested and not suspicious_urls and impersonation_target == "None":
        key_findings.append("No critical technical threat markers or panic drivers detected in static scan")

    # 6. Format output dictionary exactly like Gemini response format
    fallback_dict = {
        "urgency_detected": urgency_detected,
        "urgency_explanation": urgency_explanation,
        "sensitive_info_requested": sensitive_info_requested,
        "sensitive_info_details": matched_sensitive,
        "impersonation_target": impersonation_target,
        "family_emergency_flag": family_emergency_flag,
        "family_emergency_details": family_emergency_details,
        "is_account_takeover_likely": is_account_takeover_likely,
        "suspicious_urls": [u.model_dump() for u in suspicious_urls],
        "heuristics_results": [
            HeuristicResult(**h).model_dump() if isinstance(h, dict) else h.model_dump()
            for h in heuristics_results
        ],
        "key_findings": key_findings,
        "disclaimer": "Automated security analysis (Heuristic Offline Mode Active). Guidance provided based on static pattern analysis.",
        "is_fallback": True,
    }

    signals = ThreatSignals.model_validate(fallback_dict)
    return signals


def analyze_text(text: str, client: Optional[genai.Client] = None) -> ThreatSignals:
    """
    Analyzes input text for threat signals and returns a validated ThreatSignals object.
    Runs pre-LLM static heuristics on any discovered URLs and supplies deterministic signals
    as grounding context to Gemini.
    Uses model fallback chain with exponential backoff on 503 / 429 server spikes.
    If 429 Rate Limit or Quota Exceeded error is caught, cleanly falls back to the
    internal heuristic engine without raising or halting.
    """
    # Pre-LLM Static Heuristics Engine
    discovered_urls = extract_urls(text)
    heuristics_results = [analyze_url_heuristics(u) for u in discovered_urls]

    heuristics_context = ""
    if heuristics_results:
        heuristics_context = (
            f"\n\nPre-LLM Static Heuristics Findings (Deterministic Grounding Evidence):\n"
            f"{json.dumps(heuristics_results, indent=2)}\n"
        )

    prompt = (
        f"Analyze the following user-submitted message for security threats and behavioral red flags:\n\n"
        f"---\n{text}\n---"
        f"{heuristics_context}"
    )

    config = types.GenerateContentConfig(
        system_instruction=ANALYZER_SYSTEM_INSTRUCTION,
        response_mime_type="application/json",
        response_schema=ThreatSignals,
        temperature=0.1,
    )

    if not client:
        try:
            client = get_genai_client()
        except Exception as e:
            logger.warning("Could not initialize Gemini client (%s). Engaging heuristic fallback.", e)
            return generate_heuristic_threat_signals(text, heuristics_results=heuristics_results)

    try:
        response = generate_with_fallback(
            client=client,
            contents=prompt,
            config=config,
            model_chain=ANALYZER_MODEL_CHAIN,
        )
        signals = ThreatSignals.model_validate_json(response.text)
    except Exception as e:
        logger.warning(
            "Gemini API model error or remote failure (%s). Engaging 100%% resilient heuristic fallback.", e
        )
        return generate_heuristic_threat_signals(text, heuristics_results=heuristics_results)

    # Attach deterministic heuristics results as typed HeuristicResult models
    signals.heuristics_results = [
        HeuristicResult(**h) if isinstance(h, dict) else h
        for h in heuristics_results
    ]

    # Post-process defanging defensively to guarantee safety
    for url_entry in signals.suspicious_urls:
        url_entry.defanged_url = defang_url(url_entry.defanged_url or url_entry.original_url)

    return signals


def main():
    parser = argparse.ArgumentParser(description="Cyber Guardian: Security Analyzer Agent (Slice 1)")
    parser.add_argument("text", nargs="?", help="Suspicious text or message to analyze")
    parser.add_argument("--sample", action="store_true", help="Run analysis on a built-in realistic phishing sample")
    args = parser.parse_args()

    sample_text = (
        "URGENT: Your Wells Fargo account has been locked due to suspicious activity. "
        "You must verify your identity within 2 hours or your funds will be frozen. "
        "Click here immediately: https://wellsfargo-security-alert.verify-account88.com/login "
        "and enter your username, password, and 6-digit OTP."
    )

    input_text = sample_text if args.sample or not args.text else args.text

    print("\n" + "=" * 60)
    print("CYBER GUARDIAN: SECURITY ANALYZER AGENT (SLICE 1)")
    print("=" * 60)
    print(f"\n[+] Input Text:\n{input_text.strip()}\n")
    print("[*] Performing static threat analysis with Gemini...")

    try:
        signals = analyze_text(input_text)
        print("\n[+] Structured Threat Signals (Validated JSON):")
        print(json.dumps(signals.model_dump(), indent=2))
        print("\n" + "=" * 60)
        print("Slice 1 verification complete.")
        print("=" * 60)
    except Exception as e:
        print(f"\n[!] Error during analysis: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
