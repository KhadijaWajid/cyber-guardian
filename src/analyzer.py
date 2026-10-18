import os
import sys
import json
import argparse
from typing import Optional
from dotenv import load_dotenv
from google import genai
from google.genai import types

from src.schemas import ThreatSignals, HeuristicResult
from src.utils import defang_url, generate_with_fallback
from src.heuristics import extract_urls, analyze_url_heuristics

load_dotenv()


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
        raise ValueError("GEMINI_API_KEY environment variable is not set. Please add it to your .env file.")
    return genai.Client(api_key=api_key)


def analyze_text(text: str, client: Optional[genai.Client] = None) -> ThreatSignals:
    """
    Analyzes input text for threat signals and returns a validated ThreatSignals object.
    Runs pre-LLM static heuristics on any discovered URLs and supplies deterministic signals
    as grounding context to Gemini.
    Uses model fallback chain with exponential backoff on 503 / 429 server spikes.
    """
    if not client:
        client = get_genai_client()

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

    response = generate_with_fallback(
        client=client,
        contents=prompt,
        config=config,
    )

    signals = ThreatSignals.model_validate_json(response.text)

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
