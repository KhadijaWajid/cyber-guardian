import os
import sys
import json
import argparse
from typing import Optional
from dotenv import load_dotenv
from google import genai
from google.genai import types

from src.schemas import ThreatSignals, ThreatReport
from src.analyzer import analyze_text, get_genai_client
from src.utils import generate_with_fallback

load_dotenv()

ADVISOR_SYSTEM_INSTRUCTION = """
You are the Safety Advisor Agent in the Cyber Guardian cyber safety assistant.
Your mission is to review the structured threat signals extracted by the Security Analyzer and translate them into a clear, reassuring, and jargon-free safety report for everyday, non-technical users.

Guidelines:
1. Determine 'overall_risk':
   - 'HIGH': Active credential harvesting, financial fraud, impersonation of banks/services, or panic-inducing demands with malicious links.
   - 'MEDIUM': High-pressure urgency without clear links, unknown senders requesting follow-up, or mildly suspicious domains.
   - 'LOW': Benign notifications, legitimate promotional messages, or communications with zero red flags.
2. Plain-English 'summary':
   - Explain what is happening in 2-3 accessible sentences (e.g., "Someone is pretending to be your bank to trick you into giving away your login credentials and one-time password.").
   - Do NOT use technical jargon (avoid terms like 'typosquatting', 'apex domain', 'MFA interception' without simple explanations).
3. 'recommended_actions':
   - Provide 3 to 5 actionable, practical 'DO' and 'DO NOT' recommendations (e.g., "DO NOT click on the link provided in the message", "DO navigate to the official website directly by typing the address yourself").
   - If 'family_emergency_flag' or 'is_account_takeover_likely' is detected, explicitly instruct the user: "DO NOT transfer any funds, gift cards, or crypto", and "DO call your relative directly on their known, saved voice number or verify with a shared secret question before taking action".
4. 'disclaimer':
   - Include a concise safety reminder that automated scans provide guidance based on observed patterns.
"""


def generate_advice(signals: ThreatSignals, client: Optional[genai.Client] = None) -> ThreatReport:
    """
    Takes ThreatSignals from the Security Analyzer Agent and produces a consumer-facing ThreatReport.
    Uses model fallback chain with exponential backoff on 503 / 429 server spikes.
    """
    if not client:
        client = get_genai_client()

    prompt = (
        "Here are the technical threat signals extracted from a user-submitted message:\n\n"
        f"{signals.model_dump_json(indent=2)}\n\n"
        "Generate a complete, non-technical ThreatReport advising the user."
    )

    config = types.GenerateContentConfig(
        system_instruction=ADVISOR_SYSTEM_INSTRUCTION,
        response_mime_type="application/json",
        response_schema=ThreatReport,
        temperature=0.2,
    )

    response = generate_with_fallback(
        client=client,
        contents=prompt,
        config=config,
    )

    report = ThreatReport.model_validate_json(response.text)
    # Ensure the threat_signals field retains the exact verified signals
    report.threat_signals = signals
    return report


def main():
    parser = argparse.ArgumentParser(description="Cyber Guardian: Safety Advisor Agent (Slice 2)")
    parser.add_argument("text", nargs="?", help="Suspicious text or message to evaluate")
    parser.add_argument("--sample", action="store_true", help="Run with built-in phishing sample")
    args = parser.parse_args()

    sample_text = (
        "URGENT: Your Wells Fargo account has been locked due to suspicious activity. "
        "You must verify your identity within 2 hours or your funds will be frozen. "
        "Click here immediately: https://wellsfargo-security-alert.verify-account88.com/login "
        "and enter your username, password, and 6-digit OTP."
    )

    input_text = sample_text if args.sample or not args.text else args.text

    print("\n[+] Running Analyzer -> Advisor Pipeline...")
    signals = analyze_text(input_text)
    report = generate_advice(signals)

    print("\n" + "=" * 60)
    print("SAFETY ADVISOR AGENT REPORT (JSON)")
    print("=" * 60)
    print(json.dumps(report.model_dump(), indent=2))


if __name__ == "__main__":
    main()
