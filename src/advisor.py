import os
import sys
import json
import logging
import argparse
from typing import Optional, List
from dotenv import load_dotenv
from google import genai
from google.genai import types

from src.schemas import ThreatSignals, ThreatReport
from src.analyzer import analyze_text, get_genai_client
from src.utils import generate_with_fallback, is_rate_limit_error

load_dotenv()
logger = logging.getLogger("cyber_guardian.advisor")

ADVISOR_MODEL_CHAIN: List[str] = [
    "gemini-2.5-flash",
    "gemini-3.8-flash",
]

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


def generate_heuristic_advice(signals: ThreatSignals) -> ThreatReport:
    """
    Produces a consumer-facing ThreatReport deterministically from ThreatSignals
    when Gemini API quota is saturated or in offline mode.
    """
    has_emergency = getattr(signals, "family_emergency_flag", False)
    has_takeover = getattr(signals, "is_account_takeover_likely", False)
    has_suspicious_urls = bool(signals.suspicious_urls)
    has_urgency = bool(signals.urgency_detected)
    has_sensitive = bool(signals.sensitive_info_requested)
    target = getattr(signals, "impersonation_target", "None") or "None"

    # Compute overall risk
    if has_emergency or has_takeover or (has_urgency and has_sensitive) or (has_suspicious_urls and has_sensitive):
        overall_risk = "HIGH"
    elif has_urgency or has_sensitive or has_suspicious_urls or (target != "None"):
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    # Plain-English summary
    if has_emergency:
        summary = (
            "This communication appears to be a family emergency impersonation scam. "
            "An attacker is claiming a crisis (such as a broken phone or urgent need for money) "
            "to cause panic and bypass your normal verification habits."
        )
    elif target != "None" and (has_sensitive or has_urgency):
        summary = (
            f"Someone appears to be impersonating {target} using manufactured urgency and pressure tactics "
            "to trick you into disclosing sensitive personal credentials or taking immediate action."
        )
    elif has_urgency and has_sensitive:
        summary = (
            "This message uses high-pressure urgency tactics to solicit sensitive credentials or account information. "
            "Legitimate security desks do not mandate urgent credential confirmation under short deadlines."
        )
    elif has_suspicious_urls:
        summary = (
            "This message contains unverified or defanged links that may attempt to redirect you "
            "to deceptive phishing portals designed to harvest account details."
        )
    elif has_urgency:
        summary = (
            "This message displays artificial urgency and panic drivers designed to force hasty compliance. "
            "Exercise caution and verify before responding."
        )
    else:
        summary = (
            "Automated static heuristic scan did not detect obvious malicious patterns, credential harvesting, "
            "or artificial panic drivers in this communication."
        )

    # Practical DO / DO NOT recommendations
    actions = []
    if has_emergency or has_takeover:
        actions.append("DO NOT send money, wire transfers, crypto, or gift cards.")
        actions.append("DO call your relative directly on their known, saved voice phone number to verify their safety.")
        actions.append("DO ask a private security question that only your actual family member would know.")
        actions.append("DO NOT reply to or trust unfamiliar temporary phone numbers.")
    elif overall_risk == "HIGH":
        actions.append("DO NOT click on any links or download attachments in this message.")
        actions.append("DO NOT provide your password, 6-digit OTP, PIN, or payment details.")
        actions.append("DO navigate directly to the official website or app independently to inspect your account.")
        actions.append("DO report and block this sender handle.")
    elif overall_risk == "MEDIUM":
        actions.append("DO NOT rush to comply with any time limits or deadlines.")
        actions.append("DO verify the sender's identity through official, independently verified contact channels.")
        actions.append("DO inspect all links carefully without clicking them.")
    else:
        actions.append("DO exercise standard digital hygiene when receiving unsolicited messages.")
        actions.append("DO verify any unexpected account requests directly with the organization.")

    return ThreatReport(
        overall_risk=overall_risk,
        summary=summary,
        threat_signals=signals,
        recommended_actions=actions,
        disclaimer="Automated security analysis (Heuristic Offline Mode Active). Guidance provided based on static pattern analysis.",
        is_fallback=True,
    )


def generate_advice(signals: ThreatSignals, client: Optional[genai.Client] = None) -> ThreatReport:
    """
    Takes ThreatSignals from the Security Analyzer Agent and produces a consumer-facing ThreatReport.
    Uses model fallback chain with exponential backoff on 503 / 429 server spikes.
    Falls back cleanly to deterministic heuristic advice on 429 rate limit or quota exhaustion.
    """
    if getattr(signals, "is_fallback", False):
        return generate_heuristic_advice(signals)

    if not client:
        try:
            client = get_genai_client()
        except Exception as e:
            logger.warning("Could not initialize Gemini client for advisor (%s). Falling back to heuristic advice.", e)
            return generate_heuristic_advice(signals)

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

    try:
        response = generate_with_fallback(
            client=client,
            contents=prompt,
            config=config,
            model_chain=ADVISOR_MODEL_CHAIN,
        )
        report = ThreatReport.model_validate_json(response.text)
        report.threat_signals = signals
        return report
    except Exception as e:
        logger.warning(
            "Safety Advisor API model error or remote failure (%s). Falling back to heuristic advice.", e
        )
        return generate_heuristic_advice(signals)


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
