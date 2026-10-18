import sys
import argparse
from typing import Optional

from src.analyzer import analyze_text
from src.advisor import generate_advice
from src.schemas import ThreatReport


# Reconfigure stdout for UTF-8 on Windows consoles to prevent  artifacts
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ANSI color codes for terminal display
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
GRAY = "\033[90m"


def format_risk_badge(risk: str) -> str:
    if risk == "HIGH":
        return f"{BOLD}{RED}[!!! HIGH RISK - LIKELY MALICIOUS !!!]{RESET}"
    elif risk == "MEDIUM":
        return f"{BOLD}{YELLOW}[ !  MEDIUM RISK - PROCEED CAUTIOUSLY ! ]{RESET}"
    else:
        return f"{BOLD}{GREEN}[ *  LOW RISK - NO OBVIOUS THREATS DETECTED  * ]{RESET}"


def display_report_card(report: ThreatReport, original_input: Optional[str] = None):
    print("\n" + "=" * 70)
    print(f"{BOLD}{CYAN}                      CYBER GUARDIAN SAFETY SCAN{RESET}")
    print("=" * 70)

    # 1. Risk Level
    print(f"\n{BOLD}OVERALL THREAT LEVEL:{RESET}")
    print(f"  {format_risk_badge(report.overall_risk)}")

    # 2. Plain-English Summary
    print(f"\n{BOLD}WHAT THIS MEANS (PLAIN ENGLISH):{RESET}")
    print(f"  {report.summary}")

    # 3. Technical Markers & Red Flags (Defanged)
    signals = report.threat_signals
    print(f"\n{BOLD}THREAT INDICATORS DETECTED:{RESET}")
    
    if signals.impersonation_target and signals.impersonation_target.lower() != "none":
        print(f"  [-] {BOLD}Impersonation:{RESET} Targeting {CYAN}{signals.impersonation_target}{RESET}")

    if signals.urgency_detected:
        urgency_note = f" ({signals.urgency_explanation})" if signals.urgency_explanation else ""
        print(f"  [-] {BOLD}Urgency / Pressure:{RESET} Artificial deadline detected{urgency_note}")

    if signals.sensitive_info_requested:
        details = ", ".join(signals.sensitive_info_details) if signals.sensitive_info_details else "Credentials"
        print(f"  [-] {BOLD}Sensitive Data Requested:{RESET} {details}")

    if signals.heuristics_results:
        print(f"\n{BOLD}STATIC URL HEURISTICS (PRE-LLM DETERMINISTIC SIGNALS):{RESET}")
        for h in signals.heuristics_results:
            h_dict = h.model_dump() if hasattr(h, "model_dump") else h
            print(f"  [-] {YELLOW}{h_dict.get('defanged_url')}{RESET} [Severity: {h_dict.get('severity')}]")
            for f in h_dict.get("findings", []):
                print(f"      * {f}")

    if signals.suspicious_urls:
        print(f"\n{BOLD}SUSPICIOUS / OBFUSCATED LINKS (DEFANGED):{RESET}")
        for link in signals.suspicious_urls:
            print(f"      * Link: {YELLOW}{link.defanged_url}{RESET}")
            print(f"        Reason: {GRAY}{link.risk_reason}{RESET}")
    elif not signals.urgency_detected and not signals.sensitive_info_requested and not signals.heuristics_results:
        print("  [-] No red flag technical markers detected in text.")

    # 4. Action Checklist
    print(f"\n{BOLD}RECOMMENDED ACTION CHECKLIST:{RESET}")
    for action in report.recommended_actions:
        if action.upper().startswith("DO NOT") or action.upper().startswith("DON'T") or "NEVER" in action.upper():
            print(f"  {RED}[X] {action}{RESET}")
        else:
            print(f"  {GREEN}[v] {action}{RESET}")

    # 5. Disclaimer
    print(f"\n{GRAY}Notice: {report.disclaimer}{RESET}")
    print("=" * 70 + "\n")


def scan_message(text: str) -> ThreatReport:
    """Executes the two-stage pipeline: Analyzer Agent -> Advisor Agent."""
    signals = analyze_text(text)
    report = generate_advice(signals)
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Cyber Guardian: Two-Agent Security Analyzer and Safety Advisor"
    )
    parser.add_argument("text", nargs="?", help="Text, email snippet, SMS, or suspicious link to inspect")
    parser.add_argument("--sample", action="store_true", help="Run scan on a sample phishing scenario")
    args = parser.parse_args()

    sample_text = (
        "URGENT: Your Wells Fargo account has been locked due to suspicious activity. "
        "You must verify your identity within 2 hours or your funds will be frozen. "
        "Click here immediately: https://wellsfargo-security-alert.verify-account88.com/login "
        "and enter your username, password, and 6-digit OTP."
    )

    if args.sample:
        input_text = sample_text
    elif args.text:
        input_text = args.text
    else:
        print(f"{CYAN}Welcome to Cyber Guardian.{RESET}")
        print("Enter a suspicious email, SMS, or message to inspect (or press Enter to run demo):")
        try:
            user_input = input("> ").strip()
            input_text = user_input if user_input else sample_text
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)

    print("\n[*] Inspecting message with Security Analyzer Agent...")
    signals = analyze_text(input_text)
    
    print("[*] Generating plain-English guidance with Safety Advisor Agent...")
    report = generate_advice(signals)

    display_report_card(report, original_input=input_text)


if __name__ == "__main__":
    main()
