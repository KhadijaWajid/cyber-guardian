from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field


class SuspiciousUrl(BaseModel):
    """Details for a suspicious URL or domain detected in the text."""
    original_url: str = Field(description="The raw URL or domain found in the input")
    defanged_url: str = Field(description="The defanged URL (e.g., hxxps://domain[.]com) to prevent accidental clicks")
    risk_reason: str = Field(description="Why this URL is flagged (e.g., mismatched branding, suspicious TLD, typosquatting)")


class HeuristicResult(BaseModel):
    """Deterministic static URL heuristic inspection result."""
    original_url: str = Field(description="The raw URL or domain inspected")
    defanged_url: str = Field(description="The defanged URL safe for display")
    is_ip_address: bool = Field(default=False, description="True if host is a raw IP address")
    is_high_risk_tld: bool = Field(default=False, description="True if TLD is in high-abuse registry")
    typosquat_target: Optional[str] = Field(default=None, description="Impersonated brand target or None")
    severity: str = Field(default="LOW", description="Heuristic risk rating: HIGH, MEDIUM, or LOW")
    findings: List[str] = Field(default_factory=list, description="List of deterministic red flags")


class ThreatSignals(BaseModel):
    """Structured threat signals extracted by the Security Analyzer Agent."""
    urgency_detected: bool = Field(description="True if artificial urgency, panic drivers, or strict deadlines are present")
    urgency_explanation: str = Field(default="", description="Details on the urgency tactics used, or empty if none")
    sensitive_info_requested: bool = Field(description="True if credentials, OTPs, credit cards, or personal data are solicited")
    sensitive_info_details: List[str] = Field(default_factory=list, description="Specific sensitive data requested")
    impersonation_target: str = Field(default="None", description="Entity or brand being impersonated, or 'None'")
    family_emergency_flag: bool = Field(
        default=False,
        description="True if message claims to be a child, parent, relative, or friend in an alleged emergency requesting money",
    )
    family_emergency_details: Optional[str] = Field(
        default=None,
        description="Details of the claimed relative/family emergency tactic, or None",
    )
    is_account_takeover_likely: bool = Field(
        default=False,
        description="True if communication indicates hijacked contact, SIM swap, or account takeover of a trusted party",
    )
    suspicious_urls: List[SuspiciousUrl] = Field(default_factory=list, description="List of suspicious URLs or domains extracted and defanged")
    heuristics_results: Optional[List[HeuristicResult]] = Field(
        default_factory=list,
        description="Deterministic pre-LLM static URL heuristic signals"
    )
    key_findings: List[str] = Field(description="Bullet points of technical and behavioral red flags detected")
    disclaimer: str = Field(
        default="Automated security analysis does not guarantee complete immunity. Proceed with caution.",
        description="Standard safety advisory disclaimer"
    )
    is_fallback: bool = Field(
        default=False,
        description="True if analysis was generated via heuristic offline engine due to rate limits or API exhaustion",
    )


class ThreatReport(BaseModel):
    """Consumer-facing final advisory report produced by the Safety Advisor Agent."""
    overall_risk: Literal["LOW", "MEDIUM", "HIGH"] = Field(
        description="Calculated risk score based on indicators: LOW, MEDIUM, or HIGH"
    )
    summary: str = Field(
        description="Clear explanation in plain English without technical jargon explaining why this was flagged"
    )
    threat_signals: ThreatSignals = Field(
        description="The underlying technical threat signals extracted by the Security Analyzer Agent"
    )
    recommended_actions: List[str] = Field(
        description="Concrete dos and don'ts for everyday users to stay safe (action checklist)"
    )
    disclaimer: str = Field(
        default="Automated security analysis provides guidance based on static patterns and does not guarantee complete immunity. Always proceed with caution.",
        description="Standard consumer safety disclaimer"
    )
    is_fallback: bool = Field(
        default=False,
        description="True if report was generated via heuristic offline engine due to rate limits or API exhaustion",
    )
