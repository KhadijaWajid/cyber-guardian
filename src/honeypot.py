import os
import json
import logging
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

from src.analyzer import get_genai_client
from src.utils import generate_with_fallback

logger = logging.getLogger("cyber_guardian.honeypot")


class ProbeItem(BaseModel):
    name: str = Field(description="Name or title of probe strategy")
    strategy: str = Field(description="Forensic objective of this counter-probe")
    copy_text: str = Field(description="Exact safe message text the user can copy-paste to the scammer")


class HoneypotAnalysis(BaseModel):
    attacker_objective: str = Field(description="The attacker's immediate psychological and tactical goal")
    playbook_analysis: str = Field(description="Brief breakdown of the social engineering manipulation tactics used")
    infrastructure_probe: ProbeItem = Field(description="Probe coaxing reveal of real payment link, registration, or phone number")
    consistency_check: ProbeItem = Field(description="Stalling question designed to catch impersonator lacking private family context")
    fake_compliance: ProbeItem = Field(description="Feign compliance to force attacker to reveal actionable banking/routing details")


HONEYPOT_SYSTEM_INSTRUCTION = """
You are the Reverse-Interrogation & Honeypot Counter-Intelligence Agent in the Cyber Guardian cyber safety suite.
Your mission is to defend the user during an active social engineering or phishing interaction by analyzing the attacker's playbook
and generating 3 highly effective, safe counter-probe responses.

Rules:
1. Identify the attacker's immediate tactical objective (e.g. urgent wire transfer, gift card PIN, login credential harvest, voice bypass).
2. Generate 3 distinct safe counter-probe responses:
   - Infrastructure Probe: Coaxes the scammer into revealing infrastructure (e.g., asking for their official company registration, physical office phone, or alternative payment portal link).
   - Consistency Check: A stalling question checking family/business consistency that a real contact would know but an impostor cannot answer (e.g., "What was the name of grandma's dog when we visited last summer?").
   - Fake Compliance: Feigns willingness to comply but creates a technical obstacle requiring the attacker to provide actionable forensic markers (e.g., "My banking app requires the destination bank's SWIFT/routing number and legal beneficiary name, please send them.").
3. Tone: Naive, cooperative, non-confrontational, never tipping off that the user suspects a scam.
4. Output strictly structured JSON conforming to the requested schema.
"""


def _get_deterministic_fallback_probes(attacker_last_message: str) -> Dict[str, Any]:
    """Provides deterministic high-quality counter-probes when LLM is unavailable or in test mocks."""
    msg_lower = attacker_last_message.lower()

    if any(k in msg_lower for k in ["mom", "dad", "phone broke", "stranded", "hospital", "emergency"]):
        obj = "Family emergency impersonation aiming for immediate untraceable money transfer"
        playbook = "Fabricated urgency combined with emotional distress to prevent out-of-band verification"
        consistency = (
            "Hey, of course I want to help you out! Just remind me real quick, what was the name of the street we stayed on during that summer cabin trip?"
        )
        fake_comp = (
            "I'm at the bank app right now, but it's asking for the exact routing number and full legal name on the account before sending. What is it?"
        )
    else:
        obj = "Financial credential or direct electronic fund transfer extraction"
        playbook = "Authority pressure coupled with an artificial deadline to force compliance"
        consistency = (
            "I received your notice, but our records show a different account reference number. Could you verify our primary billing zip code and registered account ID?"
        )
        fake_comp = (
            "I am ready to authorize the payment right now, but our finance portal is rejecting the link. Can you send your direct corporate account IBAN/SWIFT or wire instructions?"
        )

    return {
        "attacker_objective": obj,
        "playbook_analysis": playbook,
        "infrastructure_probe": {
            "name": "Infrastructure Probe",
            "strategy": "Coax attacker to provide real domain, company registration, or direct phone number",
            "copy_text": "I'd like to get this cleared immediately. Do you have your direct departmental extension and official support ticket URL so I can log it for my accountant?",
        },
        "consistency_check": {
            "name": "Stalling / Consistency Check",
            "strategy": "Pose a private verification question that only the legitimate party can answer",
            "copy_text": consistency,
        },
        "fake_compliance": {
            "name": "Fake Compliance",
            "strategy": "Feign ignorance while demanding forensic routing identifiers",
            "copy_text": fake_comp,
        },
    }


# Alias for testing and offline scenarios
get_deterministic_counter_probes = _get_deterministic_fallback_probes


def generate_counter_probe(
    chat_history: Optional[List[Dict[str, str]]] = None,
    attacker_last_message: str = "",
    client: Optional[genai.Client] = None,
    force_fallback: bool = False,
) -> Dict[str, Any]:
    """
    Analyzes attacker behavioral playbook and returns 3 strategic counter-probes.
    Uses Gemini with fallback chain, or deterministic fallback if client or API key is absent,
    or if force_fallback is True.
    """
    if force_fallback:
        return _get_deterministic_fallback_probes(attacker_last_message)

    if not attacker_last_message and not chat_history:
        attacker_last_message = "URGENT: Please verify your account credentials or send money immediately."

    # Format conversation transcript
    history_lines = []
    if chat_history:
        for turn in chat_history:
            sender = turn.get("role", turn.get("sender", "user")).capitalize()
            content = turn.get("text", turn.get("content", ""))
            history_lines.append(f"{sender}: {content}")

    if attacker_last_message:
        history_lines.append(f"Attacker (Latest): {attacker_last_message}")

    full_conversation = "\n".join(history_lines)

    # If client is not explicitly provided, attempt to initialize from env
    if not client:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return _get_deterministic_fallback_probes(attacker_last_message)
        try:
            client = get_genai_client()
        except Exception:
            return _get_deterministic_fallback_probes(attacker_last_message)

    prompt = (
        f"Analyze this ongoing scam/phishing dialogue and prepare 3 strategic counter-probes:\n\n"
        f"---\n{full_conversation}\n---"
    )

    config = types.GenerateContentConfig(
        system_instruction=HONEYPOT_SYSTEM_INSTRUCTION,
        response_mime_type="application/json",
        response_schema=HoneypotAnalysis,
        temperature=0.3,
    )

    try:
        response = generate_with_fallback(
            client=client,
            contents=prompt,
            config=config,
        )
        data = HoneypotAnalysis.model_validate_json(response.text)
        return data.model_dump()
    except Exception as e:
        logger.warning("Honeypot LLM generation failed (%s). Utilizing deterministic forensic probe generator.", e)
        return _get_deterministic_fallback_probes(attacker_last_message)
