import os
import json
import logging
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

from src.analyzer import get_genai_client
from src.utils import generate_with_fallback, is_rate_limit_error

logger = logging.getLogger("cyber_guardian.honeypot")

HONEYPOT_MODEL_CHAIN: List[str] = [
    "gemini-2.5-flash",
    "gemini-3.8-flash",
]


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
            model_chain=HONEYPOT_MODEL_CHAIN,
        )
        data = HoneypotAnalysis.model_validate_json(response.text)
        return data.model_dump()
    except Exception as e:
        logger.warning("Honeypot LLM generation failed (%s). Utilizing deterministic forensic probe generator.", e)
        return _get_deterministic_fallback_probes(attacker_last_message)


# ==============================================================================
# MULTI-TURN SCAMMER SIMULATION & BEHAVIORAL ANALYSIS
# ==============================================================================

class ScammerTurn(BaseModel):
    reply: str = Field(description="Realistic in-character response from the simulated scammer advancing the social engineering attack")
    tactic: str = Field(description="Behavioral analysis tag formatted as '⚡ Tactic: <Tactic Name> | 🎯 Objective: <Objective>'")


SCAMMER_SIMULATION_SYSTEM_INSTRUCTION = """
You are an educational adversary simulator in the Cyber Guardian cyber safety suite.
Your purpose is to roleplay a social engineering scammer in a controlled honeypot training sandbox so security analysts can practice counter-interrogation.

CRITICAL SAFETY BOUNDARIES:
- NEVER output actual malicious URLs or IPs (always use safe defanged placeholders like hxxps://internal-auth[.]example[.]com if pretending to send a link).
- NEVER output executable exploit code, shell commands, or real malware payloads.
- Strictly simulate non-harmful conversational social engineering dialogue (false urgency, fabricated authority, evasion of verification).

PERSONA INSTRUCTIONS:
- Stay firmly in character as the specified scammer persona.
- Defend the scam, fabricate urgency, invent plausible bureaucratic or emotional excuses, and push the analyst to comply with your objective (credentials, payment, remote access, OTP).
- Provide a concise in-character reply (2 to 4 sentences).
- Provide a structured behavioral analysis tag summarizing the tactic and objective, formatted as:
  '⚡ Tactic: <Tactic Name> | 🎯 Objective: <Immediate Objective>'
- Output strictly structured JSON conforming to the requested schema.
"""


def _get_rate_limit_scammer_reply(
    persona: str = "", current_threat_context: str = "", latest_user_msg: str = ""
) -> Dict[str, str]:
    """
    Returns an authentic simulated attacker reply based on lure type when
    counter-interrogation encounters a 429 Rate Limit or Quota Exceeded error.
    """
    combined = f"{persona} {current_threat_context} {latest_user_msg}".lower()

    if "family" in combined or any(k in combined for k in ["mom", "dad", "son", "daughter", "stranded", "hospital", "cabin", "dog"]):
        reply = (
            "Urgent: I lost my phone and am stranded right now! Please don't delay, "
            "reply with the 6-digit confirmation code immediately to avoid permanent suspension."
        )
    elif "tech support" in combined or any(k in combined for k in ["microsoft", "windows", "virus", "remote", "anydesk"]):
        reply = (
            "Urgent: Critical network anomalies detected on your workstation. "
            "Please reply with the 6-digit confirmation code immediately to avoid permanent suspension."
        )
    elif "crypto" in combined or any(k in combined for k in ["wallet", "investment", "bitcoin", "deposit", "roi"]):
        reply = (
            "Urgent: Your wallet security verification failed. "
            "Please reply with the 6-digit confirmation code immediately to avoid permanent suspension."
        )
    else:
        # Bank Fraud / Account verification / Default lure
        reply = (
            "Urgent: Your account verification failed. "
            "Please reply with the 6-digit confirmation code immediately to avoid permanent suspension."
        )

    return {
        "content": reply,
        "tactic": "⚡ Tactic: False Urgency & Credential Harvesting",
    }


def _get_deterministic_scammer_reply(user_message: str, persona: str) -> Dict[str, str]:
    msg_l = (user_message or "").lower()
    p_l = (persona or "").lower()

    if "family" in p_l or any(k in msg_l for k in ["mom", "dad", "cabin", "dog", "relative"]):
        reply = (
            "Please stop asking questions right now! I'm stranded at the station, my phone battery is at 2%, "
            "and I can't receive calls. Just send the $450 to this temporary number right now or I'm stuck here all night!"
        )
        tactic = "⚡ Tactic: Emotional Coercion & Panic Driver | 🎯 Objective: Evade Out-of-Band Call"
    elif "tech support" in p_l or any(k in msg_l for k in ["anydesk", "teamviewer", "badge", "id", "ip"]):
        reply = (
            "This is Senior Engineer David Miller from Microsoft Security Operations (ID #MS-7719). "
            "Your machine's IP is broadcasting malicious outbound packets right now. If you do not allow remote diagnostic "
            "connection within 5 minutes, your Windows license will be permanently revoked and forwarded to law enforcement."
        )
        tactic = "⚡ Tactic: Technical Intimidation & False Authority | 🎯 Objective: Secure Remote Desktop Access"
    elif "crypto" in p_l or any(k in msg_l for k in ["crypto", "wallet", "investment", "roi", "deposit"]):
        reply = (
            "Our automated arbitrage pool has locked in your 350% yield, but the liquidity allocation pool is 98% subscribed. "
            "You have exactly 10 minutes to deposit the validation balance to secure your tranche before the smart contract refunds."
        )
        tactic = "⚡ Tactic: Artificial Scarcity & Greed Exploitation | 🎯 Objective: Immediate Crypto Deposit"
    elif "bank" in p_l or any(k in msg_l for k in ["bank", "wells", "fargo", "chase", "fraud", "account"]):
        reply = (
            "This is the Automated Fraud Prevention Desk. We have detected unauthorized wire transfers totaling $2,450. "
            "For your protection, please confirm your 6-digit one-time passcode (OTP) or account password right now to cancel this transaction."
        )
        tactic = "⚡ Tactic: Fabricated Emergency & Account Threat | 🎯 Objective: Credential / OTP Harvesting"
    else:
        reply = (
            "Notice: We have flagged multiple security violations on your account profile. "
            "Please confirm your credentials immediately to avoid permanent account termination and legal escalation."
        )
        tactic = "⚡ Tactic: False Urgency & Fear Induction | 🎯 Objective: Force Immediate Compliance"

    return {"content": reply, "tactic": tactic}


def simulate_scammer_reply(
    messages: List[Dict[str, Any]],
    persona: str = "Bank Fraud Department",
    current_threat_context: str = "",
    client: Optional[genai.Client] = None,
    force_fallback: bool = False,
) -> Dict[str, str]:
    """
    Simulates a turn of the scammer in the honeypot sandbox, returning an in-character
    reply and a structured behavioral analysis tag.
    """
    latest_user_msg = ""
    for m in reversed(messages):
        if m.get("role") in ["user", "analyst"]:
            latest_user_msg = m.get("content", "")
            break

    if force_fallback:
        return _get_deterministic_scammer_reply(latest_user_msg, persona)

    # Format transcript
    history_lines = []
    if current_threat_context:
        history_lines.append(f"Initial Threat Context / Original Scam Bait:\n{current_threat_context}\n")

    for turn in messages:
        sender = "Analyst (User)" if turn.get("role") in ["user", "analyst"] else "Scammer (You)"
        content = turn.get("content", turn.get("text", ""))
        history_lines.append(f"{sender}: {content}")

    conversation_text = "\n".join(history_lines)

    if not client:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return _get_rate_limit_scammer_reply(persona, current_threat_context, latest_user_msg)
        try:
            client = get_genai_client()
        except Exception as e:
            logger.warning("Could not initialize Gemini client for honeypot (%s). Using authentic fallback reply.", e)
            return _get_rate_limit_scammer_reply(persona, current_threat_context, latest_user_msg)

    prompt = (
        f"Active Persona: {persona}\n"
        f"Conversation History:\n{conversation_text}\n\n"
        f"Respond as the scammer to the latest message. Maintain urgency and evasion tactics while complying with safety bounds."
    )

    config = types.GenerateContentConfig(
        system_instruction=SCAMMER_SIMULATION_SYSTEM_INSTRUCTION,
        response_mime_type="application/json",
        response_schema=ScammerTurn,
        temperature=0.7,
    )

    try:
        response = generate_with_fallback(
            client=client,
            contents=prompt,
            config=config,
            model_chain=HONEYPOT_MODEL_CHAIN,
        )
        data = ScammerTurn.model_validate_json(response.text)
        return {"content": data.reply, "tactic": data.tactic}
    except Exception as e:
        logger.warning(
            "Scammer simulation API failure (%s). Returning authentic fallback reply.", e
        )
        return _get_rate_limit_scammer_reply(persona, current_threat_context, latest_user_msg)

