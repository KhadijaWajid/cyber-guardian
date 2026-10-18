import os
import pytest
from unittest.mock import MagicMock
from src.db import init_db, log_threat, check_repeat_offender, get_all_records, clear_db, create_user, verify_user
from src.schemas import ThreatSignals
from src.honeypot import (
    generate_counter_probe,
    get_deterministic_counter_probes,
    HoneypotAnalysis,
    ProbeItem,
)
from src.heuristics import analyze_ecommerce_discount


# ==============================================================================
# FEATURE 1: Threat Recidivism Database Tests
# ==============================================================================

@pytest.fixture
def temp_db(tmp_path):
    """Provides an isolated SQLite database file for testing using pytest tmp_path."""
    path = str(tmp_path / "test_cyber_guardian.db")
    init_db(path)
    return path


def test_db_init_and_empty_check(temp_db):
    res = check_repeat_offender("unknown_sender@evil.com", ["https://new-url.xyz"], db_path=temp_db)
    assert res["is_repeat_offender"] is False
    assert res["repeat_count"] == 0
    assert res["warning_badge"] is None
    assert res["matched_identifiers"] == []


def test_db_log_threat_and_repeat_sender_detection(temp_db):
    row_id1 = log_threat(
        sender_handle="badguy@scam.com",
        threat_type="phishing",
        risk_score=90,
        impersonated_target="Netflix",
        extracted_links=["https://netflix-fake.xyz/login"],
        notes="First encounter",
        db_path=temp_db,
    )
    assert row_id1 > 0

    # First check on same sender
    res = check_repeat_offender("badguy@scam.com", db_path=temp_db)
    assert res["is_repeat_offender"] is True
    assert res["repeat_count"] == 1
    assert "⚠️ REPEAT OFFENDER: Observed 1 time previously" in res["warning_badge"]
    assert "badguy@scam.com" in res["matched_identifiers"]
    assert res["previous_risk_scores"] == [90]
    assert "phishing" in res["previous_threat_types"]

    # Log second encounter
    row_id2 = log_threat(
        sender_handle="badguy@scam.com",
        threat_type="credential_harvesting",
        risk_score=95,
        impersonated_target="Netflix",
        extracted_links=["https://netflix-fake2.xyz"],
        notes="Second encounter",
        db_path=temp_db,
    )
    assert row_id2 > row_id1

    # Check repeat count updated to 2
    res2 = check_repeat_offender("badguy@scam.com", db_path=temp_db)
    assert res2["is_repeat_offender"] is True
    assert res2["repeat_count"] == 2
    assert "⚠️ REPEAT OFFENDER: Observed 2 times previously" in res2["warning_badge"]


def test_db_repeat_offender_url_matching(temp_db):
    log_threat(
        sender_handle="phisher1@somewhere.com",
        threat_type="fake_discount",
        risk_score=80,
        impersonated_target="Rolex Store",
        extracted_links=["https://cheap-rolex-store.xyz/checkout"],
        notes="Scam domain logged",
        db_path=temp_db,
    )

    # Different sender, but identical malicious URL
    res = check_repeat_offender(
        sender_handle="different_sender@other.com",
        links=["https://cheap-rolex-store.xyz/checkout"],
        db_path=temp_db,
    )
    assert res["is_repeat_offender"] is True
    assert res["repeat_count"] == 1
    assert "https://cheap-rolex-store.xyz/checkout" in res["matched_identifiers"]


def test_db_get_all_records_and_clear(temp_db):
    log_threat(
        sender_handle="user1@test.com",
        threat_type="phishing",
        risk_score=50,
        impersonated_target="Bank",
        db_path=temp_db,
    )
    log_threat(
        sender_handle="user2@test.com",
        threat_type="impersonation",
        risk_score=75,
        impersonated_target="Mom",
        db_path=temp_db,
    )

    records = get_all_records(limit=10, db_path=temp_db)
    assert len(records) == 2
    assert records[0]["sender_handle"] == "user2@test.com"

    clear_db(db_path=temp_db)
    assert len(get_all_records(db_path=temp_db)) == 0


# ==============================================================================
# FEATURE 2: Family Emergency Impersonation Detector Schema Tests
# ==============================================================================

def test_threat_signals_family_emergency_fields():
    signals = ThreatSignals(
        urgency_detected=True,
        urgency_explanation="I dropped my phone in water and need money right now",
        sensitive_info_requested=True,
        sensitive_info_details=["wire transfer", "cashapp"],
        impersonation_target="Daughter / Family Member",
        family_emergency_flag=True,
        family_emergency_details="Stranded at airport asking for urgent wire transfer from a temporary number",
        is_account_takeover_likely=True,
        key_findings=["Family emergency impersonation driver", "Urgent fund request"],
    )

    assert signals.family_emergency_flag is True
    assert signals.is_account_takeover_likely is True
    assert "Stranded at airport" in signals.family_emergency_details


def test_threat_signals_family_emergency_default_values():
    signals = ThreatSignals(
        urgency_detected=False,
        sensitive_info_requested=False,
        key_findings=["Clean message"],
    )
    assert signals.family_emergency_flag is False
    assert signals.family_emergency_details is None
    assert signals.is_account_takeover_likely is False


# ==============================================================================
# FEATURE 3: Honeypot & Reverse-Interrogation Tests
# ==============================================================================

def test_honeypot_schema_models():
    probe = ProbeItem(
        name="Infrastructure Probe",
        strategy="Coax payment portal URL",
        copy_text="Could you send your direct billing link?",
    )
    assert probe.name == "Infrastructure Probe"

    analysis = HoneypotAnalysis(
        attacker_objective="Extract wire transfer",
        playbook_analysis="Urgency driver",
        infrastructure_probe=probe,
        consistency_check=probe,
        fake_compliance=probe,
    )
    assert analysis.attacker_objective == "Extract wire transfer"


def test_generate_counter_probe_deterministic_fallback():
    probes = generate_counter_probe(
        attacker_last_message="URGENT: Click here to verify your account or it will be suspended.",
        force_fallback=True,
    )

    assert "attacker_objective" in probes
    assert "playbook_analysis" in probes
    assert "infrastructure_probe" in probes
    assert "consistency_check" in probes
    assert "fake_compliance" in probes

    assert len(probes["infrastructure_probe"]["copy_text"]) > 10
    assert len(probes["consistency_check"]["copy_text"]) > 10
    assert len(probes["fake_compliance"]["copy_text"]) > 10


def test_generate_counter_probe_family_emergency_variation():
    msg = "Mom, my phone broke! This is my temporary number, I'm stranded at the hospital and need $500 right now."
    probes = generate_counter_probe(attacker_last_message=msg, force_fallback=True)

    assert "family" in probes["attacker_objective"].lower() or "emergency" in probes["attacker_objective"].lower()
    # Check that the consistency probe asks a personal verification question
    assert any(
        kw in probes["consistency_check"]["copy_text"].lower()
        for kw in ["cabin", "dog", "street", "summer", "remind me"]
    )


def test_generate_counter_probe_with_mocked_llm(monkeypatch):
    mock_payload = HoneypotAnalysis(
        attacker_objective="Direct swift transfer extraction",
        playbook_analysis="Manufactured panic driver",
        infrastructure_probe=ProbeItem(
            name="Infrastructure Probe",
            strategy="Extract domain registration",
            copy_text="Can you provide your legal company registration number?",
        ),
        consistency_check=ProbeItem(
            name="Consistency Check",
            strategy="Ask for known reference",
            copy_text="What was our last invoice reference ID?",
        ),
        fake_compliance=ProbeItem(
            name="Fake Compliance",
            strategy="Force routing details",
            copy_text="Please give me the destination bank name and branch routing code.",
        ),
    )

    mock_response = MagicMock()
    mock_response.text = mock_payload.model_dump_json()

    monkeypatch.setattr("src.honeypot.generate_with_fallback", lambda **kwargs: mock_response)

    dummy_client = MagicMock()
    probes = generate_counter_probe(
        attacker_last_message="Please transfer $500 immediately to avoid arrest.",
        client=dummy_client,
    )

    assert probes["attacker_objective"] == "Direct swift transfer extraction"
    assert "legal company registration" in probes["infrastructure_probe"]["copy_text"]
    assert "invoice reference ID" in probes["consistency_check"]["copy_text"]


# ==============================================================================
# FEATURE 4: E-Commerce Fake Discount & Scam Store Heuristic Tests
# ==============================================================================

def test_ecommerce_steep_percentage_discount():
    res = analyze_ecommerce_discount("Massive clearance sale! 90% off all inventory today only!")
    assert res["is_fake_discount_likely"] is True
    assert res["discount_rate"] == 90.0
    assert "exceeding normal retail margin" in res["risk_summary"]


def test_ecommerce_was_now_price_drop():
    res = analyze_ecommerce_discount("Special deal: Was $1200 now only $89! Flash sale ends in 10 minutes.")
    assert res["is_fake_discount_likely"] is True
    assert res["discount_rate"] is not None
    assert res["discount_rate"] > 90.0
    assert len(res["urgency_markers_found"]) > 0


def test_ecommerce_luxury_brand_markdown():
    res = analyze_ecommerce_discount(
        text="Authentic Rolex and Dyson airwrap sale! Was $1500 now $499.",
        url="https://cheap-luxury-deals.top",
    )
    assert res["is_fake_discount_likely"] is True
    assert res["luxury_brand_detected"] in ["rolex", "dyson"]
    assert "price-controlled brand" in res["risk_summary"]


def test_ecommerce_urgency_and_scarcity_markers():
    res = analyze_ecommerce_discount("Only 2 items left in stock! Hurry, flash sale ends in 5 minutes! Claim before timer expires.")
    assert len(res["urgency_markers_found"]) >= 2
    assert any("scarcity" in m.lower() or "countdown" in m.lower() for m in res["urgency_markers_found"])


def test_ecommerce_benign_commercial_offer():
    res = analyze_ecommerce_discount("Welcome to our online bookstore! Enjoy 15% off your first purchase.")
    assert res["is_fake_discount_likely"] is False
    assert res["discount_rate"] == 15.0
    assert res["luxury_brand_detected"] is None
    assert "conventional commercial parameters" in res["risk_summary"]


# ==============================================================================
# FEATURE 5: Authentication & Incognito Guest Mode Tests
# ==============================================================================

def test_user_creation_and_verification(temp_db):
    # Test valid user creation
    assert create_user("alice", "CyberSecret123!", db_path=temp_db) is True
    # Test duplicate prevention
    assert create_user("alice", "AnotherPassword", db_path=temp_db) is False
    # Test case-insensitivity on creation
    assert create_user("ALICE", "AnotherPassword", db_path=temp_db) is False

    # Test invalid / empty credentials
    assert create_user("", "pass", db_path=temp_db) is False
    assert create_user("bob", "", db_path=temp_db) is False

    # Test verification
    assert verify_user("alice", "CyberSecret123!", db_path=temp_db) is True
    assert verify_user("ALICE", "CyberSecret123!", db_path=temp_db) is True
    assert verify_user("alice", "WrongPassword", db_path=temp_db) is False
    assert verify_user("nonexistent", "somepass", db_path=temp_db) is False


def test_log_threat_guest_mode_bypass(temp_db):
    # Guest mode should NOT log to database and should return 0
    row_id = log_threat(
        sender_handle="phish@evil.com",
        threat_type="phishing",
        risk_score=90,
        impersonated_target="Bank",
        db_path=temp_db,
        is_guest=True,
    )
    assert row_id == 0

    records = get_all_records(db_path=temp_db)
    assert len(records) == 0


def test_user_specific_threat_records_filtering(temp_db):
    # Create two users
    create_user("operator_a", "PassA123", db_path=temp_db)
    create_user("operator_b", "PassB123", db_path=temp_db)

    # Log threat for operator_a
    log_threat(
        sender_handle="scam_a@evil.com",
        threat_type="phishing",
        risk_score=85,
        impersonated_target="TargetA",
        db_path=temp_db,
        username="operator_a",
    )

    # Log threat for operator_b
    log_threat(
        sender_handle="scam_b@evil.com",
        threat_type="credential_harvesting",
        risk_score=95,
        impersonated_target="TargetB",
        db_path=temp_db,
        username="operator_b",
    )

    # Verify filtering
    records_a = get_all_records(db_path=temp_db, username="operator_a")
    assert len(records_a) == 1
    assert records_a[0]["sender_handle"] == "scam_a@evil.com"
    assert records_a[0]["username"] == "operator_a"

    records_b = get_all_records(db_path=temp_db, username="operator_b")
    assert len(records_b) == 1
    assert records_b[0]["sender_handle"] == "scam_b@evil.com"
    assert records_b[0]["username"] == "operator_b"

    # All records without filter
    all_records = get_all_records(db_path=temp_db)
    assert len(all_records) == 2


def test_scammer_turn_schema():
    from src.honeypot import ScammerTurn
    turn = ScammerTurn(
        reply="Please confirm your account password right now.",
        tactic="⚡ Tactic: False Urgency | 🎯 Objective: Credential Harvesting",
    )
    assert "password" in turn.reply
    assert "False Urgency" in turn.tactic


def test_simulate_scammer_reply_deterministic():
    from src.honeypot import simulate_scammer_reply
    res = simulate_scammer_reply(
        messages=[{"role": "user", "content": "What is your official employee badge number?"}],
        persona="Bank Fraud Department",
        force_fallback=True,
    )
    assert "content" in res
    assert "tactic" in res
    assert len(res["content"]) > 10
    assert "⚡ Tactic:" in res["tactic"]
    assert "🎯 Objective:" in res["tactic"]


def test_simulate_scammer_reply_family_distress():
    from src.honeypot import simulate_scammer_reply
    res = simulate_scammer_reply(
        messages=[{"role": "user", "content": "Where did we go on vacation last year?"}],
        persona="Urgent Family Distress",
        force_fallback=True,
    )
    assert "content" in res
    assert "tactic" in res
    assert "Emotional Coercion" in res["tactic"]


def test_simulate_scammer_reply_on_429_quota_error():
    from src.honeypot import simulate_scammer_reply
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception(
        "429 RESOURCE_EXHAUSTED: Rate limit exceeded for quota"
    )

    res = simulate_scammer_reply(
        messages=[{"role": "user", "content": "What is your badge number?"}],
        persona="Bank Fraud Department",
        client=mock_client,
    )

    assert "Urgent: Your account verification failed" in res["content"]
    assert "6-digit confirmation code" in res["content"]
    assert res["tactic"] == "⚡ Tactic: False Urgency & Credential Harvesting"


def test_simulate_scammer_reply_on_429_family_lure():
    from src.honeypot import simulate_scammer_reply
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception(
        "429 RESOURCE_EXHAUSTED: Rate limit exceeded"
    )

    res = simulate_scammer_reply(
        messages=[{"role": "user", "content": "Are you really my son?"}],
        persona="Urgent Family Distress",
        client=mock_client,
    )

    assert "6-digit confirmation code" in res["content"]
    assert res["tactic"] == "⚡ Tactic: False Urgency & Credential Harvesting"


def test_simulate_scammer_reply_on_404_or_general_exception():
    from src.honeypot import simulate_scammer_reply
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception(
        "404 NOT_FOUND: models/gemini-2.5-flash is not found"
    )

    res = simulate_scammer_reply(
        messages=[{"role": "user", "content": "Who is this?"}],
        persona="Bank Fraud Department",
        client=mock_client,
    )

    assert "6-digit confirmation code" in res["content"]
    assert res["tactic"] == "⚡ Tactic: False Urgency & Credential Harvesting"




