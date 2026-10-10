import random
from typing import List, Tuple
from sqlalchemy.orm import Session
from app.models import HoneypotSession, HoneypotMessage, ThreatLog
from app.services.extractor import extract_indicators
from app.schemas.common import ExtractedIndicator

# Persona Response Templates
PERSONA_TEMPLATES = {
    "victim": [
        "Oh dear, I received your notice! I am a bit elderly and not very good with computers. Could you please resend the exact payment link or account number so I don't get into trouble?",
        "Thank you for contacting me. My screen gave me an error when I tried clicking that. Can you give me your UPI ID or phone number directly so I can send the money?",
        "I want to make sure I do this right. Which bank account or Bitcoin wallet address should I use for the transfer? Please spell it out clearly.",
        "Oh goodness, I don't want my account locked! Should I transfer to your UPI ID or pay online? Please guide me step by step.",
    ],
    "confused_user": [
        "I tried following your instructions but the webpage didn't load properly. Do you have an alternative link or direct payment phone number?",
        "My banking app says the account number is invalid. Can you double check the routing/UPI details and send them again?",
        "Is there another crypto wallet address or UPI ID I can use? This payment portal keeps freezing on my phone.",
    ],
    "compliant": [
        "I understand the urgency. I am ready to complete the transaction right now. Please provide the exact payment details.",
        "I am logged into my bank portal now. What is the beneficiary name and account/UPI ID to add?",
    ]
}

def detect_tactics(text: str) -> List[str]:
    """Detects scammer tactics used in incoming message."""
    tactics = []
    lower_text = text.lower()

    if any(w in lower_text for w in ["urgent", "immediately", "police", "legal", "suspended", "blocked", "warrant"]):
        tactics.append("Urgency & Coercion")
    if any(w in lower_text for w in ["otp", "pin", "password", "cvv", "verification code"]):
        tactics.append("Credential / OTP Harvesting")
    if any(w in lower_text for w in ["pay", "transfer", "send money", "fee", "fine", "deposit"]):
        tactics.append("Unsolicited Financial Demand")
    if any(w in lower_text for w in ["http", "https", "www", "link", "click"]):
        tactics.append("Phishing Domain Link")
    if any(w in lower_text for w in ["bank", "support", "customs", "tax", "police", "helpdesk"]):
        tactics.append("Impersonation of Authority")
    if any(w in lower_text for w in ["btc", "bitcoin", "eth", "usdt", "crypto", "wallet"]):
        tactics.append("Cryptocurrency Transfer Request")

    if not tactics:
        tactics.append("Social Engineering Probe")

    return tactics

def process_honeypot_chat(
    db: Session,
    message: str,
    session_id: str = None,
    persona: str = "victim"
) -> Tuple[HoneypotSession, str, List[str], List[ExtractedIndicator]]:
    """
    Processes incoming scammer message in simulated honeypot environment.
    - Updates/creates HoneypotSession
    - Persists scammer message and agent response
    - Extracts IOCs and persists to ThreatLog DB
    - Generates safe persona response to coax further intel
    """
    clean_persona = persona.lower() if persona in PERSONA_TEMPLATES else "victim"

    # Get or create session
    if session_id:
        session = db.query(HoneypotSession).filter(HoneypotSession.id == session_id).first()
        if not session:
            session = HoneypotSession(id=session_id, persona=clean_persona)
            db.add(session)
    else:
        session = HoneypotSession(persona=clean_persona)
        db.add(session)

    db.flush()

    # Detect tactics
    tactics = detect_tactics(message)
    existing_tactics = list(session.tactics_json or [])
    updated_tactics = list(set(existing_tactics + tactics))
    session.tactics_json = updated_tactics
    session.turn_count = (session.turn_count or 0) + 1

    # Extract IOCs
    extracted = extract_indicators(message)
    for ioc in extracted:
        # Check if already logged
        existing_log = db.query(ThreatLog).filter(
            ThreatLog.type == ioc.type,
            ThreatLog.value == ioc.value
        ).first()
        if not existing_log:
            threat_entry = ThreatLog(
                type=ioc.type,
                value=ioc.value,
                severity=ioc.severity.value,
                confidence=ioc.confidence,
                source=f"Honeypot Session #{session.id}",
                context=ioc.context,
                metadata_json=ioc.metadata or {}
            )
            db.add(threat_entry)

    # Save Scammer message
    scammer_msg = HoneypotMessage(
        session_id=session.id,
        sender_role="scammer",
        text=message
    )
    db.add(scammer_msg)

    # Select persona response turn
    options = PERSONA_TEMPLATES.get(clean_persona, PERSONA_TEMPLATES["victim"])
    reply = options[(session.turn_count - 1) % len(options)]

    # Save Agent response
    agent_msg = HoneypotMessage(
        session_id=session.id,
        sender_role="agent",
        text=reply
    )
    db.add(agent_msg)

    db.commit()
    db.refresh(session)

    return session, reply, updated_tactics, extracted
