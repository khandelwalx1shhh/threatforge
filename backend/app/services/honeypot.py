from typing import Tuple, List
from sqlalchemy.orm import Session
from app.models import HoneypotSession, HoneypotMessage, ThreatLog
from app.services.extractor import extract_indicators
from app.schemas.common import ExtractedIndicator

PERSONA_RESPONSES = {
    "victim": [
        "Oh dear, I received your message! I am a bit elderly and not very good with technology. Could you please send me the exact payment link or account number again so I don't get into trouble?",
        "Thank you for guiding me. My screen gave an error when I tried that. Can you share your UPI ID or phone number directly so I can send the money?",
        "I want to make sure I do this right. Which bank account or Bitcoin wallet address should I transfer to? Please spell it out clearly.",
        "Oh goodness, I don't want my account locked! Should I transfer to your UPI ID or pay online? Please help me step by step.",
    ],
    "confused_user": [
        "I tried following your link but it didn't open properly on my phone. Do you have a direct UPI ID or alternative server URL?",
        "My payment app says the account number is invalid. Could you double-check the routing or phone number details and send them again?",
        "Is there another crypto wallet address or bank account I can use? This payment portal keeps freezing.",
    ]
}

SAFETY_WARNING = (
    "SIMULATION ONLY: This honeypot response is generated locally inside an isolated sandbox. "
    "No real external messages are sent to scammers or third-party networks."
)

def run_honeypot_chat_turn(
    db: Session,
    message: str,
    session_id: str = None,
    persona: str = "victim"
) -> Tuple[HoneypotSession, str, List[str], List[ExtractedIndicator], str]:
    """
    Executes a turn in the simulated honeypot chat sandbox.
    Guarantees no outbound external communications are sent.
    """
    clean_persona = persona.lower() if persona in PERSONA_RESPONSES else "victim"

    # Get or create HoneypotSession
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
    tactics = []
    lower_msg = message.lower()
    if any(w in lower_msg for w in ["urgent", "immediately", "police", "legal", "suspended", "blocked", "warrant"]):
        tactics.append("Urgency & Coercion")
    if any(w in lower_msg for w in ["otp", "pin", "password", "cvv", "verification code"]):
        tactics.append("Credential / OTP Harvesting")
    if any(w in lower_msg for w in ["pay", "transfer", "send money", "fee", "fine", "deposit"]):
        tactics.append("Unsolicited Financial Demand")
    if any(w in lower_msg for w in ["http", "https", "www", "link", "click"]):
        tactics.append("Phishing Domain Link")
    if any(w in lower_msg for w in ["bank", "support", "customs", "tax", "police", "helpdesk"]):
        tactics.append("Impersonation of Authority")
    if any(w in lower_msg for w in ["btc", "bitcoin", "eth", "usdt", "crypto", "wallet"]):
        tactics.append("Cryptocurrency Transfer Request")

    if not tactics:
        tactics.append("Social Engineering Probe")

    existing_tactics = list(session.tactics_json or [])
    updated_tactics = list(set(existing_tactics + tactics))
    session.tactics_json = updated_tactics
    session.turn_count = (session.turn_count or 0) + 1

    # Extract IOCs from incoming message
    extracted = extract_indicators(message)
    for ioc in extracted:
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

    # Generate honeypot persona response (AI generated via Gemini if key present, else local deterministic template)
    from app.services.gemini_detector import gemini_detector
    ai_reply = gemini_detector.generate_honeypot_reply(message, clean_persona, session.turn_count) if gemini_detector.is_available else None
    if ai_reply:
        reply = ai_reply
    else:
        options = PERSONA_RESPONSES.get(clean_persona, PERSONA_RESPONSES["victim"])
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

    return session, reply, updated_tactics, extracted, SAFETY_WARNING
