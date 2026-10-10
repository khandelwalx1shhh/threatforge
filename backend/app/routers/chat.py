from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.chat import ChatRequest, ChatResponse
from app.services.honeypot_agent import process_honeypot_chat

router = APIRouter(prefix="/api", tags=["Honeypot Chat"])

@router.post("/chat", response_model=ChatResponse)
def chat_honeypot(payload: ChatRequest, db: Session = Depends(get_db)):
    """
    POST /api/chat
    Simulated honeypot persona response generation.
    Engages scammers safely in a controlled environment to coax operational intel without real interaction.
    """
    if not payload.message or not payload.message.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message payload must not be empty or whitespace-only."
        )

    session, reply, tactics, iocs = process_honeypot_chat(
        db=db,
        message=payload.message,
        session_id=payload.session_id,
        persona=payload.persona or "victim"
    )

    return ChatResponse(
        session_id=session.id,
        reply=reply,
        persona=session.persona,
        tactics_detected=tactics,
        extracted_iocs=iocs,
        turn_count=session.turn_count
    )
