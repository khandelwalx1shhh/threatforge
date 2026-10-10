from fastapi import APIRouter
from app.schemas.chat import ChatRequest, ChatResponse
import uuid

router = APIRouter(prefix="/api", tags=["Honeypot Chat"])

@router.post("/chat", response_model=ChatResponse)
def chat_honeypot(payload: ChatRequest):
    """
    POST /api/chat
    Simulated honeypot persona response generation.
    """
    session_id = payload.session_id or f"TF-{uuid.uuid4().hex[:6].upper()}"
    return ChatResponse(
        session_id=session_id,
        reply="Placeholder honeypot agent response.",
        persona=payload.persona or "victim",
        tactics_detected=[],
        extracted_iocs=[],
        turn_count=1
    )
