from pydantic import BaseModel, Field
from typing import List, Optional
from app.schemas.common import ExtractedIndicator

class ChatRequest(BaseModel):
    session_id: Optional[str] = Field(default=None, description="Honeypot conversation session ID (auto-generated if omitted)")
    message: str = Field(..., min_length=1, description="Incoming message from suspected scammer")
    persona: Optional[str] = Field(default="victim", description="Honeypot agent persona mode (e.g., victim, confused_user, compliant)")

class ChatResponse(BaseModel):
    session_id: str = Field(..., description="Unique session ID for honeypot conversation")
    reply: str = Field(..., description="Honeypot agent simulated response to engage the scammer")
    persona: str = Field(..., description="Active agent persona")
    tactics_detected: List[str] = Field(default_factory=list, description="Scam tactics identified in incoming message")
    extracted_iocs: List[ExtractedIndicator] = Field(default_factory=list, description="Indicators captured during this exchange")
    turn_count: int = Field(default=1, description="Current turn index in conversation")
