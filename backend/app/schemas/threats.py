from pydantic import BaseModel, Field
from typing import List, Optional
from app.schemas.common import SeverityEnum

class ThreatItem(BaseModel):
    id: str = Field(..., description="Unique threat indicator identifier")
    type: str = Field(..., description="Type of indicator (e.g. Phishing URL, UPI ID, Suspicious Phone)")
    value: str = Field(..., description="Indicator value")
    severity: SeverityEnum = Field(..., description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    time: str = Field(..., description="Human-readable or ISO timestamp of detection")
    source: Optional[str] = Field(default="Honeypot Session", description="Origin source of threat indicator")
    risk_score: Optional[float] = Field(default=0.0, description="Associated risk score 0-100")

class ThreatsListResponse(BaseModel):
    items: List[ThreatItem] = Field(default_factory=list)
    total: int = Field(..., description="Total count of threat items")
    page: int = Field(default=1)
    size: int = Field(default=50)
