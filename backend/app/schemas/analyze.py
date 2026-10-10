from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from app.schemas.common import ExtractedIndicator, RiskBreakdownFactor, SeverityEnum

class AnalyzeRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Suspicious text or message to analyze for threat & scam risk")
    sender: Optional[str] = Field(default=None, description="Sender identifier (e.g. email, phone number, handle)")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Optional extra metadata context")

class AnalyzeResponse(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Overall risk score from 0 (safe) to 100 (critical scam)")
    risk_level: SeverityEnum = Field(..., description="Calculated risk level: LOW, MEDIUM, HIGH, CRITICAL")
    confidence_score: float = Field(default=0.90, ge=0.0, le=1.0, description="Overall confidence rating in risk calculation")
    uncertainty_range: str = Field(default="±5%", description="Uncertainty range metric e.g. ±5%")
    summary: str = Field(..., description="Executive summary of analysis findings")
    breakdown: List[RiskBreakdownFactor] = Field(default_factory=list, description="Explainable breakdown of risk factors")
    indicators: List[ExtractedIndicator] = Field(default_factory=list, description="Threat indicators detected in text")
    recommendations: List[str] = Field(default_factory=list, description="Recommended security response actions")
    analyzed_at: str = Field(..., description="ISO timestamp of analysis")
