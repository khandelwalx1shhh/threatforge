from pydantic import BaseModel, Field, model_validator, ConfigDict
from typing import List, Optional, Dict, Any
from app.schemas.common import ExtractedIndicator, RiskBreakdownFactor

class AnalyzeRequest(BaseModel):
    text: Optional[str] = Field(default=None, max_length=5000, description="Message text to analyze for scam/fraud risk")
    message: Optional[str] = Field(default=None, max_length=5000, description="Alternative field for message text")
    source: Optional[str] = Field(default="manual_test", description="Source channel: whatsapp, telegram, manual_test")
    cloud_analysis: bool = Field(default=False, description="Whether cloud analysis is enabled (defaults to False)")
    sender: Optional[str] = Field(default=None, description="Sender identifier")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Optional extra metadata context")

    @model_validator(mode="before")
    @classmethod
    def validate_request_payload(cls, data: Any):
        if not isinstance(data, dict):
            return data

        # Validate source
        src = data.get("source", "manual_test")
        if src is not None:
            valid_sources = {"whatsapp", "telegram", "manual_test"}
            src_str = str(src).lower().strip()
            if src_str not in valid_sources:
                raise ValueError(f"Invalid source '{src}'. Supported sources: whatsapp, telegram, manual_test")
            data["source"] = src_str

        # Validate text or message
        raw_text = data.get("text")
        if raw_text is None:
            raw_text = data.get("message")

        if raw_text is None:
            raise ValueError("Field 'text' is required.")

        if not isinstance(raw_text, str):
            raise ValueError("Field 'text' must be a string.")

        cleaned = raw_text.strip()
        if not cleaned:
            raise ValueError("Message text must not be empty or whitespace-only.")

        if len(cleaned) > 5000:
            raise ValueError("Message text exceeds maximum allowed length of 5000 characters.")

        data["text"] = cleaned
        data["message"] = cleaned
        return data

class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score integer between 0 and 100")
    risk_level: str = Field(..., description="Exact risk band: low (0-29), medium (30-59), high (60-79), critical (80-100)")
    reasons: List[str] = Field(default_factory=list, description="Explainable reasons for detected threat signals")
    recommended_action: str = Field(..., description="Recommended safe action for the user")
    indicators: List[ExtractedIndicator] = Field(default_factory=list, description="Extracted threat indicators")
    model_version: str = Field(default="text-v1", description="Identifier of the loaded ML model or 'none'")
    analysis_mode: str = Field(default="rules+ml", description="Analysis mode: 'rules+ml', 'rules', or 'ml'")

    # Optional fields for backward compatibility with React dashboard & existing clients
    summary: Optional[str] = Field(default=None, description="Executive summary")
    breakdown: Optional[List[RiskBreakdownFactor]] = Field(default_factory=list, description="Factor breakdown")
    recommendations: Optional[List[str]] = Field(default_factory=list, description="Action recommendations")
    analyzed_at: Optional[str] = Field(default=None, description="ISO timestamp")
    confidence_score: Optional[float] = Field(default=0.90, description="Confidence rating")
    uncertainty_range: Optional[str] = Field(default="±5%", description="Score uncertainty estimate")
