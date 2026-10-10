from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum

class SeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IndicatorTypeEnum(str, Enum):
    URL = "Phishing URL"
    IP = "IP Address"
    CRYPTO = "Crypto Wallet"
    PHONE = "Suspicious Phone"
    EMAIL = "Email Address"
    UPI = "UPI ID"
    BANK = "Bank Account"
    SOCIAL = "Social Engineering"
    OTHER = "Other Indicator"

class ExtractedIndicator(BaseModel):
    type: str = Field(..., description="Category/type of indicator (e.g., Phishing URL, UPI ID, Phone)")
    value: str = Field(..., description="The indicator value (e.g., domain, IP, phone number, wallet address)")
    severity: SeverityEnum = Field(default=SeverityEnum.MEDIUM, description="Severity rating: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0, description="Extraction confidence score (0.0 to 1.0)")
    context: Optional[str] = Field(default=None, description="Surrounding text snippet where indicator was found")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata (e.g., domain registrar, ISP)")

class RiskBreakdownFactor(BaseModel):
    factor: str = Field(..., description="Name of the risk factor (e.g., Urgency Language, Crypto Payment)")
    score: float = Field(..., ge=0.0, le=100.0, description="Score contribution for this factor")
    description: str = Field(..., description="Explanation of why this factor contributed to risk")
    severity: SeverityEnum = Field(default=SeverityEnum.MEDIUM)
