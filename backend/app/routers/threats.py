from fastapi import APIRouter
from app.schemas.threats import ThreatsListResponse, ThreatItem
from app.schemas.common import SeverityEnum
from typing import Optional

router = APIRouter(prefix="/api", tags=["Threat Intelligence"])

@router.get("/threats", response_model=ThreatsListResponse)
def list_threats(page: int = 1, size: int = 50, severity: Optional[str] = None):
    """
    GET /api/threats
    Returns logged threat indicators with optional severity filtering.
    """
    sample_items = [
        ThreatItem(id="TF-1", type="Phishing URL", value="secure-banking-verify.example", severity=SeverityEnum.HIGH, time="2 min ago"),
        ThreatItem(id="TF-2", type="UPI ID", value="support-alert@upi", severity=SeverityEnum.MEDIUM, time="8 min ago"),
        ThreatItem(id="TF-3", type="Suspicious Phone", value="+91 98XXX XX421", severity=SeverityEnum.HIGH, time="14 min ago"),
        ThreatItem(id="TF-4", type="Social Engineering", value="Urgent account verification", severity=SeverityEnum.LOW, time="21 min ago"),
    ]
    if severity:
        sample_items = [t for t in sample_items if t.severity.value.upper() == severity.upper()]

    return ThreatsListResponse(
        items=sample_items,
        total=len(sample_items),
        page=page,
        size=size
    )
