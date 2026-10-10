from fastapi import APIRouter
from app.schemas.analyze import AnalyzeRequest, AnalyzeResponse
from app.schemas.common import SeverityEnum
from datetime import datetime, timezone

router = APIRouter(prefix="/api", tags=["Threat Analysis"])

@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_threat(payload: AnalyzeRequest):
    """
    POST /api/analyze
    Analyzes suspicious text/message for scam risk scoring and explainable breakdown.
    """
    return AnalyzeResponse(
        risk_score=0.0,
        risk_level=SeverityEnum.LOW,
        summary="Placeholder analysis result.",
        breakdown=[],
        indicators=[],
        recommendations=["Placeholder recommendation"],
        analyzed_at=datetime.now(timezone.utc).isoformat()
    )
