from fastapi import APIRouter, HTTPException, status
from app.schemas.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_scam_risk

router = APIRouter(prefix="/api", tags=["Threat Analysis"])

@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_threat(payload: AnalyzeRequest):
    """
    POST /api/analyze
    Analyzes suspicious text/message for scam risk scoring and explainable breakdown.
    """
    if not payload.message or not payload.message.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message payload must not be empty or whitespace-only."
        )

    return analyze_scam_risk(message=payload.message, sender=payload.sender)
