from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_scam_risk
from app.models import AnalysisReport, ThreatLog
from json import dumps

router = APIRouter(prefix="/api", tags=["Threat Analysis"])

@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_threat(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    POST /api/analyze
    Analyzes suspicious text/message for scam risk scoring and explainable breakdown.
    Persists analysis report and logs extracted threat indicators into database.
    """
    if not payload.message or not payload.message.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message payload must not be empty or whitespace-only."
        )

    result = analyze_scam_risk(message=payload.message, sender=payload.sender)

    # Persist report
    report = AnalysisReport(
        message=payload.message,
        sender=payload.sender,
        risk_score=result.risk_score,
        risk_level=result.risk_level.value,
        summary=result.summary,
        breakdown_json=[f.model_dump() for f in result.breakdown],
        recommendations_json=result.recommendations
    )
    db.add(report)

    # Auto-log extracted IOCs
    for ioc in result.indicators:
        existing = db.query(ThreatLog).filter(
            ThreatLog.type == ioc.type,
            ThreatLog.value == ioc.value
        ).first()
        if not existing:
            threat = ThreatLog(
                type=ioc.type,
                value=ioc.value,
                severity=ioc.severity.value,
                confidence=ioc.confidence,
                risk_score=result.risk_score,
                source="Threat Analysis",
                context=ioc.context,
                metadata_json=ioc.metadata or {}
            )
            db.add(threat)

    db.commit()

    return result
