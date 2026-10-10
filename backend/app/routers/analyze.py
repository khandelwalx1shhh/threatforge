from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_scam_risk
from app.models import AnalysisReport, ThreatLog

router = APIRouter(prefix="/api", tags=["Threat Analysis"])

@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_threat(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    POST /api/analyze
    Analyzes suspicious text/message for scam risk scoring, reasons, and recommended action.
    Combines trained ML classifier and explainable deterministic rules.
    Persists analysis report and logs extracted threat indicators into database.
    """
    text_to_analyze = payload.text or payload.message
    if not text_to_analyze or not text_to_analyze.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message text must not be empty or whitespace-only."
        )

    result = analyze_scam_risk(
        message=text_to_analyze,
        sender=payload.sender,
        source=payload.source,
        cloud_analysis=payload.cloud_analysis,
        raw_headers=payload.raw_headers,
        headers=payload.headers
    )

    # Persist report to database
    report = AnalysisReport(
        message=text_to_analyze,
        sender=payload.sender,
        risk_score=float(result.risk_score),
        risk_level=result.risk_level,
        summary=result.summary or f"{result.risk_level.upper()} RISK ({result.risk_score}/100)",
        breakdown_json=[f.model_dump() for f in (result.breakdown or [])],
        recommendations_json=result.recommendations or [result.recommended_action]
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
                risk_score=float(result.risk_score),
                source=f"Analysis ({payload.source or 'manual_test'})",
                context=ioc.context,
                metadata_json=ioc.metadata or {}
            )
            db.add(threat)

    db.commit()

    return result
