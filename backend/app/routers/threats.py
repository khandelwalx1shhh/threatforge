from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional
from app.database import get_db
from app.models import ThreatLog
from app.schemas.threats import ThreatsListResponse, ThreatItem
from app.schemas.common import SeverityEnum

router = APIRouter(prefix="/api", tags=["Threat Intelligence"])

def format_relative_time(dt) -> str:
    if not dt:
        return "recently"
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = int((now - dt).total_seconds())
    if diff < 60:
        return "Just now"
    elif diff < 3600:
        return f"{diff // 60} min ago"
    elif diff < 86400:
        return f"{diff // 3600} hours ago"
    else:
        return f"{diff // 86400} days ago"

@router.get("/threats", response_model=ThreatsListResponse)
def list_threats(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    severity: Optional[str] = None,
    query: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    GET /api/threats
    Returns logged threat indicators from database with filtering, search, and pagination.
    """
    q = db.query(ThreatLog)

    if severity:
        q = q.filter(ThreatLog.severity == severity.upper())

    if query and query.strip():
        search_pattern = f"%{query.strip()}%"
        q = q.filter((ThreatLog.value.like(search_pattern)) | (ThreatLog.type.like(search_pattern)))

    total = q.count()
    offset = (page - 1) * size
    records = q.order_by(ThreatLog.detected_at.desc()).offset(offset).limit(size).all()

    items = []
    for r in records:
        try:
            sev_enum = SeverityEnum(r.severity.upper())
        except ValueError:
            sev_enum = SeverityEnum.MEDIUM

        items.append(ThreatItem(
            id=r.id,
            type=r.type,
            value=r.value,
            severity=sev_enum,
            time=format_relative_time(r.detected_at),
            source=r.source or "Honeypot Session",
            risk_score=r.risk_score or 0.0
        ))

    return ThreatsListResponse(
        items=items,
        total=total,
        page=page,
        size=size
    )

@router.delete("/threats/history")
def delete_threat_history(db: Session = Depends(get_db)):
    """
    DELETE /api/threats/history
    Privacy & Trust feature: Permanently wipes all recorded threat logs, analysis reports,
    and cached indicators to support user right-to-be-forgotten and history deletion.
    """
    from app.models import AnalysisReport
    threats_deleted = db.query(ThreatLog).delete()
    reports_deleted = db.query(AnalysisReport).delete()
    db.commit()
    return {
        "status": "success",
        "message": "All threat intelligence history and analysis reports have been permanently deleted.",
        "threats_purged": threats_deleted,
        "reports_purged": reports_deleted
    }

@router.post("/threats/purge")
def purge_threat_retention(
    retention_days: int = Query(7, ge=1, le=365, description="Retention threshold in days"),
    db: Session = Depends(get_db)
):
    """
    POST /api/threats/purge
    Purges threat records and reports older than the specified retention window (default: 7 days).
    """
    from datetime import datetime, timezone, timedelta
    from app.models import AnalysisReport
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    threats_purged = db.query(ThreatLog).filter(ThreatLog.detected_at < cutoff).delete()
    reports_purged = db.query(AnalysisReport).filter(AnalysisReport.created_at < cutoff).delete()
    db.commit()

    return {
        "status": "success",
        "retention_days": retention_days,
        "cutoff_timestamp": cutoff.isoformat(),
        "threats_purged": threats_purged,
        "reports_purged": reports_purged
    }

@router.get("/privacy/policy")
def get_privacy_transparency_policy():
    """
    GET /api/privacy/policy
    Returns transparent machine-readable privacy policy and client data handling disclosures.
    """
    return {
        "policy_version": "1.0.0",
        "zero_crawling_guarantee": True,
        "pre_transmission_sanitization": True,
        "client_side_token_scrubbing": True,
        "raw_message_logging_disabled": True,
        "default_retention_days": 7,
        "data_collected": [
            "Sanitized message text with tokens and OTPs redacted",
            "Whitelisted messaging source (WhatsApp or Telegram)",
            "Pseudonymized sender identifier",
            "Extracted suspicious threat indicators (unverified)"
        ],
        "data_never_collected": [
            "Contact lists and address books",
            "Full chat conversations and messaging history",
            "Banking credentials, account pins, and OTP passcodes",
            "Other app notifications (emails, SMS, banking apps)",
            "Device hardware serials, IMEI, or advertising IDs"
        ]
    }

