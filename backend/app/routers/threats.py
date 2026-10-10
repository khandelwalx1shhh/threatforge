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
