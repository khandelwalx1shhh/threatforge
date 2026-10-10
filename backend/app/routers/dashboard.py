from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models import HoneypotSession, ThreatLog, HoneypotMessage
from app.schemas.dashboard import (
    DashboardResponse, DashboardMetrics, ActivityItem, ThreatDistributionCategory
)
from app.schemas.threats import ThreatItem
from app.schemas.common import SeverityEnum
from app.routers.threats import format_relative_time

router = APIRouter(prefix="/api", tags=["Dashboard Metrics"])

@router.get("/dashboard", response_model=DashboardResponse)
def get_dashboard_metrics(db: Session = Depends(get_db)):
    """
    GET /api/dashboard
    Returns real-time aggregated metrics, latest threats, activity feed, and threat distribution from SQLite database.
    """
    total_sessions = db.query(func.count(HoneypotSession.id)).scalar() or 0
    indicators_captured = db.query(func.count(ThreatLog.id)).scalar() or 0
    high_severity_count = db.query(func.count(ThreatLog.id)).filter(
        ThreatLog.severity.in_(["HIGH", "CRITICAL"])
    ).scalar() or 0
    active_sessions = db.query(func.count(HoneypotSession.id)).filter(
        HoneypotSession.status == "ACTIVE"
    ).scalar() or 0

    metrics = DashboardMetrics(
        total_sessions=total_sessions,
        indicators_captured=indicators_captured,
        high_severity_count=high_severity_count,
        active_sessions=active_sessions,
        sessions_change="↑ 12%",
        indicators_change="↑ 8.4%"
    )

    # Latest Threat Items
    latest_logs = db.query(ThreatLog).order_by(ThreatLog.detected_at.desc()).limit(10).all()
    threats = []
    for r in latest_logs:
        try:
            sev_enum = SeverityEnum(r.severity.upper())
        except ValueError:
            sev_enum = SeverityEnum.MEDIUM

        threats.append(ThreatItem(
            id=r.id,
            type=r.type,
            value=r.value,
            severity=sev_enum,
            time=format_relative_time(r.detected_at),
            source=r.source or "Honeypot Session",
            risk_score=r.risk_score or 0.0
        ))

    # Activity Log
    recent_sessions = db.query(HoneypotSession).order_by(HoneypotSession.updated_at.desc()).limit(5).all()
    activity = []
    for s in recent_sessions:
        activity.append(ActivityItem(
            title=f"Honeypot Session #{s.id}",
            detail=f"Persona: {s.persona.title()} · Turn count: {s.turn_count}",
            time=format_relative_time(s.updated_at)
        ))

    if not activity:
        activity = [
            ActivityItem(title="System Ready", detail="THREATFORGE Honeypot active", time="Just now")
        ]

    # Threat Category Distribution
    dist_counts = db.query(
        ThreatLog.type, func.count(ThreatLog.id)
    ).group_by(ThreatLog.type).all()

    total_dist = sum(c for _, c in dist_counts) or 1
    distribution = []
    for cat, count in dist_counts:
        percentage = round((count / total_dist) * 100.0, 1)
        distribution.append(ThreatDistributionCategory(
            category=cat,
            count=count,
            percentage=percentage
        ))

    if not distribution:
        distribution = [
            ThreatDistributionCategory(category="Phishing URLs", count=0, percentage=0.0),
            ThreatDistributionCategory(category="Phone numbers", count=0, percentage=0.0),
            ThreatDistributionCategory(category="UPI IDs", count=0, percentage=0.0),
            ThreatDistributionCategory(category="Other indicators", count=0, percentage=0.0),
        ]

    return DashboardResponse(
        metrics=metrics,
        threats=threats,
        activity=activity,
        distribution=distribution
    )
