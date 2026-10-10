from fastapi import APIRouter
from app.schemas.dashboard import DashboardResponse, DashboardMetrics, ActivityItem, ThreatDistributionCategory
from app.schemas.threats import ThreatItem
from app.schemas.common import SeverityEnum

router = APIRouter(prefix="/api", tags=["Dashboard Metrics"])

@router.get("/dashboard", response_model=DashboardResponse)
def get_dashboard_metrics():
    """
    GET /api/dashboard
    Returns aggregated metrics and activity logs for security overview dashboard.
    """
    metrics = DashboardMetrics(
        total_sessions=128,
        indicators_captured=346,
        high_severity_count=23,
        active_sessions=7,
        sessions_change="↑ 12%",
        indicators_change="↑ 8.4%"
    )
    threats = [
        ThreatItem(id="TF-1", type="Phishing URL", value="secure-banking-verify.example", severity=SeverityEnum.HIGH, time="2 min ago"),
        ThreatItem(id="TF-2", type="UPI ID", value="support-alert@upi", severity=SeverityEnum.MEDIUM, time="8 min ago"),
        ThreatItem(id="TF-3", type="Suspicious Phone", value="+91 98XXX XX421", severity=SeverityEnum.HIGH, time="14 min ago"),
        ThreatItem(id="TF-4", type="Social Engineering", value="Urgent account verification", severity=SeverityEnum.LOW, time="21 min ago"),
    ]
    activity = [
        ActivityItem(title="New honeypot session started", detail="Session #TF-1042", time="Just now"),
        ActivityItem(title="Suspicious indicator extracted", detail="Phishing URL · Session #TF-1040", time="2 min ago"),
        ActivityItem(title="Threat severity updated", detail="HIGH · Session #TF-1038", time="8 min ago"),
    ]
    distribution = [
        ThreatDistributionCategory(category="Phishing URLs", count=76, percentage=76.0),
        ThreatDistributionCategory(category="Phone numbers", count=54, percentage=54.0),
        ThreatDistributionCategory(category="UPI IDs", count=42, percentage=42.0),
        ThreatDistributionCategory(category="Other indicators", count=28, percentage=28.0),
    ]
    return DashboardResponse(
        metrics=metrics,
        threats=threats,
        activity=activity,
        distribution=distribution
    )
