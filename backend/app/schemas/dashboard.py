from pydantic import BaseModel, Field
from typing import List
from app.schemas.threats import ThreatItem

class DashboardMetrics(BaseModel):
    total_sessions: int = Field(..., description="Total honeypot sessions conducted")
    indicators_captured: int = Field(..., description="Total threat indicators extracted")
    high_severity_count: int = Field(..., description="Count of high/critical severity threats")
    active_sessions: int = Field(..., description="Currently active honeypot sessions")
    sessions_change: str = Field(default="↑ 12%", description="Percent change label vs previous period")
    indicators_change: str = Field(default="↑ 8.4%", description="Percent change label vs previous period")

class ActivityItem(BaseModel):
    title: str = Field(..., description="Title of recent activity event")
    detail: str = Field(..., description="Subtext detail for activity event")
    time: str = Field(..., description="Relative timestamp label")

class ThreatDistributionCategory(BaseModel):
    category: str = Field(..., description="Indicator category label")
    count: int = Field(..., description="Total count in this category")
    percentage: float = Field(..., description="Percentage representation")

class DashboardResponse(BaseModel):
    metrics: DashboardMetrics
    threats: List[ThreatItem] = Field(default_factory=list, description="Latest threat indicators for dashboard view")
    activity: List[ActivityItem] = Field(default_factory=list, description="Recent activity feed")
    distribution: List[ThreatDistributionCategory] = Field(default_factory=list, description="Threat distribution breakdown")
