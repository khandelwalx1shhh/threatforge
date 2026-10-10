from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import ThreatLog, HoneypotSession
from app.schemas.common import SeverityEnum, IndicatorTypeEnum

from app.routers import analyze, chat, extract, threats, dashboard

# Create database tables automatically
Base.metadata.create_all(bind=engine)

def seed_initial_demo_data():
    """Seed initial sample threat logs and honeypot sessions if database is empty."""
    db = SessionLocal()
    try:
        if db.query(ThreatLog).count() == 0:
            initial_threats = [
                ThreatLog(
                    id="TF-1",
                    type=IndicatorTypeEnum.URL.value,
                    value="secure-banking-verify.example",
                    severity=SeverityEnum.HIGH.value,
                    confidence=0.95,
                    risk_score=85.0,
                    source="Honeypot Session #TF-1040",
                    context="Visit secure-banking-verify.example to update credentials"
                ),
                ThreatLog(
                    id="TF-2",
                    type=IndicatorTypeEnum.UPI.value,
                    value="support-alert@upi",
                    severity=SeverityEnum.MEDIUM.value,
                    confidence=0.92,
                    risk_score=60.0,
                    source="Threat Analysis",
                    context="Transfer fine to support-alert@upi"
                ),
                ThreatLog(
                    id="TF-3",
                    type=IndicatorTypeEnum.PHONE.value,
                    value="+91 98XXX XX421",
                    severity=SeverityEnum.HIGH.value,
                    confidence=0.88,
                    risk_score=75.0,
                    source="Honeypot Session #TF-1038",
                    context="Call +91 98XXX XX421 immediately"
                ),
                ThreatLog(
                    id="TF-4",
                    type=IndicatorTypeEnum.SOCIAL.value,
                    value="Urgent account verification",
                    severity=SeverityEnum.LOW.value,
                    confidence=0.80,
                    risk_score=20.0,
                    source="Threat Analysis",
                    context="Urgent account verification required"
                )
            ]
            db.add_all(initial_threats)

        if db.query(HoneypotSession).count() == 0:
            s1 = HoneypotSession(id="TF-1042", persona="victim", status="ACTIVE", turn_count=3, tactics_json=["Urgency & Coercion", "Unsolicited Financial Demand"])
            s2 = HoneypotSession(id="TF-1040", persona="confused_user", status="ACTIVE", turn_count=2, tactics_json=["Phishing Domain Link"])
            s3 = HoneypotSession(id="TF-1038", persona="compliant", status="CLOSED", turn_count=5, tactics_json=["Impersonation of Authority"])
            db.add_all([s1, s2, s3])

        db.commit()
    except Exception as e:
        db.rollback()
    finally:
        db.close()

seed_initial_demo_data()

app = FastAPI(
    title=settings.APP_NAME,
    description="AI-powered honeypot cybersecurity MVP API for threat intelligence, risk analysis, and automated scammer interaction.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers
app.include_router(analyze.router)
app.include_router(chat.router)
app.include_router(extract.router)
app.include_router(threats.router)
app.include_router(dashboard.router)

@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "ok"}
