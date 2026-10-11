from fastapi import FastAPI, Request, status, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
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

# Development CORS configured strictly for local development origins
DEVELOPMENT_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://10.21.96.95:5173",
    "http://10.21.96.95:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=DEVELOPMENT_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Phase 5: Consistent Error Exception Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    messages = []
    for err in errors:
        loc = " -> ".join([str(x) for x in err.get("loc", []) if str(x) != "body"])
        msg = err.get("msg", "Invalid field")
        messages.append(f"{loc}: {msg}" if loc else msg)
    readable_msg = "; ".join(messages) or "Validation failed for input parameters."
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error": {"code": "VALIDATION_ERROR", "message": readable_msg}}
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    code_str = "BAD_REQUEST"
    if exc.status_code == 404:
        code_str = "NOT_FOUND"
    elif exc.status_code == 422:
        code_str = "VALIDATION_ERROR"
    elif exc.status_code == 401:
        code_str = "UNAUTHORIZED"
    elif exc.status_code == 403:
        code_str = "FORBIDDEN"

    message_str = exc.detail if isinstance(exc.detail, str) else "HTTP Exception"
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": code_str, "message": message_str}}
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Ensure internal server errors never expose secrets or raw message contents
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": {"code": "INTERNAL_SERVER_ERROR", "message": "An unexpected server error occurred. Please try again later."}}
    )

# Register API routers
app.include_router(analyze.router)
app.include_router(chat.router)
app.include_router(extract.router)
app.include_router(threats.router)
app.include_router(dashboard.router)

@app.get("/health", tags=["Health"])
def health_check():
    from app.services.model_manager import model_manager
    from app.services.distilbert_detector import distilbert_detector
    from app.services.url_analyzer import url_classifier_service
    from app.services.gemini_detector import gemini_detector
    return {
        "status": "ok",
        "model_loaded": model_manager.is_loaded,
        "url_model_loaded": url_classifier_service.is_available(),
        "url_model_version": url_classifier_service.model_version,
        "distilbert_loaded": distilbert_detector.is_loaded,
        "distilbert_quantized": distilbert_detector.is_quantized,
        "gemini_configured": gemini_detector.is_available,
        "gemini_model": getattr(settings, "GEMINI_MODEL", "gemini-1.5-flash")
    }
