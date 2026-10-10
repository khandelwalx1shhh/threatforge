from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings

from app.routers import analyze, chat, extract, threats, dashboard

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
