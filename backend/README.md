# THREATFORGE Backend API

AI-powered honeypot cybersecurity MVP API built with Python, FastAPI, Pydantic, and SQLite/SQLAlchemy.

## Quick Start

### 1. Requirements
- Python 3.10+

### 2. Setup Environment
```bash
cd backend
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 4. Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 5. Run API Server
```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 6. Interactive Documentation
- OpenAPI Docs (Swagger UI): [http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

## Endpoints Summary

- `GET /health`: Health check endpoint (`{"status": "ok"}`)
- `POST /api/analyze`: Explainable scam risk scoring
- `POST /api/chat`: Simulated honeypot persona engagement
- `POST /api/extract`: Structured IOC extraction and validation
- `GET /api/threats`: Threat log listing with filtering and search
- `GET /api/dashboard`: Threat intelligence dashboard metrics

## Testing
Run unit and integration tests:
```bash
pytest
```
