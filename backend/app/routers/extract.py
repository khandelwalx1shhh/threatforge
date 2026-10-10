from fastapi import APIRouter, HTTPException, status
from app.schemas.extract import ExtractRequest, ExtractResponse
from app.services.extractor import extract_indicators

router = APIRouter(prefix="/api", tags=["IOC Extraction"])

@router.post("/extract", response_model=ExtractResponse)
def extract_threat_indicators(payload: ExtractRequest):
    """
    POST /api/extract
    Extracts structured threat indicators (IOCs) from text using conservative rule-based analysis.
    Finds URLs, Emails, Phone numbers, UPI IDs, Crypto wallets, IP addresses, and Bank accounts.
    """
    if not payload.text or not payload.text.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Text payload must not be empty or whitespace-only."
        )

    indicators = extract_indicators(payload.text)

    return ExtractResponse(
        indicators=indicators,
        count=len(indicators)
    )
