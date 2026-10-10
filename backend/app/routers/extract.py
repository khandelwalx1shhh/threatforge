from fastapi import APIRouter
from app.schemas.extract import ExtractRequest, ExtractResponse

router = APIRouter(prefix="/api", tags=["IOC Extraction"])

@router.post("/extract", response_model=ExtractResponse)
def extract_indicators(payload: ExtractRequest):
    """
    POST /api/extract
    Extracts structured threat indicators (IOCs) from text.
    """
    return ExtractResponse(
        indicators=[],
        count=0
    )
