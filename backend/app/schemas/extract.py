from pydantic import BaseModel, Field
from typing import List
from app.schemas.common import ExtractedIndicator

class ExtractRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Raw text from which to extract threat indicators (IOCs)")

class ExtractResponse(BaseModel):
    indicators: List[ExtractedIndicator] = Field(default_factory=list, description="List of structured IOCs extracted")
    count: int = Field(..., description="Total number of indicators found")
