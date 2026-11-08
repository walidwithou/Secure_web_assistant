"""
Pydantic request / response schemas for the phishing detection endpoint.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class PhishingAnalysisRequest(BaseModel):
    """Incoming phishing-analysis request from the browser extension."""

    url: HttpUrl = Field(..., description="Target URL to analyze for phishing.")
    html_content: Optional[str] = Field(
        default=None,
        description=(
            "Optional raw DOM HTML captured by the browser extension content "
            "script. Kept for future use; the current feature extractor fetches "
            "the page itself from the URL."
        ),
    )


class PhishingAnalysisResponse(BaseModel):
    """Structured phishing-analysis response returned to the client."""

    url: str = Field(..., description="The analyzed URL (as a string).")
    is_phishing: bool = Field(
        ..., description="True if phishing detected, False otherwise."
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence of the prediction (0.0 to 1.0).",
    )
    risk_level: str = Field(
        ...,
        description='Risk level: "LOW", "MEDIUM" or "HIGH".',
    )
    features_extracted: Optional[dict] = Field(
        default=None,
        description="Optional summary of the extracted feature key-value pairs.",
    )

    @field_validator("risk_level")
    @classmethod
    def _validate_risk_level(cls, v: str) -> str:
        allowed = {"LOW", "MEDIUM", "HIGH"}
        if v not in allowed:
            raise ValueError(f"risk_level must be one of {sorted(allowed)}")
        return v