"""
Phishing detection routes.

POST /api/v1/phishing/analyze
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, status

from app.core.config import RISK_HIGH_THRESHOLD, RISK_MEDIUM_THRESHOLD
from app.schemas.phishing import PhishingAnalysisRequest, PhishingAnalysisResponse
from app.services.model_loader import model_service

# Import the existing (read-only) feature extractor.
from app.services.phishing.feature_extractor import (  # noqa: E402
    FEATURE_COLUMNS,
    extract_features,
)

router = APIRouter()


def _risk_level(phishing_probability: float) -> str:
    if phishing_probability >= RISK_HIGH_THRESHOLD:
        return "HIGH"
    if phishing_probability >= RISK_MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


@router.post(
    "/phishing/analyze",
    response_model=PhishingAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a URL for phishing",
)
async def analyze_phishing(
    request: PhishingAnalysisRequest,
) -> PhishingAnalysisResponse:
    """Analyze a URL (and optional DOM) for phishing indicators.

    1. Extracts the 30 phishing features from the URL via
       :func:`feature_extractor.extract_features` (UCI encoding, matching
       training).
    2. Runs inference through the singleton model service.
    3. Categorises risk by phishing probability and returns a structured
       response.
    """
    url_str = str(request.url)

    # ------------------------------------------------------------------
    # Step 1: feature extraction (read-only existing module)
    # ------------------------------------------------------------------
    try:
        feature_dict = extract_features(url_str, encoding="uci")
    except Exception as exc:  # noqa: BLE001 - surface as 400
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Feature extraction failed: {exc}",
        ) from exc

    # Order the vector exactly as the model expects (FEATURE_COLUMNS order).
    feature_vector = [feature_dict[name] for name in FEATURE_COLUMNS]

    # Optional: surface the extracted features in the response.
    features_extracted: Optional[dict] = dict(feature_dict)

    # ------------------------------------------------------------------
    # Step 2: inference (model loaded once at startup)
    # ------------------------------------------------------------------
    try:
        inference = model_service.predict(feature_vector)
    except Exception as exc:  # noqa: BLE001 - surface as 500
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference failed: {exc}",
        ) from exc

    phishing_probability = float(inference["phishing_probability"])
    is_phishing = bool(inference["prediction"] == 1)
    confidence = float(inference["confidence"])
    risk = _risk_level(phishing_probability)

    return PhishingAnalysisResponse(
        url=url_str,
        is_phishing=is_phishing,
        confidence_score=confidence,
        risk_level=risk,
        features_extracted=features_extracted,
    )