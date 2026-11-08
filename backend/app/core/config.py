"""
Application configuration for the Secure Web Assistant phishing detection API.

All paths are resolved relative to this file so the service works regardless of
the current working directory.  Existing ML assets are consumed read-only.
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------
CORE_DIR = Path(__file__).resolve().parent         # backend/app/core
APP_DIR = CORE_DIR.parent                          # backend/app
BACKEND_DIR = APP_DIR.parent                       # backend
PROJECT_ROOT = BACKEND_DIR.parent                  # Secure_web_assistant

# Serialized ML model (read-only, consumed as-is).
MODEL_PATH = BACKEND_DIR / "app" / "model" / "pickle" / "model.pkl"

# Existing feature extractor (read-only, consumed as-is).
#   backend/app/services/phishing/feature_extractor.py
FEATURE_EXTRACTOR_MODULE = "app.services.phishing.feature_extractor"

# ---------------------------------------------------------------------------
# Risk-level thresholds (phishing probability)
# ---------------------------------------------------------------------------
RISK_HIGH_THRESHOLD = 0.8   # >= 0.8  → HIGH
RISK_MEDIUM_THRESHOLD = 0.5  # >= 0.5  → MEDIUM

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
# Chrome extensions use the chrome-extension:// scheme.
# Local test origins: http://localhost:* and http://127.0.0.1:*
CORS_ORIGIN_REGEX = (
    r"^(chrome-extension://|http://localhost(:\d+)?|http://127\.0\.0\.1(:\d+)?)$"
)

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
API_V1_PREFIX = "/api/v1"
HOST = os.getenv("PHISHING_API_HOST", "127.0.0.1")
PORT = int(os.getenv("PHISHING_API_PORT", "8000"))