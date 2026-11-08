"""
FastAPI application entrypoint.

- Configures CORS to permit Chrome extensions and local test origins.
- Mounts the /api/v1 router.
- Eagerly loads the ML model on startup.
- Exposes a GET /health check.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.phishing import router as phishing_router
from app.core.config import API_V1_PREFIX, CORS_ORIGIN_REGEX, HOST, PORT
from app.services.model_loader import model_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the ML model once at startup."""
    model_service.load()
    yield


app = FastAPI(
    title="Secure Web Assistant — Phishing Detection API",
    description="REST API for serving the URL phishing detection pipeline.",
    version="1.0.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS — permit Chrome extensions and local test origins
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Exception handlers — bad URLs -> HTTP 400 (per spec) instead of Pydantic's
# default 422 Unprocessable Entity.
# ---------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def _validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.errors(), "message": "Invalid request."},
    )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(phishing_router, prefix=API_V1_PREFIX)


@app.get("/health", tags=["health"], summary="Health check")
async def health() -> dict:
    return {
        "status": "ok",
        "model_loaded": model_service.is_loaded,
    }


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=False)