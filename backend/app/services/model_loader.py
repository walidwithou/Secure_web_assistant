"""
Thread-safe model service that loads the serialized phishing classifier once
at startup and exposes a ``predict(features)`` method for inference.

The model is loaded exactly once (lazily on first use, or eagerly via the
FastAPI lifespan in :mod:`app.main`).  ``predict`` is thread-safe.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, Iterable, Optional, Sequence

import joblib

# Import the canonical feature-column order from the existing (read-only)
# extractor so the inference vector matches training exactly.
from app.services.phishing.feature_extractor import FEATURE_COLUMNS  # noqa: E402
from app.core.config import MODEL_PATH


class ModelService:
    """Singleton wrapper around the serialized XGBoost phishing classifier.

    The model is loaded exactly once.  ``predict`` is thread-safe and returns
    both the canonical class (0 = legitimate, 1 = phishing) and a confidence
    / probability score.
    """

    _instance: Optional["ModelService"] = None
    _instance_lock = threading.Lock()

    def __new__(cls, *args: Any, **kwargs: Any) -> "ModelService":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, model_path: str = str(MODEL_PATH)) -> None:
        # Guard against re-initialisation of the singleton.
        if getattr(self, "_initialized", False):
            return
        self._model_path = model_path
        self._model: Any = None
        self._lock = threading.RLock()
        self._classes: Sequence[Any] = ()
        self._phishing_class: Any = None
        self._initialized = True

    def load(self) -> "ModelService":
        """Load the serialized model from disk (idempotent, thread-safe)."""
        with self._lock:
            if self._model is not None:
                return self
            self._model = joblib.load(self._model_path)
            self._classes = list(getattr(self._model, "classes_", [])) or [0, 1]
            self._resolve_phishing_class()
        return self

    def _resolve_phishing_class(self) -> None:
        """Map serialized labels to canonical 0 (legit) / 1 (phishing)."""
        classes = self._classes
        if 1 in classes:
            self._phishing_class = 1
        elif -1 in classes:
            self._phishing_class = -1
        else:
            self._phishing_class = classes[-1]  # last class treated as positive

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    def predict(self, features: Iterable[float]) -> Dict[str, Any]:
        """Run inference on a single feature vector.

        Parameters
        ----------
        features : iterable of float
            30 numerical feature values in ``FEATURE_COLUMNS`` order.

        Returns
        -------
        dict
            {
                "prediction": int,                # 0 = legitimate, 1 = phishing
                "confidence": float,              # P(predicted class) in [0, 1]
                "phishing_probability": float,    # P(class == phishing) in [0, 1]
            }
        """
        with self._lock:
            if self._model is None:
                self.load()

            vector = [float(x) for x in features]
            if len(vector) != len(FEATURE_COLUMNS):
                raise ValueError(
                    f"Expected {len(FEATURE_COLUMNS)} features, got {len(vector)}"
                )

            # XGBoost expects a 2D array: one row.
            prediction = int(self._model.predict([vector])[0])
            is_phishing = 1 if prediction == self._phishing_class else 0

            # Confidence / probability.
            phishing_probability = 0.5
            confidence = 0.5
            if hasattr(self._model, "predict_proba"):
                proba = self._model.predict_proba([vector])[0]
                proba_dict = dict(zip(self._classes, proba))
                phishing_probability = float(
                    proba_dict.get(self._phishing_class, 0.5)
                )
                confidence = float(max(proba))
            else:
                # Fallback: treat the raw prediction as the probability.
                phishing_probability = float(is_phishing)
                confidence = float(is_phishing)

            return {
                "prediction": int(is_phishing),
                "confidence": round(confidence, 6),
                "phishing_probability": round(phishing_probability, 6),
            }


# Module-level singleton (lazy; loads on first predict() or via lifespan).
model_service = ModelService()