import os
import logging
from typing import Optional
import joblib

logger = logging.getLogger("threatforge.model_manager")

class ModelManager:
    """
    Manages loading and inference for the baseline scam-message ML classifier.
    Handles graceful fallback when the model file is missing or fails to load.
    """
    def __init__(self):
        self.model = None
        self.is_loaded = False
        self.model_version = "none"
        self._load_model()

    def _get_model_path(self) -> str:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return os.path.join(base_dir, "models", "scam_classifier_v1.joblib")

    def _load_model(self):
        model_path = self._get_model_path()
        if not os.path.exists(model_path):
            logger.info(f"Model file not found at {model_path}. Running in rules-only mode.")
            self.model = None
            self.is_loaded = False
            self.model_version = "none"
            return

        try:
            self.model = joblib.load(model_path)
            self.is_loaded = True
            self.model_version = "text-v1"
            logger.info("Scam classifier text-v1 loaded successfully.")
        except Exception as e:
            logger.warning(f"Failed to load model file at {model_path}: {e}. Falling back to rules-only.")
            self.model = None
            self.is_loaded = False
            self.model_version = "none"

    def reload(self):
        """Attempts to reload the model from disk."""
        self._load_model()

    def unload(self):
        """Forces model unload for testing fallback behavior."""
        self.model = None
        self.is_loaded = False
        self.model_version = "none"

    def predict_scam_probability(self, text: str) -> Optional[float]:
        """
        Returns estimated scam probability between 0.0 and 1.0 using the trained pipeline.
        Returns None if model is unavailable.
        """
        if not self.is_loaded or self.model is None:
            return None

        try:
            classes = list(self.model.classes_)
            probas = self.model.predict_proba([text])[0]
            if "scam" in classes:
                scam_idx = classes.index("scam")
                return float(probas[scam_idx])
            else:
                return float(probas[-1])
        except Exception as e:
            logger.warning(f"Error during model inference: {e}")
            return None

# Global singleton instance
model_manager = ModelManager()
