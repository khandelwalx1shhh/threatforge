import logging
import os
import time
import warnings
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict

logger = logging.getLogger("threatforge.distilbert")

DEFAULT_MODEL_ID = "cybersectony/phishing-email-detection-distilbert_v2.4.1"

# Candidate mapping from author's model card / dataset documentation
AUTHOR_CANDIDATE_LABELS: Dict[int, str] = {
    0: "legitimate_email",
    1: "phishing_url",
    2: "legitimate_url",
    3: "phishing_url_alt"
}

class DistilBertPrediction(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    model_name: str = Field(default=DEFAULT_MODEL_ID)
    model_version: str = Field(default="v2.4.1")
    is_available: bool = Field(default=True)
    is_quantized: bool = Field(default=False, description="Whether 8-bit dynamic INT8 CPU quantization is active")
    latency_ms: Optional[float] = Field(default=None, description="Inference latency in milliseconds")
    predicted_class_index: Optional[int] = None
    predicted_class_label: Optional[str] = None
    candidate_class_label: Optional[str] = None
    class_probabilities: Dict[str, float] = Field(default_factory=dict)
    candidate_probabilities: Dict[str, float] = Field(default_factory=dict)
    confidence: float = Field(default=0.0)
    verification_status: str = Field(
        default="unverified",
        description="'verified' if model config has official semantic labels, 'unverified' if generic LABEL_X"
    )
    warning: Optional[str] = None
    explanation: str = Field(default="")
    risk_assessment: Optional[str] = None

class DistilBertDetector:
    """
    Singleton service for loading and executing local inference with
    cybersectony/phishing-email-detection-distilbert_v2.4.1.
    Supports PyTorch 8-bit dynamic quantization on CPU for 3-4x latency reduction.
    """
    def __init__(self, model_id: str = DEFAULT_MODEL_ID, auto_load: bool = True):
        self.model_id = model_id
        self.tokenizer = None
        self.model = None
        self.device = None
        self.is_loaded = False
        self.is_quantized = False
        self.raw_id2label: Dict[int, str] = {}
        self.is_label_mapping_verified: bool = False
        self.load_error: Optional[str] = None

        # Check if dynamic quantization is requested (default: True on CPU)
        quantize_env = os.environ.get("DISTILBERT_QUANTIZE", "true").lower()
        self.enable_quantization = quantize_env in ("1", "true", "yes")

        if auto_load:
            self.load()

    def load(self) -> bool:
        """Loads the tokenizer and model into memory in evaluation mode."""
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            forced_device = os.environ.get("INFERENCE_DEVICE", "").lower()
            if forced_device == "cpu":
                self.device = torch.device("cpu")
            elif forced_device == "cuda" and torch.cuda.is_available():
                self.device = torch.device("cuda")
            else:
                self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

            logger.info(f"Loading DistilBERT phishing model '{self.model_id}' on {self.device}...")

            self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_id)
            self.model.to(self.device)
            self.model.eval()

            # Dynamic 8-bit Quantization on CPU for ~3-4x speedup
            if self.device.type == "cpu" and self.enable_quantization:
                try:
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        warnings.filterwarnings("ignore", category=DeprecationWarning)
                        self.model = torch.quantization.quantize_dynamic(
                            self.model, {torch.nn.Linear}, dtype=torch.qint8
                        )
                    self.is_quantized = True
                    logger.info("Enabled PyTorch 8-bit dynamic INT8 CPU quantization for DistilBERT.")
                except Exception as q_exc:
                    self.is_quantized = False
                    logger.warning(f"Dynamic quantization could not be applied, using standard float32: {q_exc}")

            # Inspect model.config.id2label to verify actual class mapping
            cfg_id2label = getattr(self.model.config, "id2label", {})
            self.raw_id2label = {int(k): str(v) for k, v in cfg_id2label.items()} if cfg_id2label else {}

            # Check if labels are generic LABEL_0, LABEL_1 etc.
            generic_labels = any(
                lbl.startswith("LABEL_") for lbl in self.raw_id2label.values()
            ) or not self.raw_id2label

            self.is_label_mapping_verified = not generic_labels
            self.is_loaded = True
            self.load_error = None

            logger.info(
                f"DistilBERT model loaded successfully. Quantized: {self.is_quantized}. "
                f"Verified id2label: {self.is_label_mapping_verified} (raw: {self.raw_id2label})"
            )
            return True

        except Exception as exc:
            self.is_loaded = False
            self.load_error = str(exc)
            logger.warning(
                f"Failed to load DistilBERT model '{self.model_id}': {exc}. "
                "Backend will gracefully operate using rules and baseline classifier."
            )
            return False

    def predict(self, text: str) -> DistilBertPrediction:
        """
        Executes local inference with truncation up to 512 tokens.
        Returns a structured DistilBertPrediction object.
        """
        if not self.is_loaded or self.model is None or self.tokenizer is None:
            return DistilBertPrediction(
                is_available=False,
                is_quantized=False,
                latency_ms=None,
                verification_status="unavailable",
                warning="DistilBERT model is currently not loaded or unavailable.",
                explanation="Model offline; analysis handled via deterministic rules.",
                risk_assessment="deferred_to_rules"
            )

        try:
            import torch

            start_time = time.perf_counter()

            # Tokenize input with truncation and max sequence length of 512 tokens
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=False
            )

            # Move inputs to target device
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            # Run inference in torch.inference_mode()
            with torch.inference_mode():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs_tensor = torch.softmax(logits, dim=-1)[0]
                probs_list = probs_tensor.cpu().tolist()

            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Compute predictions
            predicted_idx = int(torch.argmax(probs_tensor).item())
            raw_label = self.raw_id2label.get(predicted_idx, f"LABEL_{predicted_idx}")
            candidate_label = AUTHOR_CANDIDATE_LABELS.get(predicted_idx, f"class_{predicted_idx}")
            confidence = float(probs_list[predicted_idx])

            # Class probabilities mapped to raw model labels
            class_probs = {
                self.raw_id2label.get(i, f"LABEL_{i}"): float(prob)
                for i, prob in enumerate(probs_list)
            }

            # Candidate probabilities mapped to author-claimed labels
            candidate_probs = {
                AUTHOR_CANDIDATE_LABELS.get(i, f"class_{i}"): float(prob)
                for i, prob in enumerate(probs_list)
            }

            verification_status = "verified" if self.is_label_mapping_verified else "unverified"
            warning_msg = None
            if not self.is_label_mapping_verified:
                warning_msg = (
                    "Model config.id2label exposes generic labels (LABEL_0..3). "
                    "Author-suggested labels ('legitimate_email', 'phishing_url') are unverified. "
                    "Do NOT classify an email as safe solely because this model predicts a non-phishing class."
                )

            # Construct concise, unhallucinated explanation
            explanation = (
                f"DistilBERT classified input with {confidence:.1%} confidence into class index {predicted_idx} "
                f"({raw_label}, candidate: {candidate_label}) in {latency_ms:.1f}ms. "
                f"Status: {verification_status}."
            )

            risk_assessment = "suspicious" if predicted_idx in {1, 3} else "low_statistical_anomaly"

            return DistilBertPrediction(
                model_name=self.model_id,
                model_version="v2.4.1",
                is_available=True,
                is_quantized=self.is_quantized,
                latency_ms=latency_ms,
                predicted_class_index=predicted_idx,
                predicted_class_label=raw_label,
                candidate_class_label=candidate_label,
                class_probabilities=class_probs,
                candidate_probabilities=candidate_probs,
                confidence=round(confidence, 4),
                verification_status=verification_status,
                warning=warning_msg,
                explanation=explanation,
                risk_assessment=risk_assessment
            )

        except Exception as exc:
            logger.error(f"DistilBERT inference error: {exc}")
            return DistilBertPrediction(
                is_available=False,
                is_quantized=self.is_quantized,
                latency_ms=None,
                verification_status="inference_error",
                warning=f"Inference error encountered: {type(exc).__name__}",
                explanation="DistilBERT inference failed; risk computed via fallback.",
                risk_assessment="deferred_to_rules"
            )

# Singleton instance
distilbert_detector = DistilBertDetector(auto_load=True)
