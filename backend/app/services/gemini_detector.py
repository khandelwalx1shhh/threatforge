import json
import logging
import re
from typing import Dict, Any, Optional, List
from app.config import settings

logger = logging.getLogger("threatforge.gemini")

class GeminiDetector:
    """
    Service for executing AI-powered cyber threat intelligence and deception analysis
    using Google Gemini models (e.g. gemini-1.5-flash).
    Gracefully handles missing keys, network timeouts, and model rate limits.
    """
    def __init__(self):
        self._is_configured = False
        self._genai = None
        self._model = None
        self._check_and_init()

    def _check_and_init(self):
        api_key = (getattr(settings, "GEMINI_API_KEY", "") or "").strip()
        if not api_key or "your_gemini_api_key" in api_key.lower():
            self._is_configured = False
            return

        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model_name = getattr(settings, "GEMINI_MODEL", "gemini-3.8-flash") or "gemini-3.8-flash"
            self._genai = genai
            self._model = genai.GenerativeModel(model_name)
            self._is_configured = True
            logger.info(f"Gemini AI Detector initialized successfully with model: {model_name}")
        except Exception as e:
            logger.warning(f"Failed to initialize Gemini AI Detector: {e}")
            self._is_configured = False

    @property
    def is_available(self) -> bool:
        """Returns True if a valid Gemini API key is configured and ready."""
        # Re-check in case environment variable changed dynamically
        api_key = (getattr(settings, "GEMINI_API_KEY", "") or "").strip()
        if api_key and not self._is_configured and "your_gemini_api_key" not in api_key.lower():
            self._check_and_init()
        return self._is_configured

    @is_available.setter
    def is_available(self, value: bool):
        self._is_configured = bool(value)

    def analyze(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Executes AI threat analysis using Gemini.
        Returns structured dictionary with risk score, intent, psychological tactics, and safety advice.
        Returns None if unavailable or if an error occurs.
        """
        if not self.is_available or not self._model:
            return None

        clean_text = (text or "").strip()
        if not clean_text:
            return None

        prompt = f"""You are ThreatForge AI, an expert cyber threat intelligence and anti-phishing defense analyst.
Analyze the following message, email, or URL for social engineering, financial fraud, phishing, credential harvesting, or extortion intent.

Message text to inspect:
\"\"\"{clean_text[:3000]}\"\"\"

Respond strictly with a valid JSON object matching this exact schema:
{{
  "risk_score": <integer from 0 to 100>,
  "risk_level": "<low|medium|high|critical>",
  "intent_category": "<Credential Harvesting|Financial Extortion|Tech Support Scam|Phishing Link|Impersonation|Benign>",
  "psychological_tactics": ["<e.g. Artificial Urgency>", "<e.g. Authority Coercion>"],
  "summary": "<1-2 sentence executive assessment of why this is or isn't a threat>",
  "reasons": ["<detailed finding 1>", "<detailed finding 2>"],
  "recommended_action": "<clear defensive advice for the recipient>",
  "confidence": <float between 0.0 and 1.0>
}}
Do NOT output any markdown backticks, explanations, or text outside the JSON object.
"""

        try:
            candidate_models = [
                getattr(settings, "GEMINI_MODEL", "gemini-3.8-flash") or "gemini-3.8-flash",
                "gemini-3.8-flash",
                "gemini-2.5-flash",
                "gemini-flash-latest",
                "gemini-1.5-flash"
            ]
            response = None
            used_model_name = candidate_models[0]
            for m_name in candidate_models:
                try:
                    model_inst = self._genai.GenerativeModel(m_name)
                    response = model_inst.generate_content(
                        prompt,
                        generation_config={"temperature": 0.1, "max_output_tokens": 800}
                    )
                    used_model_name = m_name
                    break
                except Exception as ex:
                    if "404" in str(ex) or "not found" in str(ex).lower():
                        continue
                    raise ex

            if not response:
                return None

            raw_text = (response.text or "").strip()
            # Clean possible markdown formatting
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:]
            elif raw_text.startswith("```"):
                raw_text = raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            raw_text = raw_text.strip()

            parsed = json.loads(raw_text)
            
            # Enforce schema bounds
            risk_score = max(0, min(100, int(parsed.get("risk_score", 50))))
            risk_level = str(parsed.get("risk_level", "medium")).lower()
            if risk_level not in ["low", "medium", "high", "critical"]:
                if risk_score >= 80:
                    risk_level = "critical"
                elif risk_score >= 60:
                    risk_level = "high"
                elif risk_score >= 30:
                    risk_level = "medium"
                else:
                    risk_level = "low"

            return {
                "engine": "Google Gemini",
                "model": getattr(settings, "GEMINI_MODEL", "gemini-1.5-flash"),
                "risk_score": risk_score,
                "risk_level": risk_level,
                "intent_category": str(parsed.get("intent_category", "Unknown Threat")),
                "psychological_tactics": list(parsed.get("psychological_tactics", [])),
                "summary": str(parsed.get("summary", "")),
                "reasons": list(parsed.get("reasons", [])),
                "recommended_action": str(parsed.get("recommended_action", "")),
                "confidence": float(parsed.get("confidence", 0.90))
            }
        except Exception as e:
            logger.warning(f"Gemini API analysis failed or timed out: {e}")
            return None

    def generate_honeypot_reply(self, message: str, persona: str, turn: int = 1) -> Optional[str]:
        """
        Uses Gemini to generate adaptive persona honeypot responses to bait scammers
        safely inside the isolated sandbox.
        """
        if not self.is_available or not self._model:
            return None

        prompt = f"""You are an isolated honeypot deception agent in a cybersecurity defense lab.
Your goal is to simulate a vulnerable persona ({persona}) responding to a suspected scammer.
Elicit details like UPI IDs, bank routing numbers, or server URLs so threat analysts can extract IOCs.
Never reveal actual personal secrets. Keep it realistic, brief (1-2 sentences), and convincingly human.

Scammer message:
\"\"\"{message[:1000]}\"\"\"

Generate only the persona reply text:"""

        try:
            response = self._model.generate_content(
                prompt,
                generation_config={"temperature": 0.7, "max_output_tokens": 150}
            )
            return (response.text or "").strip()
        except Exception as e:
            logger.warning(f"Gemini honeypot response generation failed: {e}")
            return None

gemini_detector = GeminiDetector()
