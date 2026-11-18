from __future__ import annotations

import logging
import os
import random
import time
from typing import Any, Optional, Type, TypeVar

from pydantic import BaseModel, ValidationError

try:
    from google import genai
    from google.genai import types
    from google.genai.errors import APIError, ServerError
    _GENAI_AVAILABLE = True
except ImportError:
    _GENAI_AVAILABLE = False
    genai = None  # type: ignore
    types = None  # type: ignore
    APIError = Exception
    ServerError = Exception

from core.config import GeminiConfig

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class GeminiClient:
    """Thin wrapper around Google Gen AI SDK (google-genai) with retries, structured output, and safety handling."""

    def __init__(self, config: GeminiConfig):
        self.config = config
        self.api_key: Optional[str] = config.api_key or os.getenv("GEMINI_API_KEY")
        self.model: str = config.model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self._client: Optional[Any] = None

        if not _GENAI_AVAILABLE or genai is None or types is None:
            logger.warning("google-genai package is not installed. LLM capabilities will be disabled.")
            return

        if not self.api_key:
            logger.info("GEMINI_API_KEY is not set. LLM reasoner will operate in fallback mode.")
            return

        try:
            self._client = genai.Client(
                api_key=self.api_key,
                http_options=types.HttpOptions(timeout=int(self.config.timeout_seconds) if self.config.timeout_seconds else None),
            )
        except Exception as e:
            logger.warning(f"Failed to initialize Gemini GenAI client: {e}")
            self._client = None

    def is_available(self) -> bool:
        return self._client is not None and types is not None

    def generate_json(
        self,
        prompt: str,
        schema: Type[T],
        temperature: Optional[float] = None,
    ) -> Optional[T]:
        """Generate structured JSON response adhering to a Pydantic schema with retry and backoff."""
        if not self.is_available() or self._client is None or types is None:
            logger.debug("Gemini client unavailable. Returning None.")
            return None

        temp = temperature if temperature is not None else self.config.temperature
        max_retries = self.config.max_retries
        base_delay = 1.0

        for attempt in range(1, max_retries + 1):
            try:
                gen_config = types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=schema,
                    temperature=temp,
                )

                response = self._client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config=gen_config,
                )

                if not response:
                    logger.warning("Empty response received from Gemini.")
                    return None

                # Check safety ratings / finish reason
                if hasattr(response, "candidates") and response.candidates:
                    candidate = response.candidates[0]
                    finish_reason = getattr(candidate, "finish_reason", None)
                    if finish_reason and str(finish_reason).upper() in ("SAFETY", "BLOCK", "RECITATION"):
                        logger.warning(f"Gemini response blocked by safety filters: {finish_reason}")
                        return None

                raw_text = getattr(response, "text", None)
                if not raw_text or not raw_text.strip():
                    logger.warning("Gemini returned empty text.")
                    return None

                # Strict Pydantic validation
                try:
                    result = schema.model_validate_json(raw_text.strip())
                    return result
                except ValidationError as ve:
                    # In case of minor markdown enclosure (```json ... ```)
                    cleaned = raw_text.strip()
                    if cleaned.startswith("```"):
                        lines = cleaned.splitlines()
                        if lines[0].startswith("```"):
                            lines = lines[1:]
                        if lines and lines[-1].startswith("```"):
                            lines = lines[:-1]
                        cleaned = "\n".join(lines).strip()
                        return schema.model_validate_json(cleaned)
                    logger.warning(f"Pydantic schema validation failed on Gemini response: {ve}")
                    return None

            except Exception as e:
                status_code = getattr(e, "code", None)
                is_transient = (
                    status_code in (429, 500, 502, 503, 504)
                    or "quota" in str(e).lower()
                    or "rate" in str(e).lower()
                    or "timeout" in str(e).lower()
                    or "timed out" in str(e).lower()
                    or isinstance(e, (ServerError, TimeoutError))
                )

                jitter = random.uniform(0.1, 0.4)
                delay = (base_delay * (2 ** (attempt - 1))) + jitter

                if is_transient and attempt < max_retries:
                    logger.warning(
                        f"Transient Gemini API error on attempt {attempt}/{max_retries}: {e}. "
                        f"Retrying in {delay:.2f}s..."
                    )
                    time.sleep(delay)
                    continue

                logger.warning(f"Gemini API request failed permanently on attempt {attempt}: {e}")
                return None

        return None
