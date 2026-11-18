from __future__ import annotations

import os
from unittest.mock import MagicMock, patch
from dotenv import load_dotenv
import pytest
from pydantic import BaseModel

load_dotenv()

from core.config import GeminiConfig
from core.llm import GeminiClient
from core.schemas import LLMTriageOutput, VerdictEnum


class DummySchema(BaseModel):
    verdict: str
    score: float


def test_llm_client_missing_api_key():
    config = GeminiConfig(api_key=None)
    with patch.dict(os.environ, {}, clear=True):
        client = GeminiClient(config)
        assert client.is_available() is False
        res = client.generate_json("test prompt", DummySchema)
        assert res is None


def test_llm_client_blocked_safety_response():
    config = GeminiConfig(api_key="mock_key_123")
    client = GeminiClient(config)

    # Mock SDK response with SAFETY block
    mock_candidate = MagicMock()
    mock_candidate.finish_reason = "SAFETY"

    mock_resp = MagicMock()
    mock_resp.candidates = [mock_candidate]
    mock_resp.text = None

    client._client = MagicMock()
    client._client.models.generate_content.return_value = mock_resp

    result = client.generate_json("trigger prompt", DummySchema)
    assert result is None


def test_llm_client_malformed_json_response():
    config = GeminiConfig(api_key="mock_key_123")
    client = GeminiClient(config)

    mock_candidate = MagicMock()
    mock_candidate.finish_reason = "STOP"

    mock_resp = MagicMock()
    mock_resp.candidates = [mock_candidate]
    mock_resp.text = "This is not valid json at all {"

    client._client = MagicMock()
    client._client.models.generate_content.return_value = mock_resp

    result = client.generate_json("trigger prompt", DummySchema)
    assert result is None


def test_llm_client_transient_error_retry():
    config = GeminiConfig(api_key="mock_key_123", max_retries=2)
    client = GeminiClient(config)

    from google.genai.errors import APIError

    client._client = MagicMock()
    # First attempt raises 429, second attempt succeeds with valid JSON
    err_429 = APIError(429, {"error": {"message": "Rate limit exceeded"}})

    mock_candidate = MagicMock()
    mock_candidate.finish_reason = "STOP"
    mock_resp = MagicMock()
    mock_resp.candidates = [mock_candidate]
    mock_resp.text = '{"verdict": "suspicious", "score": 0.85}'

    client._client.models.generate_content.side_effect = [err_429, mock_resp]

    result = client.generate_json("trigger prompt", DummySchema)
    assert result is not None
    assert result.verdict == "suspicious"
    assert result.score == 0.85


def test_llm_live_api_if_key_available():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        pytest.skip("GEMINI_API_KEY not configured. Skipping live Gemini API test.")

    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    config = GeminiConfig(api_key=api_key, model=model_name)
    client = GeminiClient(config)

    prompt = (
        "Classify the following simulated event strictly into schema: "
        "User root attempted 1 failed password. Return verdict and confidence."
    )
    result = client.generate_json(prompt, schema=LLMTriageOutput)
    if result:
        assert isinstance(result, LLMTriageOutput)
        assert result.confidence >= 0.0
