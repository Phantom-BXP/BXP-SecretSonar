import pytest
import httpx
from unittest.mock import AsyncMock, patch
from bxp_secretsonar.validators.generic_http import GenericHttpValidator
from bxp_secretsonar.core.models import Candidate, Evidence, ValidationResult


def _make_candidate(pattern: str, value: str, priority: int = 1) -> Candidate:
    ev = Evidence(artifact_id="test", pattern_name=pattern, matched_value=value)
    return Candidate(evidence=ev, confidence_score=0.9, priority=priority)


@pytest.mark.asyncio
async def test_confirmed_on_200():
    validator = GenericHttpValidator()
    candidate = _make_candidate("generic_api_key", "sk_live_validkey1234567890")

    mock_response = httpx.Response(200, request=httpx.Request("GET", "https://api.example.com"))
    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, return_value=mock_response):
        result = await validator.validate(candidate)

    assert result.result == ValidationResult.CONFIRMED
    assert result.is_confirmed is True
    assert result.validator_name == "generic_http"


@pytest.mark.asyncio
async def test_rejected_on_401():
    validator = GenericHttpValidator()
    candidate = _make_candidate("generic_api_key", "sk_live_invalidkey12345678")

    mock_response = httpx.Response(401, request=httpx.Request("GET", "https://api.example.com"))
    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, return_value=mock_response):
        result = await validator.validate(candidate)

    assert result.result == ValidationResult.REJECTED
    assert result.is_confirmed is False


@pytest.mark.asyncio
async def test_unknown_for_non_validable_pattern():
    validator = GenericHttpValidator()
    candidate = _make_candidate("private_key_header", "-----BEGIN RSA PRIVATE KEY-----")

    result = await validator.validate(candidate)

    assert result.result == ValidationResult.UNKNOWN
    assert "not actively validated" in (result.proof or "")


@pytest.mark.asyncio
async def test_unknown_when_no_endpoint_configured():
    validator = GenericHttpValidator()
    candidate = _make_candidate("unknown_pattern_type", "somevalue1234567890ab")

    result = await validator.validate(candidate)

    assert result.result == ValidationResult.UNKNOWN
    assert "No validation endpoint" in (result.proof or "")


@pytest.mark.asyncio
async def test_error_resilience_on_network_failure():
    validator = GenericHttpValidator(timeout=1.0)
    candidate = _make_candidate("bearer_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test")

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, side_effect=httpx.ConnectError("fail")):
        result = await validator.validate(candidate)

    assert result.result == ValidationResult.UNKNOWN
    assert result.validator_name == "generic_http"
