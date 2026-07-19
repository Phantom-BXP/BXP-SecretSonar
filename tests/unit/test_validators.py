import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from bxp_secretsonar.core.models import Evidence, Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator

@pytest.mark.asyncio
async def test_confirmed_on_200():
    evidence = Evidence(artifact_id="1", pattern_name="generic_api_key", matched_value="test123", source_url="http://example.com")
    candidate = Candidate(evidence=evidence, confidence_score=0.8, priority=3)
    validator = GenericHttpValidator(ssl_verify=False)

    # Mock le get_client pour retourner un client avec la réponse souhaitée
    mock_client = AsyncMock()
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch.object(validator.stealth_mgr, 'get_client', return_value=mock_client):
        result = await validator.validate(candidate)
        assert result.result == ValidationResult.CONFIRMED

@pytest.mark.asyncio
async def test_rejected_on_401():
    evidence = Evidence(artifact_id="2", pattern_name="bearer_token", matched_value="test456", source_url="http://example.com")
    candidate = Candidate(evidence=evidence, confidence_score=0.8, priority=3)
    validator = GenericHttpValidator(ssl_verify=False)

    mock_client = AsyncMock()
    mock_resp = AsyncMock()
    mock_resp.status_code = 401
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch.object(validator.stealth_mgr, 'get_client', return_value=mock_client):
        result = await validator.validate(candidate)
        assert result.result == ValidationResult.REJECTED

@pytest.mark.asyncio
async def test_unknown_for_excluded_pattern():
    evidence = Evidence(artifact_id="3", pattern_name="private_key_header", matched_value="somekey", source_url="http://example.com")
    candidate = Candidate(evidence=evidence, confidence_score=0.8, priority=3)
    validator = GenericHttpValidator(ssl_verify=False)
    result = await validator.validate(candidate)
    assert result.result == ValidationResult.UNKNOWN
    assert "non validé" in (result.proof or "")

@pytest.mark.asyncio
async def test_unknown_when_no_endpoint_configured():
    evidence = Evidence(artifact_id="4", pattern_name="unknown_pattern_type", matched_value="value123", source_url="http://example.com")
    candidate = Candidate(evidence=evidence, confidence_score=0.8, priority=3)
    validator = GenericHttpValidator(ssl_verify=False)
    result = await validator.validate(candidate)
    assert result.result == ValidationResult.UNKNOWN
    assert "non validé" in (result.proof or "")

@pytest.mark.asyncio
async def test_error_resilience_on_network_failure():
    evidence = Evidence(artifact_id="5", pattern_name="generic_api_key", matched_value="value123", source_url="http://example.com")
    candidate = Candidate(evidence=evidence, confidence_score=0.8, priority=3)
    validator = GenericHttpValidator(ssl_verify=False)

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=Exception("Network error"))

    with patch.object(validator.stealth_mgr, 'get_client', return_value=mock_client):
        result = await validator.validate(candidate)
        assert result.result == ValidationResult.UNKNOWN
