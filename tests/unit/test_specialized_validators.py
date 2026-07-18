import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from bxp_secretsonar.core.models import Evidence, Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.stripe_validator import StripeValidator
from bxp_secretsonar.validators.github_validator import GitHubValidator

@pytest.mark.asyncio
async def test_stripe_validator_confirmed():
    evidence = Evidence(artifact_id="1", pattern_name="stripe_key", matched_value="sk_test_123")
    candidate = Candidate(evidence=evidence, confidence_score=0.7, priority=5)
    validator = StripeValidator(ssl_verify=False, timeout=5.0)

    async def mock_gen_validate(self, candidate):
        return Validated(
            candidate=candidate,
            result=ValidationResult.CONFIRMED,
            validator_name="generic"
        )

    async def mock_get(url, headers=None, **kwargs):
        resp = MagicMock()
        resp.json = AsyncMock()
        if 'balance' in url:
            resp.status_code = 200
            resp.json.return_value = {"available": [{"amount": 1000}]}
        elif 'account' in url:
            resp.status_code = 200
            resp.json.return_value = {"id": "acct_123", "email": "test@test.com", "country": "US", "type": "standard"}
        elif 'subscriptions' in url:
            resp.status_code = 200
            resp.json.return_value = {"data": []}
        else:
            resp.status_code = 200
            resp.json.return_value = {}
        return resp

    with patch.object(validator.__class__.__bases__[0], 'validate', side_effect=mock_gen_validate, autospec=True):
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            validated = await validator.validate(candidate)
            assert validated.result == ValidationResult.CONFIRMED

@pytest.mark.asyncio
async def test_github_validator_confirmed():
    evidence = Evidence(artifact_id="2", pattern_name="github_token", matched_value="ghp_123")
    candidate = Candidate(evidence=evidence, confidence_score=0.7, priority=5)
    validator = GitHubValidator(ssl_verify=False, timeout=5.0)

    async def mock_gen_validate(self, candidate):
        return Validated(
            candidate=candidate,
            result=ValidationResult.CONFIRMED,
            validator_name="generic"
        )

    async def mock_get(url, headers=None, **kwargs):
        resp = MagicMock()
        resp.json = AsyncMock()
        if 'api.github.com/user' in url:
            resp.status_code = 200
            resp.json.return_value = {"login": "testuser", "plan": {"name": "free"}}
        else:
            resp.status_code = 200
            resp.json.return_value = {}
        return resp

    with patch.object(validator.__class__.__bases__[0], 'validate', side_effect=mock_gen_validate, autospec=True):
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            validated = await validator.validate(candidate)
            assert validated.result == ValidationResult.CONFIRMED
