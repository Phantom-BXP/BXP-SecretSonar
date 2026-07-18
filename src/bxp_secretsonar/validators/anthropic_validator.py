import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator

class AnthropicValidator(GenericHttpValidator):
    async def validate(self, candidate: Candidate) -> Validated:
        validated = await super().validate(candidate)
        if validated.result != ValidationResult.CONFIRMED:
            return validated
        secret = candidate.evidence.matched_value
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                headers = {"x-api-key": secret, "anthropic-version": "2023-06-01"}
                resp = await client.get("https://api.anthropic.com/v1/models", headers=headers)
                if resp.status_code == 200:
                    validated.candidate.confidence_score = min(1.0, validated.candidate.confidence_score + 0.4)
                    validated.result = ValidationResult.CONFIRMED
                elif resp.status_code in (401, 403):
                    validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.3)
                    validated.result = ValidationResult.REJECTED
        except Exception:
            validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.1)
        return validated
