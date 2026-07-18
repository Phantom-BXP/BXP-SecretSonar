import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator

class AtlassianValidator(GenericHttpValidator):
    async def validate(self, candidate: Candidate) -> Validated:
        validated = await super().validate(candidate)
        if validated.result != ValidationResult.CONFIRMED:
            return validated
        secret = candidate.evidence.matched_value
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get("https://api.atlassian.com/me", headers={"Authorization": f"Bearer {secret}"})
                if resp.status_code == 200:
                    data = resp.json()
                    validated.candidate.confidence_score = min(1.0, validated.candidate.confidence_score + 0.4)
                    validated.result = ValidationResult.CONFIRMED
                    validated.candidate.evidence.metadata["atlassian_account_id"] = data.get("account_id", "")
                elif resp.status_code in (401, 403):
                    validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.3)
                    validated.result = ValidationResult.REJECTED
        except Exception:
            validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.1)
        return validated
