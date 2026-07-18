import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator

class GCPValidator(GenericHttpValidator):
    async def validate(self, candidate: Candidate) -> Validated:
        validated = await super().validate(candidate)
        if validated.result != ValidationResult.CONFIRMED:
            return validated
        secret = candidate.evidence.matched_value
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={secret}")
                if resp.status_code == 200:
                    data = resp.json()
                    if "email" in data:
                        validated.candidate.confidence_score = min(1.0, validated.candidate.confidence_score + 0.4)
                        validated.result = ValidationResult.CONFIRMED
                        validated.candidate.evidence.metadata["gcp_email"] = data.get("email", "")
                    else:
                        validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.2)
                elif resp.status_code in (400, 401):
                    validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.3)
                    validated.result = ValidationResult.REJECTED
        except Exception:
            validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.1)
        return validated
