import asyncio
import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator

class AWSValidator(GenericHttpValidator):
    """Validation AWS renforcée via sts:GetCallerIdentity."""

    async def validate(self, candidate: Candidate) -> Validated:
        validated = await super().validate(candidate)
        if validated.result != ValidationResult.CONFIRMED:
            return validated

        pattern = candidate.evidence.pattern_name.lower()
        if not any(kw in pattern for kw in ["aws", "amazon", "s3", "iam"]):
            return validated

        secret = candidate.evidence.matched_value
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                headers = {"Authorization": f"Bearer {secret}"}
                resp = await client.get(
                    "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
                    headers=headers
                )
                if resp.status_code == 200:
                    validated.candidate.confidence_score = min(1.0, validated.candidate.confidence_score + 0.2)
                    validated.result = ValidationResult.CONFIRMED
                else:
                    validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.3)
                    if validated.candidate.confidence_score < 0.5:
                        validated.result = ValidationResult.UNKNOWN
        except Exception:
            validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.1)

        return validated
