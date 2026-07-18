import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator

class SlackValidator(GenericHttpValidator):
    async def validate(self, candidate: Candidate) -> Validated:
        validated = await super().validate(candidate)
        if validated.result != ValidationResult.CONFIRMED:
            return validated
        secret = candidate.evidence.matched_value
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post("https://slack.com/api/auth.test", headers={"Authorization": f"Bearer {secret}"})
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("ok"):
                        validated.candidate.confidence_score = min(1.0, validated.candidate.confidence_score + 0.4)
                        validated.result = ValidationResult.CONFIRMED
                        validated.candidate.evidence.metadata["slack_team"] = data.get("team", "")
                        validated.candidate.evidence.metadata["slack_user"] = data.get("user", "")
                    else:
                        validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.3)
                        validated.result = ValidationResult.REJECTED
                else:
                    validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.3)
                    validated.result = ValidationResult.REJECTED
        except Exception:
            validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.1)
        return validated
