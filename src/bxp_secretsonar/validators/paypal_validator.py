import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator

class PayPalValidator(GenericHttpValidator):
    async def validate(self, candidate: Candidate) -> Validated:
        validated = await super().validate(candidate)
        if validated.result != ValidationResult.CONFIRMED:
            return validated
        secret = candidate.evidence.matched_value
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                headers = {"Authorization": f"Bearer {secret}", "Content-Type": "application/json"}
                resp = await client.get("https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=openid", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    email = data.get("email", "")
                    if email:
                        validated.candidate.confidence_score = min(1.0, validated.candidate.confidence_score + 0.4)
                        validated.result = ValidationResult.CONFIRMED
                        validated.candidate.evidence.metadata["paypal_email"] = email
                    else:
                        validated.candidate.confidence_score = min(1.0, validated.candidate.confidence_score + 0.2)
                else:
                    validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.3)
                    validated.result = ValidationResult.REJECTED
        except Exception:
            validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.1)
        return validated
