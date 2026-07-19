import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator
from bxp_secretsonar.utils.stealth import StealthManager

class PayPalValidator(GenericHttpValidator):
    def __init__(self, ssl_verify: bool = True, timeout: float = 5.0, stealth_mgr: StealthManager = None):
        super().__init__(ssl_verify=ssl_verify, timeout=timeout, stealth_mgr=stealth_mgr)

    async def validate(self, candidate: Candidate) -> Validated:
        validated = await super().validate(candidate)
        if validated.result != ValidationResult.CONFIRMED:
            return validated
        secret = candidate.evidence.matched_value
        try:
            client = self._get_client("paypal")
            async with client:
                resp = await client.get("https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=openid",
                                         headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json"})
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
