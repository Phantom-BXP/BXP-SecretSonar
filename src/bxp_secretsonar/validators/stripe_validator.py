import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator
from bxp_secretsonar.utils.stealth import StealthManager

class StripeValidator(GenericHttpValidator):
    def __init__(self, ssl_verify: bool = True, timeout: float = 5.0, stealth_mgr: StealthManager = None):
        super().__init__(ssl_verify=ssl_verify, timeout=timeout, stealth_mgr=stealth_mgr)

    async def validate(self, candidate: Candidate) -> Validated:
        validated = await super().validate(candidate)
        if validated.result != ValidationResult.CONFIRMED:
            return validated
        secret = candidate.evidence.matched_value
        metadata = validated.candidate.evidence.metadata
        score_boost = 0.0

        headers = self.stealth_mgr.get_headers("stripe")
        headers.update({"Authorization": f"Bearer {secret}"})

        async with httpx.AsyncClient(timeout=10.0, headers=headers) as client:
            # 1. Solde
            try:
                resp = await client.get("https://api.stripe.com/v1/balance")
                if resp.status_code == 200:
                    data = resp.json()
                    available = data.get("available", [])
                    metadata["stripe_balance_available"] = available
                    if available:
                        score_boost += 0.3
                else:
                    validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.3)
                    validated.result = ValidationResult.REJECTED
                    return validated
            except Exception:
                validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.1)
                return validated

            # 2. Compte
            try:
                resp = await client.get("https://api.stripe.com/v1/account")
                if resp.status_code == 200:
                    data = resp.json()
                    metadata["stripe_account_id"] = data.get("id")
                    score_boost += 0.2
            except Exception:
                pass

            # 3. Abonnements
            try:
                resp = await client.get("https://api.stripe.com/v1/subscriptions?limit=10")
                if resp.status_code == 200:
                    data = resp.json()
                    subs = data.get("data", [])
                    metadata["stripe_subscriptions_count"] = len(subs)
                    if subs:
                        score_boost += 0.1
            except Exception:
                pass

        validated.candidate.confidence_score = min(1.0, validated.candidate.confidence_score + score_boost)
        validated.result = ValidationResult.CONFIRMED
        return validated
