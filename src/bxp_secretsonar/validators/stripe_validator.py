import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator

class StripeValidator(GenericHttpValidator):
    async def validate(self, candidate: Candidate) -> Validated:
        validated = await super().validate(candidate)
        if validated.result != ValidationResult.CONFIRMED:
            return validated
        secret = candidate.evidence.matched_value
        metadata = validated.candidate.evidence.metadata
        score_boost = 0.0

        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {"Authorization": f"Bearer {secret}"}

            # 1. Solde complet (toutes les devises)
            try:
                resp = await client.get("https://api.stripe.com/v1/balance", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    available = data.get("available", [])
                    pending = data.get("pending", [])
                    metadata["stripe_balance_available"] = available
                    metadata["stripe_balance_pending"] = pending
                    if available:
                        score_boost += 0.3
                else:
                    validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.3)
                    validated.result = ValidationResult.REJECTED
                    return validated
            except Exception:
                validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.1)
                return validated

            # 2. Détails du compte
            try:
                resp = await client.get("https://api.stripe.com/v1/account", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    metadata["stripe_account_id"] = data.get("id")
                    metadata["stripe_email"] = data.get("email")
                    metadata["stripe_country"] = data.get("country")
                    metadata["stripe_type"] = data.get("type")  # standard, express, custom
                    score_boost += 0.2
            except Exception:
                pass

            # 3. Liste des abonnements (10 premiers)
            try:
                resp = await client.get("https://api.stripe.com/v1/subscriptions?limit=10", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    subs = data.get("data", [])
                    metadata["stripe_subscriptions_count"] = len(subs)
                    # Récupérer les IDs et statuts pour l'audit
                    metadata["stripe_subscriptions"] = [
                        {"id": s["id"], "status": s["status"], "plan": s.get("items", {}).get("data", [{}])[0].get("price", {}).get("id")}
                        for s in subs
                    ]
                    if subs:
                        score_boost += 0.1
            except Exception:
                pass

        # Ajouter le boost de confiance
        validated.candidate.confidence_score = min(1.0, validated.candidate.confidence_score + score_boost)
        validated.result = ValidationResult.CONFIRMED
        return validated
