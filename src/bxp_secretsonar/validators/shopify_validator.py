import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator

class ShopifyValidator(GenericHttpValidator):
    async def validate(self, candidate: Candidate) -> Validated:
        validated = await super().validate(candidate)
        if validated.result != ValidationResult.CONFIRMED:
            return validated
        secret = candidate.evidence.matched_value
        # On essaie avec un store générique (pas idéal, mais permet de tester la clé)
        # En pratique, il faut le store name, mais on peut tenter une requête générique.
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                # Tentative d'utiliser la clé comme X-Shopify-Access-Token sur un admin API endpoint fictif
                resp = await client.get("https://test.myshopify.com/admin/api/2024-01/shop.json", headers={"X-Shopify-Access-Token": secret})
                # Le code 401 signifie clé invalide ou mauvais store, 200 = valide
                if resp.status_code == 200:
                    validated.candidate.confidence_score = min(1.0, validated.candidate.confidence_score + 0.4)
                    validated.result = ValidationResult.CONFIRMED
                elif resp.status_code == 401:
                    validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.3)
                    validated.result = ValidationResult.REJECTED
        except Exception:
            validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.1)
        return validated
