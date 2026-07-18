import httpx, re
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.validators.generic_http import GenericHttpValidator

class TwilioValidator(GenericHttpValidator):
    async def validate(self, candidate: Candidate) -> Validated:
        validated = await super().validate(candidate)
        if validated.result != ValidationResult.CONFIRMED:
            return validated
        secret = candidate.evidence.matched_value
        # Twilio credentials often appear as "SID:AuthToken" or separate
        sid = None
        token = secret
        if ":" in secret:
            parts = secret.split(":")
            sid = parts[0]
            token = parts[1] if len(parts) > 1 else ""
        # Try to list accounts (requires valid SID/Token pair)
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                if sid and token:
                    resp = await client.get(
                        f"https://api.twilio.com/2010-04-01/Accounts/{sid}",
                        auth=(sid, token)
                    )
                else:
                    # Fallback: try as auth token with empty SID (unlikely)
                    resp = await client.get(
                        "https://api.twilio.com/2010-04-01/Accounts",
                        auth=(secret, secret)
                    )
                if resp.status_code == 200:
                    data = resp.json()
                    # If we got account details, high confidence
                    validated.candidate.confidence_score = min(1.0, validated.candidate.confidence_score + 0.5)
                    validated.result = ValidationResult.CONFIRMED
                    validated.candidate.evidence.metadata["twilio_sid"] = data.get("sid", "")
                elif resp.status_code in (401, 403):
                    validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.3)
                    validated.result = ValidationResult.REJECTED
        except Exception:
            validated.candidate.confidence_score = max(0.1, validated.candidate.confidence_score - 0.1)
        return validated
