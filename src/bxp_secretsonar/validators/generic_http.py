import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult

# Endpoints de validation connus par type de secret
VALIDATION_ENDPOINTS = {
    "generic_api_key": [
        {"url": "https://api.github.com/user", "header": "Authorization", "prefix": "token ", "success_codes": [200]},
        {"url": "https://api.openai.com/v1/models", "header": "Authorization", "prefix": "Bearer ", "success_codes": [200]},
    ],
    "bearer_token": [
        {"url": "https://api.github.com/user", "header": "Authorization", "prefix": "Bearer ", "success_codes": [200]},
    ],
}

# Patterns qui ne supportent PAS la validation active
NON_VALIDABLE_PATTERNS = {"private_key_header", "aws_access_key"}


class GenericHttpValidator:
    """Validateur actif générique avec timeout strict et SSL adaptatif."""

    def __init__(self, ssl_verify: bool = True, timeout: float = 5.0):
        self.ssl_verify = ssl_verify
        self.timeout = timeout

    async def validate(self, candidate: Candidate) -> Validated:
        pattern = candidate.evidence.pattern_name

        # Skip non-validable patterns
        if pattern in NON_VALIDABLE_PATTERNS:
            return Validated(
                candidate=candidate,
                result=ValidationResult.UNKNOWN,
                proof=f"Pattern '{pattern}' not actively validated",
                validator_name="generic_http",
            )

        endpoints = VALIDATION_ENDPOINTS.get(pattern, [])
        if not endpoints:
            return Validated(
                candidate=candidate,
                result=ValidationResult.UNKNOWN,
                proof="No validation endpoint configured",
                validator_name="generic_http",
            )

        async with httpx.AsyncClient(verify=self.ssl_verify, timeout=self.timeout) as client:
            for ep in endpoints:
                try:
                    headers = {ep["header"]: f"{ep['prefix']}{candidate.evidence.matched_value}"}
                    resp = await client.get(ep["url"], headers=headers)
                    if resp.status_code in ep["success_codes"]:
                        return Validated(
                            candidate=candidate,
                            result=ValidationResult.CONFIRMED,
                            proof=f"HTTP {resp.status_code} from {ep['url']}",
                            validator_name="generic_http",
                        )
                    elif resp.status_code in (401, 403):
                        return Validated(
                            candidate=candidate,
                            result=ValidationResult.REJECTED,
                            proof=f"HTTP {resp.status_code} from {ep['url']}",
                            validator_name="generic_http",
                        )
                except Exception as e:
                    continue  # Try next endpoint

        return Validated(
            candidate=candidate,
            result=ValidationResult.UNKNOWN,
            proof="All validation endpoints failed or inconclusive",
            validator_name="generic_http",
        )
