import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.utils.stealth import StealthManager

# Patterns pour lesquels une validation HTTP générique est autorisée.
VALID_PATTERNS = [
    "generic_api_key",
    "bearer_token",
    "api_key",
    "auth_token",
    "access_token",
    "secret_key",
    "aws_access_key",
    "aws_secret_key",
    "stripe_key",
    "github_token",
    "gitlab_token",
    "slack_token",
    "discord_token",
    "paypal_secret",
    "twilio_sid",
    "twilio_token",
    "gcp_api_key",
    "heroku_api_key",
    "sendgrid_api_key",
    "mailgun_api_key",
    "atlassian_api_token",
    "shopify_access_token",
    "openai_api_key",
    "anthropic_api_key",
    "revolut_token",
    "twitch_token",
]

class GenericHttpValidator:
    def __init__(self, ssl_verify: bool = True, timeout: float = 5.0, stealth_mgr: StealthManager = None, proxy: str = None):
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.stealth_mgr = stealth_mgr or StealthManager()
        self.proxy = proxy

    async def validate(self, candidate: Candidate) -> Validated:
        pattern = candidate.evidence.pattern_name.lower()
        
        # Filtre défensif : ne valider que les patterns autorisés
        if pattern not in VALID_PATTERNS:
            return Validated(
                candidate=candidate,
                result=ValidationResult.UNKNOWN,
                validator_name="generic_http",
                proof=f"Pattern '{candidate.evidence.pattern_name}' non validé (hors liste ou exclu)"
            )

        # Validation HTTP basique
        headers = self.stealth_mgr.get_headers("generic")
        secret = candidate.evidence.matched_value
        headers["Authorization"] = f"Bearer {secret}"
        url = candidate.evidence.source_url or "http://example.com"

        try:
            async with httpx.AsyncClient(verify=self.ssl_verify, timeout=self.timeout, headers=headers, proxy=self.proxy) as client:
                resp = await client.get(url)
                self.stealth_mgr.record_request(resp.status_code == 200)
                if resp.status_code == 200:
                    return Validated(
                        candidate=candidate,
                        result=ValidationResult.CONFIRMED,
                        validator_name="generic_http"
                    )
                elif resp.status_code in (401, 403):
                    return Validated(
                        candidate=candidate,
                        result=ValidationResult.REJECTED,
                        validator_name="generic_http"
                    )
                else:
                    return Validated(
                        candidate=candidate,
                        result=ValidationResult.UNKNOWN,
                        validator_name="generic_http"
                    )
        except Exception:
            return Validated(
                candidate=candidate,
                result=ValidationResult.UNKNOWN,
                validator_name="generic_http"
            )
