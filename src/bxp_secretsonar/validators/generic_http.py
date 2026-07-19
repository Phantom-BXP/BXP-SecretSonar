import httpx
from bxp_secretsonar.core.models import Candidate, Validated, ValidationResult
from bxp_secretsonar.utils.stealth import StealthManager
from bxp_secretsonar.utils.resilience import get_circuit_breaker, CircuitState

VALID_PATTERNS = [
    "generic_api_key", "bearer_token", "api_key", "auth_token", "access_token",
    "secret_key", "aws_access_key", "aws_secret_key", "stripe_key",
    "github_token", "gitlab_token", "slack_token", "discord_token",
    "paypal_secret", "twilio_sid", "twilio_token", "gcp_api_key",
    "heroku_api_key", "sendgrid_api_key", "mailgun_api_key",
    "atlassian_api_token", "shopify_access_token", "openai_api_key",
    "anthropic_api_key", "revolut_token", "twitch_token",
]

class GenericHttpValidator:
    def __init__(self, ssl_verify: bool = True, timeout: float = 5.0,
                 stealth_mgr: StealthManager = None, proxy: str = None):
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.stealth_mgr = stealth_mgr or StealthManager()
        self.proxy = proxy

    def _get_client(self, service: str = "generic"):
        """Retourne un client HTTP configuré avec le transport TLS du profil actif."""
        return self.stealth_mgr.get_client(service)


    async def validate(self, candidate: Candidate) -> Validated:
        pattern = candidate.evidence.pattern_name.lower()
        if pattern not in VALID_PATTERNS:
            return Validated(
                candidate=candidate,
                result=ValidationResult.UNKNOWN,
                validator_name="generic_http",
                proof=f"Pattern '{candidate.evidence.pattern_name}' non validé (hors liste ou exclu)"
            )

        secret = candidate.evidence.matched_value
        url = candidate.evidence.source_url or "http://example.com"

        # Vérifier le circuit breaker pour ce service
        circuit = get_circuit_breaker("generic_http")
        if circuit.is_open():
            return Validated(
                candidate=candidate,
                result=ValidationResult.UNKNOWN,
                validator_name="generic_http",
                proof="Circuit breaker ouvert – service temporairement indisponible"
            )
        try:
            client = self._get_client("generic")
            client.headers["Authorization"] = f"Bearer {secret}"
            async with client:
                resp = await client.get(url)
                self.stealth_mgr.record_request(resp.status_code == 200)
                if resp.status_code == 200:
                    circuit.record_success()
                elif resp.status_code in (401, 403):
                    circuit.record_failure(temporary=False)  # erreur permanente
                elif resp.status_code >= 500:
                    circuit.record_failure(temporary=True)
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
