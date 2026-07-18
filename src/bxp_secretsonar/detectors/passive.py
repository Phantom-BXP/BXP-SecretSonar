import re
from bxp_secretsonar.core.models import Artifact

PASSIVE_SIGNATURES = [
    ("cowrie_ssh_banner", re.compile(r"(?i)cowrie|kippo|ssh-honeypot")),
    ("dionaea_default_page", re.compile(r"(?i)dionaea|malware\s*capture|honeypot\s*project")),
    ("generic_honeypot_form", re.compile(r"(?i)<form[^>]*action=['\"](?:login|auth|submit)['\"][^>]*>\s*<input[^>]*name=['\"](?:user|pass|admin)", re.IGNORECASE)),
    ("fake_error_page", re.compile(r"(?i)(?:403|404|500)\s+(?:forbidden|not\s+found|error).*(?:contact\s+admin|report\s+issue)", re.IGNORECASE)),
    ("default_credentials_hint", re.compile(r"(?i)(?:default|test|demo)\s*(?:credentials?|login|password|user)\s*[:=]\s*\w+")),
    ("canary_token_marker", re.compile(r"(?i)canary|thinkst|trap|decoy|lure")),
]


def analyze_passive(artifact: Artifact) -> list[str]:
    signals = []
    for name, pattern in PASSIVE_SIGNATURES:
        if pattern.search(artifact.content):
            signals.append(name)
    return signals
