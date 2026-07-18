import re
from bxp_secretsonar.core.models import BlastRadiusItem

RESOURCE_PATTERNS = [
    ("api_endpoint", re.compile(r"https?://[a-zA-Z0-9._\-/]+(?:/v\d+)?/[a-zA-Z0-9/_\-]+")),
    ("s3_bucket", re.compile(r"(?:s3\.amazonaws\.com/|s3://)([a-zA-Z0-9._\-]+)")),
    ("git_repo", re.compile(r"(?:github\.com|gitlab\.com)/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+")),
    ("db_connection", re.compile(r"(?:postgres|mysql|mongodb)://[a-zA-Z0-9:_@.\-]+")),
    ("aws_arn", re.compile(r"arn:aws:[a-z]+:[a-z0-9\-]*:\d+:[a-zA-Z0-9:/_\-]+")),
]

def analyze_blast_radius(context_before: str, context_after: str) -> list[BlastRadiusItem]:
    full_context = f"{context_before} {context_after}"
    items: list[BlastRadiusItem] = []
    seen: set[str] = set()
    for resource_type, pattern in RESOURCE_PATTERNS:
        for match in pattern.finditer(full_context):
            identifier = match.group(0)
            if identifier not in seen:
                seen.add(identifier)
                items.append(BlastRadiusItem(resource_type=resource_type, identifier=identifier, confidence=0.7))
    return items
