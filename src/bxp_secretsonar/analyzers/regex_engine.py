import re
from bxp_secretsonar.analyzers.entropy import is_high_entropy, shannon_entropy

PATTERNS = [
    ("aws_access_key", re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"), False, 0.8),
    ("generic_api_key", re.compile(r'(?i)(?:api[_-]?key|apikey|token|secret|password|auth)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,64})["\']?'), True, 0.6),
    ("bearer_token", re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})"), True, 0.7),
    ("private_key_header", re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"), False, 0.95),
]

CONTEXT_WINDOW = 50


def analyze_content(content: str, artifact_id: str) -> list[dict]:
    evidences = []
    for name, regex, req_ent, min_conf in PATTERNS:
        for m in regex.finditer(content):
            val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            if req_ent and not is_high_entropy(val):
                continue
            s = max(0, m.start() - CONTEXT_WINDOW)
            e = min(len(content), m.end() + CONTEXT_WINDOW)
            evidences.append({
                "artifact_id": artifact_id,
                "pattern_name": name,
                "matched_value": val,
                "context_before": content[s:m.start()],
                "context_after": content[m.end():e],
                "entropy_score": shannon_entropy(val),
                "base_confidence": min_conf,
            })
    return evidences
