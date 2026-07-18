from bxp_secretsonar.core.models import ImpactScore, RiskLevel, ProtocolProbeResult, ProtocolProbeStatus, BlastRadiusItem

SECRET_TYPE_WEIGHTS = {"private_key_header": 0.95, "aws_access_key": 0.9, "generic_api_key": 0.6, "bearer_token": 0.7}
PROBE_STATUS_WEIGHTS = {ProtocolProbeStatus.AUTH_ACCEPTED: 0.9, ProtocolProbeStatus.HANDSHAKE_OK: 0.4, ProtocolProbeStatus.AUTH_REJECTED: 0.1, ProtocolProbeStatus.TIMEOUT: 0.05, ProtocolProbeStatus.ERROR: 0.0, ProtocolProbeStatus.NOT_APPLICABLE: 0.0}

def compute_impact_score(secret_type: str, probe_result: ProtocolProbeResult | None = None, blast_radius: list[BlastRadiusItem] | None = None) -> ImpactScore:
    type_weight = SECRET_TYPE_WEIGHTS.get(secret_type, 0.5)
    probe_weight = PROBE_STATUS_WEIGHTS.get(probe_result.status, 0.0) if probe_result else 0.0
    br_weight = min(1.0, sum(i.confidence for i in blast_radius) / max(len(blast_radius), 1)) if blast_radius else 0.0
    composite = round(min(1.0, (type_weight * 0.4) + (probe_weight * 0.35) + (br_weight * 0.25)), 3)
    if composite >= 0.8: level = RiskLevel.CRITICAL
    elif composite >= 0.6: level = RiskLevel.HIGH
    elif composite >= 0.35: level = RiskLevel.MEDIUM
    else: level = RiskLevel.LOW
    parts = [f"type={secret_type}({type_weight:.2f})"]
    if probe_result: parts.append(f"probe={probe_result.status.value}({probe_weight:.2f})")
    if blast_radius: parts.append(f"blast_radius={len(blast_radius)}res({br_weight:.2f})")
    return ImpactScore(secret_type=secret_type, protocol_probe=probe_result, blast_radius=blast_radius or [], impact_level=level, composite_score=composite, reasoning=" + ".join(parts))
