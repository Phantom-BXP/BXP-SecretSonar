from bxp_secretsonar.core.models import RiskScore, RiskLevel

SIGNAL_WEIGHTS = {
    "cowrie_ssh_banner": 0.9, "dionaea_default_page": 0.85,
    "generic_honeypot_form": 0.6, "fake_error_page": 0.3,
    "default_credentials_hint": 0.5, "canary_token_marker": 0.95,
    "ultra_fast_response": 0.7, "uniform_timing": 0.65,
    "incompatible_headers_nginx_express": 0.8, "incompatible_headers_apache_flask": 0.8,
    "incompatible_headers_iis_php": 0.75, "incompatible_headers_cloudflare_tomcat": 0.8,
    "missing_standard_headers": 0.4, "unexpected_status_200": 0.5,
    "probe_connection_error": 0.2,
}


def compute_risk_score(target_url: str, passive_signals: list[str], active_signals: list[str]) -> RiskScore:
    all_signals = passive_signals + active_signals
    if not all_signals:
        return RiskScore(target_url=target_url, composite_score=0.0, risk_level=RiskLevel.LOW)
    weighted_sum = sum(SIGNAL_WEIGHTS.get(s, 0.3) for s in all_signals)
    composite = min(1.0, weighted_sum / max(len(all_signals), 1) * (1 + 0.3 * len(all_signals)))
    composite = round(min(1.0, composite), 3)
    if composite >= 0.85:
        level = RiskLevel.CRITICAL
    elif composite >= 0.6:
        level = RiskLevel.HIGH
    elif composite >= 0.35:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW
    return RiskScore(target_url=target_url, passive_signals=passive_signals, active_signals=active_signals, composite_score=composite, risk_level=level)
