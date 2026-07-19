import pytest
from unittest.mock import AsyncMock, patch
import httpx
from bxp_secretsonar.detectors.passive import analyze_passive
from bxp_secretsonar.detectors.active import probe_behavior
from bxp_secretsonar.detectors.scorer import compute_risk_score
from bxp_secretsonar.core.models import Artifact, ArtifactType, RiskLevel

def _make_artifact(content: str) -> Artifact:
    return Artifact(source_url="https://target.test", content=content, artifact_type=ArtifactType.HTTP_RESPONSE)

def test_detects_cowrie():
    art = _make_artifact("Welcome to Cowrie SSH honeypot")
    signals = analyze_passive(art)
    assert "cowrie_ssh_banner" in signals

def test_detects_canary():
    art = _make_artifact("This page contains a canary token")
    signals = analyze_passive(art)
    assert "canary_token_marker" in signals

def test_clean_content():
    art = _make_artifact("<html><body>Welcome</body></html>")
    signals = analyze_passive(art)
    assert len(signals) == 0

def test_fake_error():
    art = _make_artifact("403 Forbidden - contact admin")
    signals = analyze_passive(art)
    assert "fake_error_page" in signals

@pytest.mark.asyncio
async def test_probe_connection_error():
    with patch.object(httpx.AsyncClient, "request", new_callable=AsyncMock, side_effect=httpx.ConnectError("fail")):
        signals = await probe_behavior("https://target.test", timeout=1.0)
    assert "probe_connection_error" in signals

def test_zero_signals_low_risk():
    score = compute_risk_score("https://clean.test", [], [])
    assert score.composite_score == 0.0
    assert score.risk_level == RiskLevel.LOW
    assert not score.is_suspicious

def test_high_confidence_critical():
    # Appel correct : target_url, passive_signals, active_signals
    score = compute_risk_score(
        "https://hp.test",
        ["cowrie_ssh_banner", "canary_token_marker"],
        ["ultra_fast_response"]
    )
    assert score.composite_score >= 0.85
    assert score.risk_level == RiskLevel.CRITICAL
    assert score.is_suspicious
