import pytest
from unittest.mock import AsyncMock, patch
import httpx
from bxp_secretsonar.core.models import Artifact, ArtifactType, RiskLevel
from bxp_secretsonar.detectors.passive import analyze_passive
from bxp_secretsonar.detectors.active import probe_behavior
from bxp_secretsonar.detectors.scorer import compute_risk_score

def _make_artifact(content): return Artifact(source_url="https://target.test", content=content, artifact_type=ArtifactType.HTTP_RESPONSE)

def test_detects_cowrie(): assert "cowrie_ssh_banner" in analyze_passive(_make_artifact("Welcome to Cowrie SSH honeypot"))
def test_detects_canary(): assert "canary_token_marker" in analyze_passive(_make_artifact("This page contains a canary token"))
def test_clean_content(): assert len(analyze_passive(_make_artifact("<html>Welcome to portal</html>"))) == 0
def test_fake_error(): assert "fake_error_page" in analyze_passive(_make_artifact("403 Forbidden contact admin report issue"))

@pytest.mark.asyncio
async def test_probe_connection_error():
    with patch.object(httpx.AsyncClient, "request", new_callable=AsyncMock, side_effect=httpx.ConnectError("fail")):
        signals = await probe_behavior("https://target.test", timeout=1.0)
    assert "probe_connection_error" in signals

def test_zero_signals_low_risk():
    s = compute_risk_score("https://clean.test", [], [])
    assert s.composite_score == 0.0 and s.risk_level == RiskLevel.LOW

def test_high_confidence_critical():
    s = compute_risk_score("https://hp.test", ["cowrie_ssh_banner", "canary_token_marker"], ["ultra_fast_response"])
    assert s.composite_score >= 0.85 and s.risk_level == RiskLevel.CRITICAL
