import pytest
from unittest.mock import MagicMock,  AsyncMock, patch
from bxp_secretsonar.core.models import ProtocolProbeResult, ProtocolProbeStatus, BlastRadiusItem, RiskLevel
from bxp_secretsonar.plugins.validators.protocol_prober import ProtocolProber
from bxp_secretsonar.plugins.analyzers.blast_radius import analyze_blast_radius
from bxp_secretsonar.plugins.analyzers.impact_scorer import compute_impact_score

def test_extracts_api_endpoint(): assert any(i.resource_type == "api_endpoint" for i in analyze_blast_radius("Calling https://api.example.com/v1/users", ""))
def test_extracts_s3(): assert any(i.resource_type == "s3_bucket" for i in analyze_blast_radius("", "Upload to s3://my-bucket/data"))
def test_extracts_git(): assert any(i.resource_type == "git_repo" for i in analyze_blast_radius("github.com/acme/tools repo", ""))
def test_no_fp(): assert len(analyze_blast_radius("Normal documentation text.", "")) == 0

@pytest.mark.asyncio
async def test_ssh_banner():
    r = AsyncMock(); r.readline = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.9\r\n")
    w = AsyncMock()
    w.close = MagicMock()
    with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(r, w)):
        result = await ProtocolProber().probe_ssh("localhost", 22, timeout=2.0)
    assert result.status == ProtocolProbeStatus.HANDSHAKE_OK and "OpenSSH" in (result.banner or "")

def test_critical_impact():
    p = ProtocolProbeResult(protocol="ssh", status=ProtocolProbeStatus.AUTH_ACCEPTED, latency_ms=50)
    br = [BlastRadiusItem(resource_type="db_connection", identifier="postgres://prod", confidence=0.8)]
    s = compute_impact_score("private_key_header", p, br)
    assert s.impact_level == RiskLevel.CRITICAL and s.composite_score >= 0.8

def test_low_impact_rejected():
    p = ProtocolProbeResult(protocol="http", status=ProtocolProbeStatus.AUTH_REJECTED, latency_ms=200)
    s = compute_impact_score("generic_api_key", p, [])
    assert s.impact_level == RiskLevel.LOW and s.composite_score < 0.35
