import pytest
from unittest.mock import MagicMock, patch
from bxp_secretsonar.plugins.post_exploit.bypass_2fa import Bypass2FA
from bxp_secretsonar.core.models import Evidence

def test_replay_success():
    plugin = Bypass2FA()
    mock_sess = MagicMock()
    mock_sess.evidence = Evidence(artifact_id="x", pattern_name="github_token", matched_value="ghp_test")
    with patch('httpx.Client.get') as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_get.return_value = mock_resp
        result = plugin.run(mock_sess, {"action": "replay"})
        assert result["success"] is True
        assert "valide" in result["output"]

def test_generate_token_saves():
    plugin = Bypass2FA()
    mock_sess = MagicMock()
    mock_sess.evidence = Evidence(artifact_id="y", pattern_name="github_token", matched_value="session_cookie")
    with patch('httpx.Client.post') as mock_post:
        mock_resp = MagicMock(status_code=201)
        mock_resp.json.return_value = {"token": "new_pat_token"}
        mock_post.return_value = mock_resp
        result = plugin.run(mock_sess, {"action": "generate_token"})
        assert result["success"] is True
