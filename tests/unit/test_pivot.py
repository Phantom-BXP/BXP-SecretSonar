import pytest
from unittest.mock import MagicMock, patch
from bxp_secretsonar.plugins.post_exploit.pivot import PivotSOCKS

def test_pivot_socks():
    mock_client = MagicMock()
    mock_transport = MagicMock()
    mock_transport.is_active.return_value = True
    mock_client.get_transport.return_value = mock_transport
    mock_session = MagicMock()
    mock_session.tunnel = mock_client

    plugin = PivotSOCKS()
    # Mocker la vérification de port pour éviter une vraie connexion
    with patch.object(plugin, '_check_port', return_value=True):
        result = plugin.run(mock_session, {"port": 1080})
        mock_transport.request_port_forward.assert_called_once_with('', 1080)
        assert result["success"] is True
