import pytest
from unittest.mock import MagicMock
from bxp_secretsonar.plugins.post_exploit.persist import PersistSSHKey

def test_persist_ssh_key():
    # Mock session SSH
    mock_client = MagicMock()
    mock_session = MagicMock()
    mock_session.tunnel = mock_client
    mock_stdout = MagicMock()
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stdout.read.return_value = b""
    mock_client.exec_command.return_value = (None, mock_stdout, MagicMock())
    
    plugin = PersistSSHKey()
    # Créer une clé publique temporaire
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pub') as f:
        f.write("ssh-rsa AAAAB3NzaC1yc2E... testkey")
        pubkey_path = f.name
    try:
        result = plugin.run(mock_session, {"pubkey": pubkey_path})
        assert result["success"] is True
        # Vérifier que la commande exécutée contient les éléments attendus
        called_cmd = mock_client.exec_command.call_args[0][0]
        assert "authorized_keys" in called_cmd
        assert "ssh-rsa" in called_cmd
    finally:
        os.unlink(pubkey_path)
