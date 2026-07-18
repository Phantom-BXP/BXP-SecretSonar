import pytest
import os, tempfile
from bxp_secretsonar.daemon import SecretSonarDaemon

def test_daemon_loads_queries():
    # Créer un fichier de queries temporaire
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("example.com\n")
        queries_file = f.name
    try:
        daemon = SecretSonarDaemon(queries_file=queries_file)
        queries = daemon._load_queries()
        assert "example.com" in queries
    finally:
        os.unlink(queries_file)

def test_daemon_initial_state():
    daemon = SecretSonarDaemon(queries_file="nonexistent.txt")
    assert daemon.state == {"runs": [], "sessions": [], "tokens": {}}
