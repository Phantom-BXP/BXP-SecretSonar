import pytest
from bxp_secretsonar.utils.security import validate_url, mask_secret, sanitize_log

def test_validate_url_blocks_private():
    valid, msg = validate_url("http://192.168.1.1")
    assert not valid
    assert "bloquée" in msg

def test_validate_url_allows_public():
    valid, msg = validate_url("https://example.com")
    assert valid

def test_validate_url_allows_private_with_flag():
    valid, msg = validate_url("http://10.0.0.1", allow_private=True)
    assert valid

def test_validate_url_blocks_non_http():
    valid, msg = validate_url("ftp://example.com")
    assert not valid
    assert "Schéma" in msg

def test_mask_secret():
    masked = mask_secret("sk_live_1234567890")
    assert masked.startswith('*')
    assert masked.endswith('7890')

def test_sanitize_log():
    sanitized = sanitize_log("sk_live_12345678")
    # La chaîne doit contenir des astérisques après le préfixe
    assert '****' in sanitized
    assert sanitized.startswith('sk_live_')
