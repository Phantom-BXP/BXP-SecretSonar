import pytest
from bxp_secretsonar.analyzers.regex_engine import analyze_content

def test_aws_key():
    r = analyze_content('key=AKIAIOSFODNN7EXAMPLE', "a1")
    assert any(x["pattern_name"] == "aws_access_key" for x in r)

def test_generic_api_key():
    r = analyze_content('api_key=sk_live_a1b2c3d4e5f6g7h8', "a2")
    hits = [x for x in r if x["pattern_name"] == "generic_api_key"]
    assert len(hits) >= 1

def test_low_entropy_rejected():
    r = analyze_content('api_key=aaaaaaaaaaaaaaaaaaaa', "a3")
    assert not any(x["pattern_name"] == "generic_api_key" for x in r)

def test_private_key():
    r = analyze_content('-----BEGIN RSA PRIVATE KEY-----', "a4")
    assert any(x["pattern_name"] == "private_key_header" for x in r)

def test_no_false_positive():
    r = analyze_content('Normal text about software development.', "a5")
    assert len(r) == 0
