import pytest
from bxp_secretsonar.analyzers.entropy import shannon_entropy, is_high_entropy

def test_empty_string(): assert shannon_entropy("") == 0.0
def test_uniform_low(): assert shannon_entropy("aaaaaaaaaa") == 0.0
def test_binary(): assert 0.9 < shannon_entropy("01010101") < 1.1
def test_high_random(): assert is_high_entropy("aK7xQ9mZ2pL5wR8nT4") is True
def test_low_random(): assert is_high_entropy("password123") is False
def test_short_rejected(): assert is_high_entropy("abc") is False
