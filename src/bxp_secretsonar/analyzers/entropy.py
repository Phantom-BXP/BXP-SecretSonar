import math
from collections import Counter

def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values() if c > 0), 4)

THRESHOLDS = {"short": (8, 3.5), "medium": (16, 4.0), "long": (32, 4.5)}

def is_high_entropy(value):
    ln = len(value)
    ent = shannon_entropy(value)
    if ln < THRESHOLDS["short"][0]:
        return False
    if ln < THRESHOLDS["medium"][0]:
        return ent >= THRESHOLDS["short"][1]
    if ln < THRESHOLDS["long"][0]:
        return ent >= THRESHOLDS["medium"][1]
    return ent >= THRESHOLDS["long"][1]
