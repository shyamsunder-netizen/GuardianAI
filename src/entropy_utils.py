import math
from collections import Counter


def calculate_entropy(text):
    """Shannon entropy (base 2) for a string."""
    if not text:
        return 0

    counter = Counter(text)
    length = len(text)
    entropy = 0.0

    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def domain_entropy(domain):
    """Entropy of a domain label with dots removed."""
    clean_domain = domain.replace(".", "")
    return calculate_entropy(clean_domain)
