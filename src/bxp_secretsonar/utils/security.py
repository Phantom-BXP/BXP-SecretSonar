import re, ipaddress
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'), ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'), ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
]
BLOCKED_HOSTNAMES = ['localhost', 'localhost.localdomain', 'metadata.google.internal', '169.254.169.254']
ALLOWED_SCHEMES = {'http', 'https'}
ALLOW_PRIVATE = False

def is_blocked_ip(hostname: str) -> bool:
    if ALLOW_PRIVATE:
        return False
    try:
        ip = ipaddress.ip_address(hostname)
        for network in BLOCKED_NETWORKS:
            if ip in network: return True
    except ValueError:
        if hostname.lower() in BLOCKED_HOSTNAMES: return True
    return False

def mask_secret(secret: str, visible_chars: int = 4) -> str:
    if len(secret) <= visible_chars:
        return '*' * len(secret)
    return '*' * (len(secret) - visible_chars) + secret[-visible_chars:]

def validate_url(url: str, allow_private: bool = False) -> tuple:
    global ALLOW_PRIVATE
    ALLOW_PRIVATE = allow_private
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ALLOWED_SCHEMES:
            return False, f"Schéma non autorisé : {parsed.scheme}"
        if not parsed.hostname:
            return False, "Hostname manquant"
        if is_blocked_ip(parsed.hostname):
            return False, f"Adresse bloquée (utilisez --allow-private pour autoriser) : {parsed.hostname}"
        if re.search(r'[<>\"\'\\|;`\$\{\}]', url):
            return False, "Caractères dangereux"
        return True, ""
    except Exception as e:
        return False, f"URL invalide : {e}"

def sanitize_log(data: str, max_length: int = 100) -> str:
    if not data:
        return ""
    if len(data) > max_length:
        data = data[:max_length] + "..."
    # Masquer les clés Stripe (sk_live_xxxx, sk_test_xxxx)
    data = re.sub(r'(sk_(?:live|test)_)[a-zA-Z0-9]+', r'\1****', data)
    # Masquer les clés AWS (AKIAxxxx)
    data = re.sub(r'(AKIA[0-9A-Z]{4})[0-9A-Z]+', r'\1****', data)
    return data
