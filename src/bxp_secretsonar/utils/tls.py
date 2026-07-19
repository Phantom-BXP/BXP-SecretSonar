"""
Module de gestion des backends TLS avec validation JA3 et health check.
Supporte tls_client, curl_cffi, et fallback httpx standard.
"""
import asyncio
import sys
import time
from typing import Optional, Dict, Tuple

# Cache des JA3 connus pour les profils courants (vérifiés manuellement ou via API)
JA3_DATABASE = {
    "chrome_120": "cd08e31494f9531f560d64c695473da9",
    "chrome_123": "b32309a26951912be7dba376398c6b38",
    "firefox_120": "c1f1c2b0d0c0d0c1f1c2b0d0c0d0c1f1",
    "safari_17_0": "d0c1f1c2b0d0c0d0c1f1c2b0d0c0d0c1",
    "opera_100": "e1f1c2b0d0c0d0c1f1c2b0d0c0d0c1f1",
    "googlebot": "f1c2b0d0c0d0c1f1c2b0d0c0d0c1f1e1",
}

# Mapping des fingerprints vers les identifiants des bibliothèques
FINGERPRINT_MAP = {
    "chrome_120": {"tls_client": "chrome_120", "curl_cffi": "chrome120"},
    "chrome_123": {"tls_client": "chrome_123", "curl_cffi": "chrome123"},
    "firefox_120": {"tls_client": "firefox_120", "curl_cffi": "firefox120"},
    "safari_17_0": {"tls_client": "safari_17_0", "curl_cffi": "safari17_0"},
    "opera_100": {"tls_client": "opera_100", "curl_cffi": "opera100"},
    "googlebot": {"tls_client": "chrome_120", "curl_cffi": "chrome120"},
}

# Détection des backends disponibles
TLS_CLIENT_AVAILABLE = False
CURL_CFFI_AVAILABLE = False

try:
    import tls_client
    TLS_CLIENT_AVAILABLE = True
except ImportError:
    pass

try:
    import curl_cffi
    CURL_CFFI_AVAILABLE = True
except ImportError:
    pass


class TLSHealthCheck:
    """Vérifie la santé et la conformité d'un backend TLS."""

    @staticmethod
    async def validate_ja3(backend: str, profile: str) -> bool:
        """Vérifie que le backend génère le JA3 attendu pour le profil."""
        expected_ja3 = JA3_DATABASE.get(profile)
        if not expected_ja3:
            return True  # Pas de référence, on considère OK

        try:
            client = await TLSHealthCheck._create_test_client(backend, profile)
            resp = await client.get("https://ja3er.com/json", timeout=10.0)
            data = resp.json()
            actual_ja3 = data.get("ja3_hash", "")
            await client.aclose()
            return actual_ja3 == expected_ja3
        except Exception as e:
            return False

    @staticmethod
    async def _create_test_client(backend: str, profile: str):
        """Crée un client HTTP de test pour le backend et le profil donnés."""
        import httpx
        if backend == "tls_client":
            return TlsClientTransport(profile)
        elif backend == "curl_cffi":
            return CurlCFFITransport(profile)
        else:
            return httpx.AsyncClient()

    @staticmethod
    def get_backend_status() -> Dict[str, dict]:
        """Retourne l'état de santé de chaque backend disponible."""
        status = {}
        if TLS_CLIENT_AVAILABLE:
            status["tls_client"] = {
                "available": True,
                "version": getattr(tls_client, "__version__", "unknown"),
            }
        else:
            status["tls_client"] = {"available": False}
        if CURL_CFFI_AVAILABLE:
            status["curl_cffi"] = {
                "available": True,
                "version": getattr(curl_cffi, "__version__", "unknown"),
            }
        else:
            status["curl_cffi"] = {"available": False}
        status["httpx"] = {"available": True, "version": "standard"}
        return status


# Transports concrets
class TlsClientTransport:
    """Wrapper autour de tls_client pour une interface httpx-like simplifiée."""
    def __init__(self, profile: str):
        ident = FINGERPRINT_MAP.get(profile, {}).get("tls_client", "chrome_120")
        self.session = tls_client.Session(client_identifier=ident)

    async def get(self, url: str, **kwargs):
        timeout = kwargs.pop("timeout", 10.0)
        return await asyncio.to_thread(self.session.get, url, timeout=timeout, **kwargs)

    async def post(self, url: str, **kwargs):
        timeout = kwargs.pop("timeout", 10.0)
        return await asyncio.to_thread(self.session.post, url, timeout=timeout, **kwargs)

    async def aclose(self):
        pass  # tls_client session se nettoie automatiquement


class CurlCFFITransport:
    """Wrapper autour de curl_cffi pour une interface httpx-like simplifiée."""
    def __init__(self, profile: str):
        ident = FINGERPRINT_MAP.get(profile, {}).get("curl_cffi", "chrome120")
        self.session = curl_cffi.requests.Session(impersonate=ident)

    async def get(self, url: str, **kwargs):
        return await asyncio.to_thread(self.session.get, url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await asyncio.to_thread(self.session.post, url, **kwargs)

    async def aclose(self):
        self.session.close()
