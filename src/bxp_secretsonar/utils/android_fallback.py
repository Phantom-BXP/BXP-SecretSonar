"""Fallback TLS pour Android/Termux sans tls_client (optionnel)."""
try:
    import ssl
    import requests
    ANDROID_FALLBACK_AVAILABLE = True
except ImportError:
    ANDROID_FALLBACK_AVAILABLE = False

if ANDROID_FALLBACK_AVAILABLE:
    class AndroidTLSAdapter(requests.adapters.HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            ctx = ssl.create_default_context()
            ctx.set_ciphers(
                "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
            )
            kwargs["ssl_context"] = ctx
            return super().init_poolmanager(*args, **kwargs)

    def create_android_client(headers: dict, proxy: str = None):
        session = requests.Session()
        adapter = AndroidTLSAdapter()
        session.mount("https://", adapter)
        session.headers.update(headers)
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
        return session
else:
    def create_android_client(headers, proxy=None):
        raise ImportError("requests n'est pas installé. Impossible d'utiliser le fallback Android.")
