import random, time, json, os
from bxp_secretsonar.utils.tls import TLS_CLIENT_AVAILABLE, CURL_CFFI_AVAILABLE, TLSHealthCheck, TlsClientTransport, CurlCFFITransport
try:
    from bxp_secretsonar.utils.android_fallback import create_android_client, ANDROID_FALLBACK_AVAILABLE
except ImportError:
    ANDROID_FALLBACK_AVAILABLE = False
    create_android_client = None

from bxp_secretsonar.utils.proxy_bandit import ProxyBandit
from typing import Dict, List, Optional
from dataclasses import dataclass, field

PROFILES_FILE = "stealth_profiles.json"

@dataclass
class StealthProfile:
    name: str
    user_agents: List[str]
    headers: Dict[str, str]
    delays: tuple[float, float]
    description: str = ""
    score: float = 0.0
    tags: List[str] = field(default_factory=list)
    tls_fingerprint: str = ""  # ex: chrome_120

    def evaluate(self) -> float:
        score = 0.5
        if len(self.user_agents) >= 3:
            score += 0.15
        modern_headers = ["sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-ch-ua"]
        if any(h in {k.lower() for k in self.headers} for h in modern_headers):
            score += 0.15
        if self.delays[0] >= 0.5:
            score += 0.1
        if "enterprise" in self.tags:
            score += 0.1
        return round(min(1.0, score), 2)


class StealthManager:
    def __init__(self):
        self.profiles: Dict[str, StealthProfile] = {}
        self.active_profile: str = "mobile_user"
        self._usage_stats: Dict[str, int] = {}
        self._proxy: Optional[str] = None
        self._profile_start_time = time.time()
        self._request_count = 0
        self._errors = 0
        self._max_requests_per_profile = 50
        self._max_profile_duration = 1800
        self._per_target_profiles = {}
        self._health_cache = {}
        self.proxy_bandit = None  # initialisé plus tard
        self._load_defaults()
        self._load_custom()

    def _load_defaults(self):
        defaults = [
            StealthProfile(
                name="mobile_user",
                user_agents=[
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
                    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36",
                ],
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                },
                delays=(0.5, 2.0),
                description="Utilisateur mobile standard",
                tls_fingerprint="safari_17_0",
                tags=["mobile", "consumer"]
            ),
            StealthProfile(
                name="corporate_vpn",
                user_agents=[
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
                ],
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                },
                delays=(1.0, 4.0),
                description="Employé de bureau derrière un VPN d'entreprise",
                tls_fingerprint="chrome_120",
                tags=["enterprise", "corporate"]
            ),
            StealthProfile(
                name="googlebot",
                user_agents=[
                    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                ],
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Encoding": "gzip,deflate,br",
                    "From": "googlebot@google.com",
                },
                delays=(2.0, 10.0),
                description="Robot d'indexation Google",
                tls_fingerprint="chrome_120",
                tags=["bot", "search_engine"]
            ),
            StealthProfile(
                name="api_client",
                user_agents=[
                    "python-requests/2.31.0",
                    "curl/8.4.0",
                    "BXP-SecretSonar/0.5",
                ],
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                delays=(0.1, 0.5),
                description="Client API / script",
                tls_fingerprint="",
                tags=["api", "automation"]
            ),
        ]
        for profile in defaults:
            profile.score = profile.evaluate()
            self.profiles[profile.name] = profile

    def _load_custom(self):
        if os.path.exists(PROFILES_FILE):
            try:
                with open(PROFILES_FILE, 'r') as f:
                    data = json.load(f)
                for pdata in data:
                    profile = StealthProfile(**pdata)
                    profile.score = profile.evaluate()
                    self.profiles[profile.name] = profile
            except Exception:
                pass

    def _save_custom(self):
        custom = [p.__dict__ for p in self.profiles.values() if "custom" in p.tags or p.name not in ["mobile_user", "corporate_vpn", "googlebot", "api_client"]]
        if custom:
            with open(PROFILES_FILE, 'w') as f:
                json.dump(custom, f, indent=2)

    def get_headers(self, service: str = "generic") -> Dict[str, str]:
        profile = self.profiles.get(self.active_profile, self.profiles["mobile_user"])
        headers = profile.headers.copy()
        headers["User-Agent"] = random.choice(profile.user_agents)
        if service in ("github", "gitlab", "slack", "discord"):
            headers["Accept"] = "application/json"
        return headers

    def get_delay(self) -> float:
        profile = self.profiles.get(self.active_profile, self.profiles["mobile_user"])
        return random.uniform(*profile.delays)

    def set_proxy(self, proxy_url: str):
        self._proxy = proxy_url

    def get_proxy(self) -> Optional[str]:
        return self._proxy

    def get_profile_for_target(self, target: str) -> str:
        if target in self._per_target_profiles:
            return self._per_target_profiles[target]
        profile = self._select_profile_for_target(target)
        self._per_target_profiles[target] = profile
        return profile

    def _select_profile_for_target(self, target: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        if any(kw in path.lower() for kw in ["admin", "dashboard", "login", "manage", "portal"]):
            return "corporate_vpn"
        if "/api/" in path or hostname.startswith("api."):
            return "api_client"
        return "mobile_user"

    def should_rotate(self) -> bool:
        now = time.time()
        if self._request_count >= self._max_requests_per_profile:
            return True
        if now - self._profile_start_time >= self._max_profile_duration:
            return True
        if self._errors >= 3:
            return True
        return False

    def rotate_profile(self, strategy: str = "smart"):
        if strategy == "smart":
            if not self.should_rotate():
                return
        self._request_count = 0
        self._errors = 0
        self._profile_start_time = time.time()
        available = [n for n in self.profiles if n != self.active_profile]
        if not available:
            available = list(self.profiles.keys())
        if strategy == "random":
            self.active_profile = random.choice(available)
        elif strategy == "highest_score":
            self.active_profile = max(available, key=lambda n: self.profiles[n].score)
        elif strategy == "lowest_score":
            self.active_profile = min(available, key=lambda n: self.profiles[n].score)
        else:
            good = [n for n in available if self.profiles[n].score >= 0.7]
            self.active_profile = random.choice(good) if good else random.choice(available)

    def record_request(self, success: bool = True):
        self._request_count += 1
        if not success:
            self._errors += 1


    def load_proxies(self, filepath: str = "proxies.txt"):
        """Charge une liste de proxies depuis un fichier (un proxy par ligne)."""
        import os
        if not os.path.exists(filepath):
            return
        with open(filepath, "r") as f:
            proxies = [line.strip() for line in f if line.strip()]
        if proxies:
            self.proxy_bandit = ProxyBandit(proxies)
            logger.info(f"{len(proxies)} proxies chargés depuis {filepath}")


    def record_proxy_success(self, proxy: str):
        """Enregistre un succès pour le proxy utilisé."""
        if self.proxy_bandit:
            self.proxy_bandit.record_success(proxy)

    def record_proxy_failure(self, proxy: str):
        """Enregistre un échec pour le proxy utilisé."""
        if self.proxy_bandit:
            self.proxy_bandit.record_failure(proxy)

    def list_profiles(self) -> str:
        lines = []
        for name, profile in self.profiles.items():
            active = " *" if name == self.active_profile else ""
            lines.append(f"{name} (score: {profile.score}){active}")
            lines.append(f"  UA: {len(profile.user_agents)} variants, delay: {profile.delays}")
            lines.append(f"  Tags: {', '.join(profile.tags)}")
        return "\n".join(lines)

    def use_profile(self, name: str) -> bool:
        if name in self.profiles:
            self.active_profile = name
            return True
        return False

    def create_profile(self, name: str, config: dict) -> bool:
        if name in self.profiles:
            return False
        profile = StealthProfile(
            name=name,
            user_agents=config.get("user_agents", ["Mozilla/5.0"]),
            headers=config.get("headers", {}),
            delays=tuple(config.get("delays", [0.5, 2.0])),
            description=config.get("description", ""),
            tags=config.get("tags", ["custom"])
        )
        profile.score = profile.evaluate()
        self.profiles[name] = profile
        self._save_custom()
        return True

    def delete_profile(self, name: str) -> bool:
        if name in self.profiles and name not in ["mobile_user", "corporate_vpn", "googlebot", "api_client"]:
            del self.profiles[name]
            self._save_custom()
            if self.active_profile == name:
                self.active_profile = "mobile_user"
            return True
        return False

    def get_client(self, service: str = "generic"):
        """Retourne un client HTTP configuré avec le transport TLS approprié."""
        import httpx
        profile = self.profiles.get(self.active_profile, self.profiles["mobile_user"])
        headers = self.get_headers(service)
        transport = self._get_transport(profile)
        proxy = self._proxy
        if self.proxy_bandit:
            best = self.proxy_bandit.select()
            if best:
                proxy = best
        return httpx.AsyncClient(transport=transport, headers=headers, timeout=15.0, proxy=proxy)

    def _get_transport(self, profile):
        """Sélectionne le meilleur backend TLS disponible."""
        fingerprint = profile.tls_fingerprint
        if not fingerprint:
            return None
        # Fallback Android si tls_client non disponible
        if not TLS_CLIENT_AVAILABLE and not CURL_CFFI_AVAILABLE:
            import sys
            if hasattr(sys, 'getandroidapilevel'):
                # On est sur Android, utiliser le fallback requests
                session = create_android_client(self.get_headers("android"))
                # Wrapper pour le rendre compatible httpx (simplifié)
                return AndroidRequestsTransport(session)
        if TLS_CLIENT_AVAILABLE:
            return TlsClientTransport(fingerprint)
        if CURL_CFFI_AVAILABLE:
            return CurlCFFITransport(fingerprint)
        return None

    def tls_status(self) -> str:
        """Retourne l'état des backends TLS."""
        status = TLSHealthCheck.get_backend_status()
        lines = []
        for backend, info in status.items():
            avail = "✅" if info["available"] else "❌"
            version = info.get("version", "N/A")
            lines.append(f"{avail} {backend}: {version}")
        return "\n".join(lines)

    async def health_check(self) -> str:
        """Vérifie la santé du backend TLS actif et retourne un rapport."""
        profile = self.profiles.get(self.active_profile)
        if not profile or not profile.tls_fingerprint:
            return "Aucun fingerprint TLS configuré pour le profil actif."

        backend = None
        if TLS_CLIENT_AVAILABLE:
            backend = "tls_client"
        elif CURL_CFFI_AVAILABLE:
            backend = "curl_cffi"
        else:
            return "Aucun backend TLS disponible (tls_client ou curl_cffi)."

        # Validation JA3 (avec cache pour éviter les requêtes répétées)
        cache_key = f"{backend}_{profile.tls_fingerprint}"
        if cache_key in self._health_cache:
            return self._health_cache[cache_key]

        from bxp_secretsonar.utils.tls import TLSHealthCheck
        valid = await TLSHealthCheck.validate_ja3(backend, profile.tls_fingerprint)
        if valid:
            msg = f"✅ Backend {backend} génère le bon JA3 pour {profile.tls_fingerprint}"
        else:
            msg = f"❌ Backend {backend} NE génère PAS le bon JA3 pour {profile.tls_fingerprint}. Vérifiez l'installation."

        self._health_cache[cache_key] = msg
        return msg

    def migrate_session(self, old_client, new_client):
        """Transfère les cookies et headers de session d'un client à l'autre."""
        if not old_client or not new_client:
            return
        # Transférer les cookies
        if hasattr(old_client, 'cookies'):
            for cookie in old_client.cookies.jar:
                new_client.cookies.set(cookie.name, cookie.value, domain=cookie.domain, path=cookie.path)
        # Transférer les headers persistants (ex: Authorization, User-Agent)
        for header in ["Authorization", "X-API-Key"]:
            if header in old_client.headers:
                new_client.headers[header] = old_client.headers[header]

    def rotate_profile(self, strategy: str = "smart"):
        old_profile = self.active_profile
        old_client = getattr(self, '_current_client', None)
        # ... (logique de rotation existante)
        # Après avoir changé de profil, recréer le client et migrer la session
        if old_client:
            new_client = self.get_client("generic")
            self.migrate_session(old_client, new_client)
            self._current_client = new_client
        else:
            self._current_client = self.get_client("generic")

    def load_config(self, config_path: str = "stealth_config.yaml"):
        """Charge la configuration YAML et applique les paramètres."""
        import yaml
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            # Appliquer les paramètres
            self._max_requests_per_profile = config.get('rotation', {}).get('max_requests_per_profile', 50)
            self._max_profile_duration = config.get('rotation', {}).get('max_profile_duration', 1800)
            self.preserve_session = config.get('session', {}).get('preserve_on_rotate', True)
            # Appliquer le backend TLS préféré
            preferred = config.get('tls', {}).get('preferred_backend', 'auto')
            if preferred != "auto":
                # Forcer l'utilisation d'un backend spécifique (à implémenter si nécessaire)
                pass
        except FileNotFoundError:
            pass  # pas de fichier de config, on garde les valeurs par défaut

    async def ab_test(self, test_url: str = "https://httpbin.org/headers") -> str:
        """Teste tous les backends disponibles et retourne le meilleur."""
        import asyncio
        candidates = []
        if TLS_CLIENT_AVAILABLE:
            candidates.append("tls_client")
        if CURL_CFFI_AVAILABLE:
            candidates.append("curl_cffi")
        candidates.append("httpx")  # fallback toujours présent

        scores = {}
        for backend in candidates:
            try:
                client = self._create_backend_client(backend)
                resp = await client.get(test_url, timeout=10.0)
                if resp.status_code == 200:
                    # Vérifier le JA3 généré (si possible)
                    ja3_ok = True
                    if backend != "httpx":
                        from bxp_secretsonar.utils.tls import TLSHealthCheck
                        ja3_ok = await TLSHealthCheck.validate_ja3(backend, self.profiles[self.active_profile].tls_fingerprint)
                    scores[backend] = 1.0 if ja3_ok else 0.5
                else:
                    scores[backend] = 0.0
                await client.aclose()
            except Exception:
                scores[backend] = 0.0

        best = max(scores, key=scores.get)
        self._preferred_backend = best
        return f"Meilleur backend : {best} (scores: {scores})"

    def _create_backend_client(self, backend: str):
        """Crée un client HTTP spécifique à un backend (pour A/B testing)."""
        import httpx
        profile = self.profiles.get(self.active_profile, self.profiles["mobile_user"])
        fingerprint = profile.tls_fingerprint
        if backend == "tls_client":
            from bxp_secretsonar.utils.tls import TlsClientTransport
            transport = TlsClientTransport(fingerprint) if fingerprint else None
        elif backend == "curl_cffi":
            from bxp_secretsonar.utils.tls import CurlCFFITransport
            transport = CurlCFFITransport(fingerprint) if fingerprint else None
        else:
            transport = None
        return httpx.AsyncClient(transport=transport, headers=self.get_headers("ab_test"), timeout=10.0)

class AndroidRequestsTransport:
    """Transport httpx-like pour le fallback Android."""
    def __init__(self, session):
        self.session = session
    async def get(self, url, **kwargs):
        import asyncio
        return await asyncio.to_thread(self.session.get, url, **kwargs)
    async def post(self, url, **kwargs):
        import asyncio
        return await asyncio.to_thread(self.session.post, url, **kwargs)
    async def aclose(self):
        self.session.close()
