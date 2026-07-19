import random, time, json, os
from bxp_secretsonar.utils.tls import TLS_CLIENT_AVAILABLE, CURL_CFFI_AVAILABLE, TLSHealthCheck, TlsClientTransport, CurlCFFITransport
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
        return httpx.AsyncClient(transport=transport, headers=headers, timeout=15.0, proxy=self._proxy)

    def _get_transport(self, profile):
        """Sélectionne le meilleur backend TLS disponible."""
        fingerprint = profile.tls_fingerprint
        if not fingerprint:
            return None
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
