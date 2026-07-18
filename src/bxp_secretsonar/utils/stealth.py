import random, time, json, os
from typing import Dict, List, Optional
from dataclasses import dataclass, field

PROFILES_FILE = "stealth_profiles.json"

@dataclass
class StealthProfile:
    name: str
    user_agents: List[str]
    headers: Dict[str, str]
    delays: tuple[float, float]  # min, max en secondes
    description: str = ""
    score: float = 0.0  # calculé automatiquement
    tags: List[str] = field(default_factory=list)

    def evaluate(self) -> float:
        """Calcule un score de crédibilité basé sur la cohérence et la diversité du profil."""
        score = 0.5  # score de base
        # Récompenser la diversité des User-Agents
        if len(self.user_agents) >= 3:
            score += 0.15
        # Récompenser les headers modernes (Sec-Fetch-*, etc.)
        modern_headers = ["sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-ch-ua"]
        if any(h in {k.lower() for k in self.headers} for h in modern_headers):
            score += 0.15
        # Récompenser des délais réalistes (pas trop rapides)
        if self.delays[0] >= 0.5:
            score += 0.1
        # Récompenser la présence de tags spécifiques
        if "enterprise" in self.tags:
            score += 0.1
        return round(min(1.0, score), 2)


class StealthManager:
    def __init__(self):
        self.profiles: Dict[str, StealthProfile] = {}
        self.active_profile: str = "mobile_user"
        self._usage_stats: Dict[str, int] = {}
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
                description="Robot d'indexation Google (attention : IP vérifiée par les défenses)",
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
                description="Client API / script (déconseillé pour la furtivité)",
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

    # ---------- API pour les modules ----------
    def get_headers(self, service: str = "generic") -> Dict[str, str]:
        """Retourne les headers HTTP du profil actif, éventuellement adaptés au service."""
        profile = self.profiles.get(self.active_profile, self.profiles["mobile_user"])
        headers = profile.headers.copy()
        headers["User-Agent"] = random.choice(profile.user_agents)
        # Adapter au service si nécessaire
        if service in ("github", "gitlab", "slack", "discord"):
            headers["Accept"] = "application/json"
        return headers

    def get_delay(self) -> float:
        """Retourne un délai aléatoire basé sur le profil actif."""
        profile = self.profiles.get(self.active_profile, self.profiles["mobile_user"])
        return random.uniform(*profile.delays)

    def rotate_profile(self, strategy: str = "random"):
        """Change de profil actif selon une stratégie."""
        available = list(self.profiles.keys())
        if strategy == "random":
            self.active_profile = random.choice(available)
        elif strategy == "highest_score":
            self.active_profile = max(available, key=lambda n: self.profiles[n].score)
        elif strategy == "lowest_score":
            self.active_profile = min(available, key=lambda n: self.profiles[n].score)

    # ---------- Commandes opérateur ----------
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
