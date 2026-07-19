"""
Orchestrateur OPSEC avancé : SessionGhost, ChronoModel, ContextualWeaver.
Remplace les leurres de navigation et les délais de Poisson.
"""
import asyncio
import random
import time
import logging
from typing import Optional, Callable, List, Dict
from enum import Enum

import httpx
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ---------- ChronoModel ----------
class ChronoModel:
    """Générateur de délais à trois échelles (micro, meso, context switch)."""
    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        micro = cfg.get("micro", {})
        components = micro.get("components", [])
        self.micro_components = [(c["weight"], c["mu"], c["sigma"]) for c in components]
        if not self.micro_components:
            self.micro_components = [(0.8, -0.7, 0.8), (0.2, 1.4, 0.4)]

        meso = cfg.get("meso", {})
        self.meso_mu = meso.get("mu", 2.5)
        self.meso_sigma = meso.get("sigma", 1.2)

        ctx = cfg.get("context_switch", {})
        self.ctx_min = ctx.get("min", 2.0)
        self.ctx_max = ctx.get("max", 8.0)
        self.ctx_dist = ctx.get("distribution", "uniform")

        fallback = cfg.get("fallback", {})
        self.fb_min = fallback.get("min_delay", 1.0)
        self.fb_max = fallback.get("max_delay", 5.0)

    def micro_delay(self) -> float:
        """Délai entre deux requêtes individuelles (mélange log-normal)."""
        r = random.random()
        cumulative = 0.0
        for weight, mu, sigma in self.micro_components:
            cumulative += weight
            if r <= cumulative:
                return max(0.1, random.lognormvariate(mu, sigma))
        return max(0.1, random.lognormvariate(-0.7, 0.8))

    def meso_delay(self) -> float:
        """Temps de dwell sur une page (log-normal)."""
        return max(5.0, random.lognormvariate(self.meso_mu, self.meso_sigma))

    def context_switch_delay(self) -> float:
        """Délai de transition entre bruit et offensif."""
        if self.ctx_dist == "lognormal":
            return max(2.0, random.lognormvariate(1.5, 0.8))
        return random.uniform(self.ctx_min, self.ctx_max)

    def uniform_delay(self) -> float:
        """Fallback uniforme si le modèle est désactivé."""
        return random.uniform(self.fb_min, self.fb_max)


# ---------- SessionGhost ----------
class Action(Enum):
    LANDING = "landing"
    CLICK = "click"
    OFFENSIVE = "offensive"
    PAUSE = "pause"

class SessionGhost:
    """Session de navigation persistante avec état et cohérence."""
    def __init__(self, persona: dict, chrono: ChronoModel, stealth_mgr=None):
        self.persona = persona
        self.chrono = chrono
        self.stealth_mgr = stealth_mgr
        self.session = requests.Session()
        self.current_url: Optional[str] = None
        self.last_referer: Optional[str] = None
        self.history: List[str] = []
        self.cookies_jar = self.session.cookies
        self.stealth_mgr = stealth_mgr

        # Config persona
        self.interests = persona.get("interests", ["wikipedia.org"])
        self.dwell_time_mu = persona.get("dwell_time_mu", 2.5)
        self.dwell_time_sigma = persona.get("dwell_time_sigma", 1.2)
        self.click_prob = persona.get("click_probability", 0.3)
        self.max_depth = persona.get("max_depth", 2)

        # État interne
        self.state = "IDLE"
        self.depth = 0
        self.page_text = ""

    def _get_headers(self):
        """Utilise les headers du profil furtif."""
        if self.stealth_mgr:
            return self.stealth_mgr.get_headers("browser")
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def landing(self) -> float:
        """Visite une nouvelle page d'un site leurre."""
        self.depth = 0
        site = random.choice(self.interests)
        self.current_url = f"https://{site}" if not site.startswith("http") else site
        try:
            resp = self.session.get(self.current_url, headers=self._get_headers(), timeout=10.0)
            self.last_referer = self.current_url
            self.history.append(self.current_url)
            self.page_text = resp.text
            self.state = "READING"
            # Temps de lecture basé sur la longueur de la page
            words = len(self.page_text.split()) / 5  # approx
            base_time = (words / 200) * 60  # 200 mots/min
            dwell = max(5.0, random.lognormvariate(self.dwell_time_mu, self.dwell_time_sigma))
            return min(dwell, base_time)
        except Exception as e:
            logger.debug(f"SessionGhost landing error: {e}")
            return 5.0

    def click_internal(self) -> Optional[float]:
        """Simule un clic sur un lien interne."""
        if not self.page_text or self.depth >= self.max_depth:
            return None

        soup = BeautifulSoup(self.page_text, "html.parser")
        links = [a.get("href") for a in soup.find_all("a", href=True)]
        internal_links = [l for l in links if l.startswith("/") or self.current_url in l]
        if not internal_links:
            return None

        # Choisir un lien et le visiter
        chosen = random.choice(internal_links)
        if chosen.startswith("/"):
            chosen = self.current_url.rstrip("/") + chosen

        try:
            headers = self._get_headers()
            headers["Referer"] = self.current_url
            resp = self.session.get(chosen, headers=headers, timeout=10.0)
            self.last_referer = self.current_url
            self.current_url = chosen
            self.history.append(chosen)
            self.page_text = resp.text
            self.depth += 1
            self.state = "READING"
            return max(3.0, random.lognormvariate(self.dwell_time_mu * 0.7, self.dwell_time_sigma))
        except Exception as e:
            logger.debug(f"SessionGhost click error: {e}")
            return None

    def inject_offensive(self, request_fn: Callable):
        """Exécute une requête offensive avec les mêmes headers de session."""
        headers = self._get_headers()
        headers["Referer"] = self.last_referer or self.current_url or ""
        # La fonction offensive utilisera ces headers pour sa requête
        return request_fn(headers)

    def get_next_action(self) -> Action:
        """Choisit la prochaine action selon l'état de la session."""
        if self.state == "IDLE":
            return Action.LANDING
        if self.state == "READING" and random.random() < self.click_prob:
            return Action.CLICK
        return Action.PAUSE


# ---------- ContextualWeaver ----------
class ContextualWeaver:
    """Orchestre l'alternance entre bruit de navigation et requêtes offensives."""
    def __init__(self, ghost: SessionGhost, chrono: ChronoModel, config: dict = None):
        self.ghost = ghost
        self.chrono = chrono
        self.noise_ratio = config.get("noise_ratio", 0.4) if config else 0.4
        self.max_consecutive_offensive = config.get("max_consecutive_offensive", 1) if config else 1
        self.offensive_count = 0
        self.total_requests = 0

    async def execute(self, offensive_task: Callable):
        """Exécute une tâche offensive intercalée dans le bruit."""
        # Décider si on fait du bruit avant
        if self.total_requests == 0 or random.random() < self.noise_ratio:
            # Phase de bruit
            action = self.ghost.get_next_action()
            if action == Action.LANDING:
                dwell = self.ghost.landing()
                logger.debug(f"SessionGhost landing: {self.ghost.current_url} (dwell={dwell:.1f}s)")
                await asyncio.sleep(dwell)
            elif action == Action.CLICK:
                dwell = self.ghost.click_internal()
                if dwell:
                    logger.debug(f"SessionGhost click: {self.ghost.current_url} (dwell={dwell:.1f}s)")
                    await asyncio.sleep(dwell)
            elif action == Action.PAUSE:
                pause = self.chrono.meso_delay()
                await asyncio.sleep(pause)

        # Vérifier le nombre maximal de requêtes offensives consécutives
        if self.offensive_count >= self.max_consecutive_offensive:
            # Forcer une pause/bruit
            dwell = self.ghost.landing() if random.random() < 0.5 else self.chrono.meso_delay()
            await asyncio.sleep(dwell)
            self.offensive_count = 0

        # Exécution de la tâche offensive avec les headers de la session
        def offensive_with_headers():
            return offensive_task()

        # Pas de await ici, c'est l'appelant qui gère le asynchrone
        result = await offensive_task()
        self.offensive_count += 1
        self.total_requests += 1

        # Délai de transition après l'offensif
        switch_delay = self.chrono.context_switch_delay()
        await asyncio.sleep(switch_delay)

        return result
