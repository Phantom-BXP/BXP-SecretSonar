"""
Sélection de proxy par Thompson Sampling (Beta distribution).
Chaque proxy a un score de succès/échecs modélisé par une distribution Beta.
"""
import random
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

class ProxyBandit:
    """Gère un pool de proxies avec sélection par Thompson Sampling."""
    def __init__(self, proxies: List[str]):
        self.proxies = {p: {"successes": 1, "failures": 1} for p in proxies}  # prior Beta(1,1)
        self.quarantined = set()

    def select(self) -> Optional[str]:
        """Sélectionne le meilleur proxy selon Thompson Sampling."""
        available = [p for p in self.proxies if p not in self.quarantined]
        if not available:
            return None

        # Tirage aléatoire selon la distribution Beta de chaque proxy
        samples = {p: random.betavariate(self.proxies[p]["successes"], self.proxies[p]["failures"])
                   for p in available}
        best = max(samples, key=samples.get)
        logger.debug(f"Proxy sélectionné : {best} (score={samples[best]:.2f})")
        return best

    def record_success(self, proxy: str):
        """Enregistre un succès pour un proxy."""
        if proxy in self.proxies:
            self.proxies[proxy]["successes"] += 1
            # Sortir de quarantaine si assez de succès
            if proxy in self.quarantined and self.proxies[proxy]["successes"] >= 3:
                self.quarantined.discard(proxy)

    def record_failure(self, proxy: str):
        """Enregistre un échec pour un proxy. Quarantaine si trop d'échecs."""
        if proxy in self.proxies:
            self.proxies[proxy]["failures"] += 1
            # Quarantaine si le ratio échecs/succès est trop élevé
            if self.proxies[proxy]["failures"] / self.proxies[proxy]["successes"] > 3:
                self.quarantined.add(proxy)
                logger.warning(f"Proxy {proxy} mis en quarantaine")

    def add_proxy(self, proxy: str):
        """Ajoute un proxy au pool."""
        if proxy not in self.proxies:
            self.proxies[proxy] = {"successes": 1, "failures": 1}
            logger.info(f"Proxy ajouté : {proxy}")

    def remove_proxy(self, proxy: str):
        """Supprime définitivement un proxy du pool."""
        self.proxies.pop(proxy, None)
        self.quarantined.discard(proxy)
        logger.info(f"Proxy supprimé : {proxy}")
