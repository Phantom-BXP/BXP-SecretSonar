"""
Mécanismes de robustesse : Circuit Breaker, Retry intelligent, File de rattrapage.
"""
import asyncio
import time
import logging
from enum import Enum
from typing import Dict, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import httpx

logger = logging.getLogger(__name__)

# ---------- Circuit Breaker ----------
class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    """Protège un service distant contre les appels répétés en cas de défaillance."""
    def __init__(self, name: str, max_failures: int = 3, reset_timeout: float = 60.0,
                 half_open_max: int = 2):
        self.name = name
        self.max_failures = max_failures
        self.reset_timeout = reset_timeout
        self.half_open_max = half_open_max
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.half_open_successes = 0

    def record_failure(self, temporary: bool = True):
        """Enregistre un échec. Ouvre le circuit si le seuil est atteint."""
        if not temporary:
            # Erreur permanente → ouverture immédiate
            self.state = CircuitState.OPEN
            self.last_failure_time = time.time()
            logger.warning(f"Circuit {self.name} OPEN (erreur permanente)")
            return

        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.max_failures:
            self.state = CircuitState.OPEN
            logger.warning(f"Circuit {self.name} OPEN après {self.failure_count} échecs")

    def record_success(self):
        """Enregistre un succès. Referme le circuit si en half-open."""
        if self.state == CircuitState.HALF_OPEN:
            self.half_open_successes += 1
            if self.half_open_successes >= self.half_open_max:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.half_open_successes = 0
                logger.info(f"Circuit {self.name} CLOSED (recovery)")
        else:
            self.failure_count = 0  # succès en closed, on réinitialise le compteur

    def is_open(self) -> bool:
        """Retourne True si le circuit est ouvert (ou half-open en attente)."""
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time >= self.reset_timeout:
                self.state = CircuitState.HALF_OPEN
                self.half_open_successes = 0
                logger.info(f"Circuit {self.name} HALF_OPEN (testing)")
                return False  # autorise les requêtes test
            return True
        return False

# Registre global des circuits breakers
CIRCUIT_BREAKERS: Dict[str, CircuitBreaker] = {}

def get_circuit_breaker(service: str) -> CircuitBreaker:
    """Retourne le circuit breaker pour un service donné (crée si nécessaire)."""
    if service not in CIRCUIT_BREAKERS:
        CIRCUIT_BREAKERS[service] = CircuitBreaker(name=service)
    return CIRCUIT_BREAKERS[service]

# ---------- Retry intelligent ----------
def retry_with_backoff(service: str, max_attempts: int = 3):
    """Retourne un décorateur tenacity configuré pour le service."""
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError,
                                       httpx.HTTPStatusError)),
        before_sleep=lambda retry_state: logger.debug(
            f"Retry {service}: tentative {retry_state.attempt_number}"
        )
    )

# ---------- File de rattrapage ----------
class RetryQueue:
    """File de rattrapage pour les cibles momentanément inaccessibles."""
    def __init__(self, max_retries: int = 5, delay_seconds: float = 300.0):
        self.queue = asyncio.Queue()
        self.max_retries = max_retries
        self.delay = delay_seconds
        self._items = {}  # url -> (timestamp, retries)

    async def put(self, url: str):
        """Ajoute une URL à la file de rattrapage."""
        if url not in self._items:
            self._items[url] = (time.time(), 0)
            await self.queue.put(url)
            logger.debug(f"RetryQueue: ajouté {url}")

    async def get(self) -> Optional[str]:
        """Récupère une URL à réessayer (si le délai est écoulé et pas trop d'essais)."""
        while True:
            url = await self.queue.get()
            ts, retries = self._items.get(url, (0, 0))
            if retries >= self.max_retries:
                del self._items[url]
                logger.debug(f"RetryQueue: abandon {url} ({retries} retries)")
                continue
            if time.time() - ts < self.delay:
                # Remettre dans la file avec un petit délai
                await asyncio.sleep(self.delay - (time.time() - ts))
                self._items[url] = (ts, retries)  # pas d'incrémentation
                await self.queue.put(url)
                continue
            self._items[url] = (time.time(), retries + 1)
            return url
