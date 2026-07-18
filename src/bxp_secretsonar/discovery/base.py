from abc import ABC, abstractmethod
from typing import List, Callable
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

class DiscoveryProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def discover(self, query: str, limit: int = 10) -> List[str]:
        ...

    async def _retry_request(self, func: Callable, *args, max_attempts=3, **kwargs):
        """Exécute une fonction asynchrone avec retry automatique."""
        @retry(
            retry=retry_if_exception_type((httpx.ReadTimeout, httpx.ConnectError, httpx.HTTPStatusError)),
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential(multiplier=1, min=1, max=10)
        )
        async def _wrapper():
            return await func(*args, **kwargs)
        return await _wrapper()
