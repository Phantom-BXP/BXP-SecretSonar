import os, httpx
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class SecurityTrailsProvider(DiscoveryProvider):
    name = "securitytrails"
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("SECURITYTRAILS_API_KEY")
        if not self.api_key:
            raise ValueError("Clé API SecurityTrails manquante. Définissez SECURITYTRAILS_API_KEY.")

    async def discover(self, query: str, limit: int = 20) -> List[str]:
        url = f"https://api.securitytrails.com/v1/domain/{query}/subdomains"
        headers = {"APIKEY": self.api_key}
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await self._retry_request(client.get, url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        subdomains = data.get("subdomains", [])
        urls = []
        for sub in subdomains[:limit]:
            domain = f"{sub}.{query}"
            urls.append(f"https://{domain}")
            urls.append(f"http://{domain}")
        return urls[:limit]
