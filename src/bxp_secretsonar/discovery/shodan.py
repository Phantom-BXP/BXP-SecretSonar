import os
import httpx
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class ShodanProvider(DiscoveryProvider):
    name = "shodan"

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY")
        if not self.api_key:
            raise ValueError("Clé API Shodan manquante. Définissez SHODAN_API_KEY ou passez-la au constructeur.")

    async def discover(self, query: str, limit: int = 10) -> List[str]:
        url = "https://api.shodan.io/shodan/host/search"
        params = {
            "key": self.api_key,
            "query": query,
            "limit": limit
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            results = []
            for match in data.get("matches", []):
                ip = match.get("ip_str")
                port = match.get("port")
                if ip and port:
                    # On reconstruit une URL avec le port et le proto par défaut http
                    scheme = "https" if port == 443 else "http"
                    results.append(f"{scheme}://{ip}:{port}")
                elif ip:
                    results.append(f"http://{ip}")
            return results[:limit]
