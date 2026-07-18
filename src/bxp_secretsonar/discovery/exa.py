import os
import httpx
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class ExaProvider(DiscoveryProvider):
    name = "exa"

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("EXA_API_KEY")
        if not self.api_key:
            raise ValueError("Clé API Exa manquante. Définissez EXA_API_KEY ou passez-la au constructeur.")

    async def discover(self, query: str, limit: int = 10) -> List[str]:
        url = "https://api.exa.ai/search"
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json"
        }
        payload = {
            "query": query,
            "numResults": limit,
            "useAutoprompt": True,
            "type": "keyword"
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
        results = []
        for item in data.get("results", []):
            results.append(item.get("url"))
        return results[:limit]
