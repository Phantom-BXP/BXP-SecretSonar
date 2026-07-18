import os, httpx
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class CensysProvider(DiscoveryProvider):
    name = "censys"
    def __init__(self, api_id=None, api_secret=None):
        self.api_id = api_id or os.environ.get("CENSYS_API_ID")
        self.api_secret = api_secret or os.environ.get("CENSYS_API_SECRET")
        if not self.api_id or not self.api_secret:
            raise ValueError("Credentials Censys manquantes. Définissez CENSYS_API_ID et CENSYS_API_SECRET.")
        self.auth = (self.api_id, self.api_secret)

    async def discover(self, query: str, limit: int = 10) -> List[str]:
        url = "https://search.censys.io/api/v2/hosts/search"
        payload = {
            "q": query,
            "per_page": limit
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await self._retry_request(client.post, url, json=payload, auth=self.auth)
            resp.raise_for_status()
            data = resp.json()
        urls = []
        for hit in data.get("result", {}).get("hits", []):
            ip = hit.get("ip")
            if ip:
                urls.append(f"https://{ip}")
                urls.append(f"http://{ip}")
        return urls[:limit]
