import httpx
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class URLScanProvider(DiscoveryProvider):
    name = "urlscan"

    async def discover(self, query: str, limit: int = 20) -> List[str]:
        # Recherche de scans pour un domaine
        url = f"https://urlscan.io/api/v1/search/?q=domain:{query}&size={limit}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await self._retry_request(client.get, url)
            resp.raise_for_status()
            data = resp.json()
        urls = []
        for result in data.get("results", []):
            page_url = result.get("page", {}).get("url")
            if page_url:
                urls.append(page_url)
        return urls[:limit]
