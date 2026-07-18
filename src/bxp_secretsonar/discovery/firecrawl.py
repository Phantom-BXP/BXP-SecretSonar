import os
import httpx
from typing import List
from urllib.parse import urlparse, urljoin
from bxp_secretsonar.discovery.base import DiscoveryProvider

class FirecrawlProvider(DiscoveryProvider):
    name = "firecrawl"

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("FIRECRAWL_API_KEY")
        if not self.api_key:
            raise ValueError("Clé API Firecrawl manquante. Définissez FIRECRAWL_API_KEY ou passez-la au constructeur.")

    async def discover(self, query: str, limit: int = 10) -> List[str]:
        """
        Crawle un site web via Firecrawl.
        :param query: URL de base du site (ex: https://example.com)
        :param limit: nombre max d'URLs à retourner
        """
        url = "https://api.firecrawl.dev/v1/crawl"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "url": query,
            "limit": limit,
            "maxDepth": 2,  # ne pas trop profond pour rester rapide
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()

        urls = []
        for page in data.get("data", []):
            page_url = page.get("url")
            if page_url:
                urls.append(page_url)
        return urls[:limit]
