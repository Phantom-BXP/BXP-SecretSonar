import httpx
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class GitHubSearchProvider(DiscoveryProvider):
    name = "github"
    async def discover(self, query: str, limit: int = 10) -> List[str]:
        url = f"https://api.github.com/search/code?q={query}&per_page={limit}"
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await self._retry_request(client.get, url)
            resp.raise_for_status()
            data = resp.json()
        urls = []
        for item in data.get("items", []):
            html_url = item.get("html_url", "")
            if html_url:
                urls.append(html_url)
        return urls[:limit]
