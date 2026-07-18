import httpx
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class WaybackProvider(DiscoveryProvider):
    name = "wayback"

    async def discover(self, query: str, limit: int = 20) -> List[str]:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{query}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await self._retry_request(client.get, url)
            resp.raise_for_status()
            data = resp.json()
        urls = []
        for row in data[1:]:
            if row:
                urls.append(row[0])
        return urls[:limit]
