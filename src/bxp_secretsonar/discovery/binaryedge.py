import os, httpx
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class BinaryEdgeProvider(DiscoveryProvider):
    name = "binaryedge"
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("BINARYEDGE_API_KEY")
        if not self.api_key:
            raise ValueError("Clé API BinaryEdge manquante. Définissez BINARYEDGE_API_KEY.")

    async def discover(self, query: str, limit: int = 10) -> List[str]:
        url = "https://api.binaryedge.io/v2/query/search"
        headers = {"X-Key": self.api_key}
        params = {"query": query, "pagesize": limit}
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await self._retry_request(client.get, url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
        urls = []
        for event in data.get("events", []):
            ip = event.get("target", {}).get("ip")
            port = event.get("target", {}).get("port")
            if ip:
                scheme = "https" if port == 443 else "http"
                urls.append(f"{scheme}://{ip}:{port}" if port else f"http://{ip}")
        return urls[:limit]
