import httpx
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class CertSpotterProvider(DiscoveryProvider):
    name = "certspotter"
    async def discover(self, query: str, limit: int = 20) -> List[str]:
        url = f"https://api.certspotter.com/v1/issuances?domain={query}&include_subdomains=true&expand=dns_names"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await self._retry_request(client.get, url)
            resp.raise_for_status()
            data = resp.json()
        domains = set()
        for entry in data:
            for d in entry.get("dns_names", []):
                d = d.strip().lower()
                if d.startswith("*."):
                    d = d[2:]
                if d and not d.startswith("*"):
                    domains.add(d)
        urls = []
        for domain in list(domains)[:limit]:
            urls.append(f"https://{domain}")
            urls.append(f"http://{domain}")
        return urls[:limit]
