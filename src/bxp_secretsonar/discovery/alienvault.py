import httpx
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class AlienVaultProvider(DiscoveryProvider):
    name = "alienvault"

    async def discover(self, query: str, limit: int = 20) -> List[str]:
        # Endpoint passif DNS (subdomains)
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{query}/passive_dns"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await self._retry_request(client.get, url)
            resp.raise_for_status()
            data = resp.json()
        domains = set()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "").strip().lower()
            if hostname and hostname != query and not hostname.startswith("*"):
                domains.add(hostname)
        urls = []
        for domain in list(domains)[:limit]:
            urls.append(f"https://{domain}")
            urls.append(f"http://{domain}")
        return urls[:limit]
