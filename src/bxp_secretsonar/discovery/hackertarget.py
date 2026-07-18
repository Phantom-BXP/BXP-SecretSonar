import httpx
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class HackerTargetProvider(DiscoveryProvider):
    name = "hackertarget"

    async def discover(self, query: str, limit: int = 20) -> List[str]:
        # Combine reverse DNS et forward DNS lookup
        urls = set()
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Reverse DNS lookup
            try:
                resp = await self._retry_request(client.get, f"https://api.hackertarget.com/reverseiplookup/?q={query}")
                resp.raise_for_status()
                # Le résultat est un texte brut, chaque ligne = un domaine
                for line in resp.text.splitlines():
                    domain = line.strip()
                    if domain:
                        urls.add(f"https://{domain}")
                        urls.add(f"http://{domain}")
            except Exception:
                pass  # pas grave si échoue
            # Host search (sous-domaines)
            try:
                resp = await self._retry_request(client.get, f"https://api.hackertarget.com/hostsearch/?q={query}")
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    parts = line.split(",")
                    if parts:
                        domain = parts[0].strip()
                        if domain:
                            urls.add(f"https://{domain}")
                            urls.add(f"http://{domain}")
            except Exception:
                pass
        return list(urls)[:limit]
