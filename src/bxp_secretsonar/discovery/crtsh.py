import httpx
import re
from typing import List
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from bxp_secretsonar.discovery.base import DiscoveryProvider

class CrtShProvider(DiscoveryProvider):
    name = "crtsh"

    @retry(
        retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.ReadTimeout, httpx.ConnectError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    async def _fetch_json(self, url: str, client: httpx.AsyncClient):
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()

    async def discover(self, query: str, limit: int = 20) -> List[str]:
        url = f"https://crt.sh/?q=%25.{query}&output=json"
        async with httpx.AsyncClient(timeout=30.0) as client:
            data = await self._fetch_json(url, client)

        domains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for d in name.split("\n"):
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
