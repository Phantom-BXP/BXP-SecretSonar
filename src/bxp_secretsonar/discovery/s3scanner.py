import os, asyncio
from typing import List
import httpx
from bxp_secretsonar.discovery.base import DiscoveryProvider

# Liste de noms de buckets courants (peut être enrichie)
COMMON_BUCKET_NAMES = [
    "admin", "backup", "config", "data", "logs", "media", "private",
    "prod", "public", "secret", "secure", "test", "tmp", "uploads",
    "www", "web", "app", "api", "assets", "files", "storage"
]

class S3ScannerProvider(DiscoveryProvider):
    name = "s3scanner"
    async def discover(self, query: str = "", limit: int = 10) -> List[str]:
        # query ignoré, on brute-force les noms de buckets
        async def check_bucket(name):
            url = f"https://{name}.s3.amazonaws.com"
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.head(url)
                    # Si on obtient une réponse (pas 404), le bucket existe probablement
                    if resp.status_code != 404:
                        return url
            except Exception:
                pass
            return None

        tasks = [check_bucket(name) for name in COMMON_BUCKET_NAMES]
        results = await asyncio.gather(*tasks)
        found = [r for r in results if r]
        return found[:limit]
