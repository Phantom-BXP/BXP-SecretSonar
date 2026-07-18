import asyncio
from typing import Optional
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from bxp_secretsonar.core.models import Artifact, ArtifactType

class HttpCollector:
    def __init__(self, ssl_verify=True, max_concurrency=10):
        self.ssl_verify = ssl_verify
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.client = None

    async def start(self):
        self.client = httpx.AsyncClient(verify=self.ssl_verify, follow_redirects=True, timeout=httpx.Timeout(30.0), headers={"User-Agent": "BXP-SecretSonar/0.2.0a1"})

    async def close(self):
        if self.client:
            await self.client.aclose()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10), retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)), reraise=True)
    async def collect(self, url):
        if not self.client:
            raise RuntimeError("HttpCollector not started")
        async with self.semaphore:
            resp = await self.client.get(url)
            resp.raise_for_status()
        return Artifact(source_url=str(resp.url), content=resp.text, artifact_type=ArtifactType.HTTP_RESPONSE, metadata={"status_code": resp.status_code, "content_length": len(resp.content)})
