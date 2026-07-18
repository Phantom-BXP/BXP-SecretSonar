import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from bxp_secretsonar.core.models import Artifact, ArtifactType

class HttpCollector:
    def __init__(self, ssl_verify: bool = True, max_concurrency: int = 10, proxy: str = None):
        self.ssl_verify = ssl_verify
        self.max_concurrency = max_concurrency
        self.proxy = proxy
        self.client = None
        self.semaphore = httpx.Semaphore(max_concurrency)

    async def start(self):
        self.client = httpx.AsyncClient(verify=self.ssl_verify, proxy=self.proxy, follow_redirects=False)

    async def close(self):
        if self.client:
            await self.client.aclose()
            self.client = None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10),
           retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)), reraise=True)
    async def collect(self, url):
        if not self.client:
            raise RuntimeError("HttpCollector not started")
        async with self.semaphore:
            resp = await self.client.get(url)
            resp.raise_for_status()
            if hasattr(self, 'stealth_mgr'):
                self.stealth_mgr.record_request(True)
            return Artifact(
                source_url=str(resp.url),
                content=resp.text,
                artifact_type=ArtifactType.HTTP_RESPONSE,
                metadata={"status_code": resp.status_code, "content_length": len(resp.content)}
            )
