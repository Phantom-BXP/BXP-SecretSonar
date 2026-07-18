import asyncio, socket, time
from bxp_secretsonar.core.models import ProtocolProbeResult, ProtocolProbeStatus

class ProtocolProber:
    SUPPORTED_PROTOCOLS = {"ssh", "http", "https"}

    async def probe_ssh(self, host: str, port: int = 22, timeout: float = 3.0) -> ProtocolProbeResult:
        try:
            start = time.monotonic()
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
            elapsed = (time.monotonic() - start) * 1000
            if hasattr(writer, "close"): writer.close()
            await writer.wait_closed()
            return ProtocolProbeResult(protocol="ssh", status=ProtocolProbeStatus.HANDSHAKE_OK, banner=banner.decode("utf-8", errors="replace").strip(), latency_ms=round(elapsed, 2))
        except asyncio.TimeoutError:
            return ProtocolProbeResult(protocol="ssh", status=ProtocolProbeStatus.TIMEOUT, latency_ms=timeout * 1000)
        except Exception as e:
            return ProtocolProbeResult(protocol="ssh", status=ProtocolProbeStatus.ERROR, details=str(e)[:200])

    async def probe_http_auth(self, url: str, token: str, timeout: float = 5.0) -> ProtocolProbeResult:
        import httpx
        try:
            start = time.monotonic()
            async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
                resp = await client.head(url, headers={"Authorization": f"Bearer {token}"})
            elapsed = (time.monotonic() - start) * 1000
            if resp.status_code in (200, 204):
                status = ProtocolProbeStatus.AUTH_ACCEPTED
            elif resp.status_code in (401, 403):
                status = ProtocolProbeStatus.AUTH_REJECTED
            else:
                status = ProtocolProbeStatus.HANDSHAKE_OK
            return ProtocolProbeResult(protocol="http", status=status, latency_ms=round(elapsed, 2), details=f"HTTP {resp.status_code}")
        except Exception as e:
            return ProtocolProbeResult(protocol="http", status=ProtocolProbeStatus.ERROR, details=str(e)[:200])

    async def probe(self, protocol: str, target: str, credential: str = "", **kwargs) -> ProtocolProbeResult:
        if protocol == "ssh":
            host = target.split(":")[0] if ":" in target else target
            port = int(target.split(":")[1]) if ":" in target else 22
            return await self.probe_ssh(host, port, timeout=kwargs.get("timeout", 3.0))
        elif protocol in ("http", "https"):
            return await self.probe_http_auth(target, credential, timeout=kwargs.get("timeout", 5.0))
        else:
            return ProtocolProbeResult(protocol=protocol, status=ProtocolProbeStatus.NOT_APPLICABLE)
