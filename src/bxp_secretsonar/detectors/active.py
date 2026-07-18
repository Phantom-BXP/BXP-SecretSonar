import asyncio
import time
import httpx

DIFFERENTIATION_PROBES = [
    {"method": "GET", "path": "/nonexistent-path-probe-xyz", "expect_status": [404, 403, 301]},
    {"method": "HEAD", "path": "/", "expect_headers": ["server", "date"]},
]


async def probe_behavior(url: str, ssl_verify: bool = True, timeout: float = 3.0) -> list[str]:
    signals = []
    base_url = url.rstrip("/")
    async with httpx.AsyncClient(verify=ssl_verify, timeout=timeout, follow_redirects=False) as client:
        timings = []
        responses = []
        for probe in DIFFERENTIATION_PROBES:
            try:
                start = time.monotonic()
                resp = await client.request(probe["method"], f"{base_url}{probe['path']}")
                elapsed = time.monotonic() - start
                timings.append(elapsed)
                responses.append(resp)
                if elapsed < 0.005:
                    signals.append("ultra_fast_response")
                if probe.get("expect_status") and resp.status_code not in probe["expect_status"]:
                    signals.append(f"unexpected_status_{resp.status_code}")
            except Exception:
                signals.append("probe_connection_error")
                continue
        if len(timings) >= 2:
            mean_t = sum(timings) / len(timings)
            variance = sum((t - mean_t) ** 2 for t in timings) / len(timings)
            if variance < 0.000004:
                signals.append("uniform_timing")
        if responses:
            headers = responses[0].headers
            server = headers.get("server", "").lower()
            powered_by = headers.get("x-powered-by", "").lower()
            if server and powered_by:
                incompatible = [("nginx", "express"), ("apache", "flask"), ("iis", "php"), ("cloudflare", "tomcat")]
                for s, p in incompatible:
                    if s in server and p in powered_by:
                        signals.append(f"incompatible_headers_{s}_{p}")
                        break
            if "server" not in headers and "date" not in headers:
                signals.append("missing_standard_headers")
    return signals
