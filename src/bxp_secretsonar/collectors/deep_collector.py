import asyncio
import httpx
import re
from urllib.parse import urljoin
from bxp_secretsonar.core.models import Artifact, ArtifactType
from bxp_secretsonar.collectors.http import HttpCollector

class DeepCollector(HttpCollector):
    """Collecteur enrichi : explore JS, CSS, robots.txt, sitemap.xml et headers."""

    async def collect(self, url: str) -> Artifact:
        artifact = await super().collect(url)
        if not artifact:
            return None

        base_content = artifact.content
        base_url = url
        secondary_contents = []

        # Headers sensibles
        if "headers" in artifact.metadata:
            headers = artifact.metadata["headers"]
            for name, value in headers.items():
                if any(kw in name.lower() for kw in ["api", "auth", "token", "key", "secret"]):
                    secondary_contents.append(f"HEADER {name}: {value}")

        # Fichiers robots.txt et sitemap.xml
        for path in ["/robots.txt", "/sitemap.xml"]:
            full_url = urljoin(base_url, path)
            try:
                async with httpx.AsyncClient(verify=self.ssl_verify) as client:
                    resp = await client.get(full_url, timeout=5.0)
                    if resp.status_code == 200:
                        secondary_contents.append(f"FILE {path}: {resp.text[:5000]}")
            except Exception:
                pass

        # Fichiers JS/CSS référencés (max 5)
        js_urls = re.findall(r'src=["\']([^"\']+\.js)["\']', base_content)
        css_urls = re.findall(r'href=["\']([^"\']+\.css)["\']', base_content)
        for relative_url in (js_urls + css_urls)[:5]:
            full_url = urljoin(base_url, relative_url)
            try:
                async with httpx.AsyncClient(verify=self.ssl_verify) as client:
                    resp = await client.get(full_url, timeout=5.0)
                    if resp.status_code == 200:
                        secondary_contents.append(f"RESOURCE {relative_url}: {resp.text[:5000]}")
            except Exception:
                pass

        if secondary_contents:
            artifact.content = artifact.content + "\n--- SECONDARY ---\n" + "\n".join(secondary_contents)
            artifact.metadata["deep_scan"] = True
            artifact.metadata["secondary_sources"] = len(secondary_contents)

        return artifact
