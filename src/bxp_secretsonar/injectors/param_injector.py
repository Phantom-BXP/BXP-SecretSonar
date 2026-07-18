import asyncio
import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx
from bxp_secretsonar.core.models import Artifact, ArtifactType
from bxp_secretsonar.injectors.base import BaseInjector

class ParamInjector(BaseInjector):
    """Injecteur de paramètres debug, headers forcés et méthodes alternatives."""

    name = "param_injector"

    def __init__(self, ssl_verify: bool = True, max_concurrency: int = 5):
        self.ssl_verify = ssl_verify
        self.sem = asyncio.Semaphore(max_concurrency)

    async def inject(self, artifact: Artifact) -> List[Artifact]:
        base_url = artifact.source_url
        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query)

        # 1. Payloads de paramètres à ajouter/modifier
        debug_payloads = [
            {"debug": "true"},
            {"debug": "1"},
            {"test": "true"},
            {"showConfig": "1"},
            {"verbose": "1"},
        ]

        # 2. Headers à injecter
        extra_headers = [
            {"X-Debug": "true"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
        ]

        # 3. Méthodes HTTP alternatives sur le même chemin
        alt_methods = ["POST", "PUT", "PATCH"]

        tasks = []

        # Construire les URLs avec les paramètres debug
        for pl in debug_payloads:
            new_query = query_params.copy()
            new_query.update(pl)
            new_query_string = urlencode(new_query, doseq=True)
            new_parsed = parsed._replace(query=new_query_string)
            new_url = urlunparse(new_parsed)
            tasks.append(self._fetch(new_url, method="GET", headers={"User-Agent": "BXP-Injector"}))

        # Requêtes avec headers spéciaux (même URL, sans changer les params)
        for hdrs in extra_headers:
            tasks.append(self._fetch(base_url, method="GET", headers=hdrs))

        # Méthodes alternatives sur la racine
        for method in alt_methods:
            tasks.append(self._fetch(base_url, method=method, headers={"Content-Type": "application/x-www-form-urlencoded"}))

        # Exécuter toutes les requêtes en parallèle
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filtrer les réponses valides et créer de nouveaux artefacts
        new_artifacts = []
        for i, resp in enumerate(results):
            if isinstance(resp, Exception):
                continue
            if resp is None:
                continue
            content = resp.get("content", "")
            if not content:
                continue
            new_art = Artifact(
                source_url=resp.get("url", base_url),
                content=content,
                artifact_type=ArtifactType.HTTP_RESPONSE,
                metadata={"injected": True, "injector": self.name, "method": resp.get("method"), "headers": str(resp.get("headers"))},
            )
            new_artifacts.append(new_art)
        return new_artifacts

    async def _fetch(self, url: str, method: str = "GET", headers: dict = None):
        async with self.sem:
            try:
                async with httpx.AsyncClient(verify=self.ssl_verify, timeout=5.0, follow_redirects=False) as client:
                    if method == "GET":
                        resp = await client.get(url, headers=headers)
                    elif method == "POST":
                        resp = await client.post(url, headers=headers)
                    elif method == "PUT":
                        resp = await client.put(url, headers=headers)
                    elif method == "PATCH":
                        resp = await client.patch(url, headers=headers)
                    else:
                        resp = await client.get(url, headers=headers)
                    return {
                        "url": str(resp.url),
                        "content": resp.text,
                        "method": method,
                        "headers": dict(resp.headers),
                    }
            except Exception:
                return None
