import asyncio, traceback
from typing import List, Optional, Dict
from bxp_secretsonar.discovery.base import DiscoveryProvider
from bxp_secretsonar.discovery.shodan import ShodanProvider
from bxp_secretsonar.discovery.crtsh import CrtShProvider
from bxp_secretsonar.discovery.firecrawl import FirecrawlProvider
from bxp_secretsonar.discovery.exa import ExaProvider
from bxp_secretsonar.discovery.s3buckets import S3BucketsProvider
from bxp_secretsonar.discovery.certspotter import CertSpotterProvider
from bxp_secretsonar.discovery.wayback import WaybackProvider
from bxp_secretsonar.discovery.s3scanner import S3ScannerProvider
from bxp_secretsonar.discovery.github_search import GitHubSearchProvider
from bxp_secretsonar.discovery.hackertarget import HackerTargetProvider
from bxp_secretsonar.discovery.binaryedge import BinaryEdgeProvider
from bxp_secretsonar.discovery.securitytrails import SecurityTrailsProvider
from bxp_secretsonar.discovery.censys import CensysProvider
from bxp_secretsonar.discovery.alienvault import AlienVaultProvider
from bxp_secretsonar.discovery.urlscan import URLScanProvider

class DiscoveryManager:
    def __init__(self):
        self.providers: Dict[str, DiscoveryProvider] = {}
        self._register_defaults()

    def _register_defaults(self):
        # Providers sans clé API (toujours chargés)
        self.providers["crtsh"] = CrtShProvider()
        self.providers["certspotter"] = CertSpotterProvider()
        self.providers["wayback"] = WaybackProvider()
        self.providers["s3scanner"] = S3ScannerProvider()
        self.providers["github"] = GitHubSearchProvider()
        self.providers["hackertarget"] = HackerTargetProvider()
        try:
            self.providers["censys"] = CensysProvider()
        except ValueError:
            pass
        self.providers["alienvault"] = AlienVaultProvider()
        try:
            self.providers["securitytrails"] = SecurityTrailsProvider()
        except ValueError:
            pass
        self.providers["urlscan"] = URLScanProvider()
        try:
            self.providers["binaryedge"] = BinaryEdgeProvider()
        except ValueError:
            pass

        # Providers nécessitant une clé API (chargés seulement si clé présente)
        try:
            self.providers["shodan"] = ShodanProvider()
        except ValueError:
            pass
        try:
            self.providers["firecrawl"] = FirecrawlProvider()
        except ValueError:
            pass
        try:
            self.providers["exa"] = ExaProvider()
        except ValueError:
            pass
        try:
            self.providers["s3buckets"] = S3BucketsProvider()
        except ValueError:
            pass

    def register(self, name: str, provider: DiscoveryProvider):
        self.providers[name] = provider

    async def run(self, query: str, limit: int = 10, provider: Optional[str] = None) -> List[str]:
        all_urls = []
        targets = [provider] if provider else list(self.providers.keys())
        for name in targets:
            prov = self.providers.get(name)
            if not prov:
                print(f"[!] Provider '{name}' non trouvé")
                continue
            try:
                urls = await prov.discover(query, limit=limit)
                print(f"[+] {name}: {len(urls)} URLs trouvées pour '{query}'")
                all_urls.extend(urls)
            except Exception as e:
                print(f"[!] Erreur provider {name}: {type(e).__name__}: {e}")
                traceback.print_exc()
        return all_urls
