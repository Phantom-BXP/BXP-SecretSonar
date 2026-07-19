Modules principaux
==================

Discovery
---------
Providers sans clé : CRT.sh, CertSpotter, Wayback Machine, AlienVault OTX, URLScan, HackerTarget, S3 Scanner, GitHub Search.

Providers avec clé : Shodan, Censys, SecurityTrails, BinaryEdge, Exa, Firecrawl, S3 Buckets.

Validation
----------
21 services supportés : AWS, Stripe, PayPal, GitHub, GitLab, GCP, Slack, Discord, OpenAI, Anthropic, Twilio, Revolut, Twitch, Heroku, SendGrid, Mailgun, Atlassian, Shopify.

Exploitation
------------
- SSH, SMB, HTTP RCE, SQLi, WinRM, Docker, RDP, Kubernetes
- Payloads : reverse shells (Python, Bash, PowerShell), bind shell, DNS tunneling
- Persistance : clé SSH, cron, systemd, bashrc, python startup, LD\_PRELOAD
- Pivoting : proxy SOCKS, scan réseau, redirection de ports
- Bypass 2FA : rejeu de tokens, cookies, OAuth refresh, génération de PAT

Furtivité
---------
- Profils TLS (tls\_client, curl\_cffi)
- Rotation de User-Agent et headers
- Délais log‑normaux (ChronoModel)
- Proxy Bandit (Thompson Sampling)
- SessionGhost (navigation réaliste)
- ContextualWeaver (alternance bruit/offensif)

Résilience
----------
- Circuit Breaker par service et type d'erreur
- RetryQueue pour les cibles momentanément inaccessibles
- Retry intelligent (tenacity)

Machine Learning
---------------
- Détection de honeypots par Random Forest calibré
- Validation croisée, feature engineering, permutation importance
- Export ONNX (production) + coefficients JSON (fallback)
- Détection de drift en production
