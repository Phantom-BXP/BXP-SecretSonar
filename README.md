# BXP-SecretSonar

**Framework avancé de découverte, validation et exploitation de secrets exposés.**  
Version `0.5.0-alpha` — Fonctionne sur Linux, macOS, Windows et Android (Termux).

---

## 🎯 Objectif

BXP-SecretSonar automatise la recherche de secrets (clés API, tokens, identifiants) dans des applications web, évalue leur criticité et fournit un cadre d’exploitation contrôlé pour en mesurer l’impact.

Il est conçu pour les audits de sécurité autorisés. Chaque utilisateur est responsable de ses actes.

---

## 🧩 Fonctionnalités

### 🔎 Découverte de cibles (Discovery)
- **Providers sans clé API** : crt.sh, CertSpotter, Wayback Machine, AlienVault OTX, URLScan, HackerTarget, S3 Scanner public, GitHub Search
- **Providers avec clé API (free tier)** : Shodan, Censys, SecurityTrails, BinaryEdge, Exa, Firecrawl
- Recherche par mot-clé, domaine, IP, ou technologie

### 📡 Collecte & Analyse
- Collecte HTTP profonde (`--deep`) : headers, robots.txt, sitemap, fichiers JS/CSS
- Détection par expressions régulières et analyse d’entropie
- Détection de honeypots (signatures passives + sondes actives comportementales)
- Score de risque composite (impact, blast radius, criticité)

### 🛡️ Validation
- Validation HTTP générique
- Validation AWS renforcée (via `GetCallerIdentity`)
- Validation multi-niveaux ajustant le score de confiance

### 💥 Exploitation modulaire
- Plugins d’exploitation : SSH, SMB, HTTP RCE, SQLi (avec fallbacks natifs)
- Payloads : reverse shells (Python, Bash, PowerShell), bind shell, commandes système
- Exploitation automatique déclenchable par seuils (`--min-confidence`, `--min-impact`, `--honeypot-threshold`)

### 🖥️ Console interactive post‑exploitation
- Gestion de sessions persistantes (connexion SSH conservée)
- Shell SSH interactif, exécution de commandes (`exec`)
- Upload/download de fichiers via SFTP
- Génération de payloads depuis la console

### ⏱️ Planification (Scheduler)
- Tâches planifiées pour lancer des découvertes et des scans automatiquement
- Rapports JSON horodatés

---

## 🚀 Démarrage rapide

```bash
git clone https://github.com/Phantom-BXP/BXP-SecretSonar.git
cd BXP-SecretSonar
pip install -e ".[dev]"
```

Dépendances d’exploitation optionnelles :

```bash
pip install paramiko impacket
```

---

🔧 Commandes principales

```bash
# Scan simple
secretsonar scan -t https://example.com

# Scan profond
secretsonar scan -t https://example.com --deep

# Découverte de cibles
secretsonar discover -q "example.com" -p crtsh --limit 10 --scan

# Exploitation automatique (nécessite --authorized)
secretsonar scan -t https://cible.com --exploit --authorized --min-confidence 0.8

# Console post‑exploitation
secretsonar console --authorized

# Planificateur (découverte + scan toutes les 24h)
secretsonar scheduler --interval 24 --queries queries.txt
```

---

📦 Architecture

```
src/bxp_secretsonar/
├── collectors/         # HttpCollector, DeepCollector
├── analyzers/          # Expressions régulières, entropie
├── validators/         # Validateur générique, spécialisations (AWS…)
├── detectors/          # Honeypots passifs, actifs, scoring
├── plugins/
│   ├── exploits/       # SSHExec, SMBExec, HttpRCE, SQLiExec
│   ├── payloads/       # Reverse shells, bind shell, commande système
│   ├── analyzers/      # Blast radius, score d’impact
│   └── validators/     # ProtocolProber
├── exploit/            # Orchestrateur (framework.py)
├── console/            # Console interactive (interactive.py)
├── discovery/          # Providers de découverte (Shodan, CRT, etc.)
├── core/               # Moteur, modèles, environnement
└── cli.py              # Interface Click
```

---

🛣️ Prochaines étapes

· Modules de persistance (clé SSH, cron)
· Pivoting et proxy SOCKS
· Détection de leurres par Machine Learning
· Mode daemon pour le scheduler

---

📜 Licence

MIT. Utilisez cet outil uniquement sur des systèmes pour lesquels vous disposez d’une autorisation explicite.

Phantom-BXP
