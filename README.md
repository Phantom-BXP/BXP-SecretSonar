# BXP-SecretSonar

**Framework de découverte, validation et post‑exploitation de secrets exposés.**  
Version `0.5.0-alpha` — Fonctionne sur Linux, macOS, Windows et Android (Termux).

---

## 🎯 Objectif

BXP-SecretSonar automatise la recherche de secrets (clés API, tokens, identifiants) dans des applications web, 
évalue leur criticité et fournit un cadre d’exploitation contrôlé pour en mesurer l’impact.

Il a été conçu pour les audits de sécurité autorisés.  
Chaque utilisateur est responsable de ses actions.

---

## 🧩 Fonctionnalités

- **Collecte HTTP profonde** (`--deep`) : exploration des headers, robots.txt, sitemap, fichiers JS/CSS
- **Détection** : expressions régulières, analyse d’entropie, signatures de honeypots
- **Validation multi‑niveaux** : test HTTP générique + validations spécialisées (AWS `GetCallerIdentity`, …)
- **Score d’impact** : blast radius, criticité, score composite
- **Framework d’exploitation modulaire** : SSH, SMB, HTTP RCE, SQLi avec fallbacks natifs
- **Console interactive** : gestion de sessions, shell SSH, upload/download SFTP, exécution de commandes
- **Payloads** : reverse shells (Python, Bash, PowerShell), bind shell, exécution système
- **Seuils personnalisables** : `--min-confidence`, `--min-impact`, `--honeypot-threshold`
- **Multi‑plateforme** : adaptation automatique à l’environnement, alternatives quand une dépendance manque

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

# Exploitation automatique (nécessite --authorized)
secretsonar scan -t https://cible.com --exploit --authorized --min-confidence 0.8

# Console post‑exploitation
secretsonar console --authorized
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
├── core/               # Moteur, modèles, environnement
└── cli.py              # Interface Click
```

---

🛣️ Prochaines étapes

· Validation multi‑cloud (GCP, Azure)
· Détection de leurres par Machine Learning
· Modules de persistance, pivoting et exfiltration

---

📜 Licence

MIT. Utilisez cet outil uniquement sur des systèmes pour lesquels vous disposez d’une autorisation explicite.

Phantom-BXP
