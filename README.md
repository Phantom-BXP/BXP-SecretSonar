# BXP-SecretSonar



**Framework avancé de découverte, validation et exploitation contrôlée de secrets exposés.**



[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)

[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-yellow.svg)](https://github.com/astral-sh/ruff)



---



## 🎯 Objectif



BXP-SecretSonar est un outil conçu à des **fins préventives et sécuritaires**. Il permet de :



- ✅ **Découvrir** des cibles potentielles via de multiples providers

- ✅ **Collecter** des données HTTP approfondies (headers, JS, CSS, etc.)

- ✅ **Analyser** le contenu pour détecter des secrets exposés

- ✅ **Valider** les secrets détectés via des API spécifiques

- ✅ **Évaluer** le risque et l'impact (honeypots, blast radius)

- ✅ **Exploiter** de manière contrôlée

- ✅ **Gérer** des sessions post-exploitation via une console interactive



> **Chacun est responsable de ses actes.**



---



## 🧩 Fonctionnalités



### 🔎 Découverte de Cibles

•	Provider	•	API Requise	•	Description

crt.sh	Non	Certificates SSLhistoriques

CertSpotter	Non	Surveillance des certificates

Wayback Machine	Non	Archives web

AlienVault OTX	Non	Threat intelligence

URLScan	Non	Scans publics

HackerTarget	Non	Recherche DNS

S3 Scanner	Non	Buckets S3 publics

GitHub Search	Non	Recherche dans GitHub

Shodan	Oui	Moteur de recherche IoT

Censys	Oui	Base de données Internet

SecurityTrails	Oui	Historique DNS

BinaryEdge	Oui	Threat intelligence

Exa	Oui	Moteur de recherche AI

Firecrawl	Oui	Crawling avancé





### 📡 Collecte et Analyse



- **Collecte HTTP standard** : Contenu de base

- **Deep Scan** (`--deep`) :

  - Headers HTTP complets

  - Fichiers `robots.txt` et `sitemap.xml`

  - Fichiers JavaScript (max 5)

  - Fichiers CSS (max 5)

  - Détection de headers sensibles



- **Analyse par expressions régulières** : 50+ patterns pour différents services

- **Analyse d'entropie** : Détection des strings à haute entropie

- **Détection de honeypots** :

  - Signatures passives (bannières, comportement)

  - Sondes actives (comportementales)



### ✅ Validation Multi-Niveaux



Validation spécifique pour **18+ services** :

•	Service	•	Méthode de Validation	•	Type

AWS	`sts:GetCallerIdentity`	Active

Stripe	API Stripe	Active

PayPal	API PayPal	Active

GitHub	API GitHub	Active

GitLab	API GitLab	Active

GCP	API Google 	Active

Slack	API Slack	Active

Discord	API Discord	Active

OpenAI	API OpenAI	Active

Anthropic	API Anthropic	Active

Twilio	API Twilio	Active

Revolut	API Revolut	Active

Twitch	API Twitch	Active

Heroku	API Heroku	Active

SendGrid	API SendGrid	Active

Mailgun	API Mailgun	Active

Atlassian	API Atlassian	Active

Shopify	API Shopify	Active





### 🎯 Scoring Avancé



- **Risk Score** (0.0-1.0) :

  - Signaux passifs (bannières, headers)

  - Sondes actives (comportement)

  - Niveau : LOW → MEDIUM → HIGH → CRITICAL



- **Impact Score** (0.0-1.0) :

  - Type de secret

  - Vérification protocolaire

  - Blast radius (ressources affectées)

  - Niveau : LOW → MEDIUM → HIGH → CRITICAL



### 💥 Exploitation Modulaire



**Plugins d'exploitation** :



•	Plugin	•	Description	•	Protocoles

SSH Exec	Exécution de commandes SSH	SSH

SMB Exec	Exécution de commandes SMB	SMB

HTTP RCE	Remote Code Execution HTTP	HTTP/HTTPS

SQLi Exec	Exploitation SQL Injection	HTTP/HTTPS





**Payloads disponibles** :

- Reverse Shell (Python, Bash, PowerShell)

- Bind Shell

- Commande système simple



•	Option	•	Description	•	Valeurs possibles	•	Défaut

`--min-confidence`	Score de confiance minimum	0.0-1.0	0.7

`--min-impact`	Niveau d'impact minimum	low, medium, high, critical	low

`--honeypot-threshold`	Score honeypot maximum	0.0-1.0	0.5

`--strategy`	Stratégie d'exploitation	safe, aggressive	safe



### 🖥️ Console Interactive



Fonctionnalités post-exploitation :

- Gestion de sessions persistantes

- Shell SSH interactif

- Exécution de commandes (`exec`)

- Upload de fichiers via SFTP

- Download de fichiers via SFTP

- Génération de payloads

- Affichage des sessions actives



---



## 🚀 Installation



### Prérequis



- Python **3.11 ou supérieur**

- pip (généralement inclus avec Python)

- Système d'exploitation : Linux, macOS, Windows, Android (Termux)



### Installation de Base



```bash

# Cloner le dépôt

git clone https://github.com/Phantom-BXP/BXP-SecretSonar.git

cd BXP-SecretSonar



# Installer en mode développement (recommandé)

pip install -e ".[dev]"



# Ou installer en production

pip install -e .

```



### Installation des Dépendances d'Exploitation (Optionnel)



```bash

pip install paramiko    # Pour SSH Exec

pip install impacket    # Pour SMB Exec

```



### Configuration



#### Variables d'Environnement



Créer un fichier `.env` :



```bash

cat > .env << 'EOF'

# Paramètres réseau

MAX_CONCURRENCY=10

TIMEOUT=5.0

SSL_VERIFY=true



# Paramètres de sécurité

MIN_CONFIDENCE=0.7

MIN_IMPACT=low

HONEYPOT_THRESHOLD=0.5

DEBUG_MODE=false



# Paramètres d'exploitation

EXPLOIT_ENABLED=false

AUTHORIZED=false



# Logging

LOG_LEVEL=INFO

LOG_FILE=secretsonar.log

EOF

```



#### Clés API (Optionnel)



Pour les providers nécessitant une clé API, créer un fichier `api_keys.json` :



```json

{

  "shodan": "VOTRE_CLE_SHODAN",

  "censys": "VOTRE_CLE_CENSYS",

  "securitytrails": "VOTRE_CLE_SECURITYTRAILS",

  "binaryedge": "VOTRE_CLE_BINARYEDGE",

  "exa": "VOTRE_CLE_EXA",

  "firecrawl": "VOTRE_CLE_FIRECRAWL"

}

```



---



## 🎯 Utilisation



### Commandes de Base



| Commande | Description |

|----------|-------------|

| `secretsonar scan -t URL` | Scan simple d'une URL |

| `secretsonar scan -t URL --deep` | Scan profond (JS, CSS, etc.) |

| `secretsonar scan -t URL --exploit --authorized` | Scan avec exploitation |

| `secretsonar discover -q "domaine.com" -p crtsh` | Découverte via CRT.sh |

| `secretsonar console --authorized` | Lancer la console interactive |

| `secretsonar scheduler --interval 24` | Planificateur (toutes les 24h) |



### Exemples Complets



#### Scan Simple

```bash

secretsonar scan -t https://example.com

```



#### Scan Profond avec Validation

```bash

secretsonar scan -t https://example.com \

    --deep \

    --min-confidence 0.8 \

    --min-impact medium

```



#### Découverte + Scan Automatique

```bash

secretsonar discover -q "example.com" \

    -p crtsh \

    --limit 20 \

    --scan

```



#### Exploitation Automatique

```bash

secretsonar scan -t https://cible.com \

    --deep \

    --exploit \

    --authorized \

    --min-confidence 0.9 \

    --min-impact high \

    --honeypot-threshold 0.3 \

    --strategy safe \

    --console-after

```



#### Console Interactive

```bash

secretsonar console --authorized



# Avec chargement de sessions sauvegardées

secretsonar console --authorized --load-sessions sessions.pkl

```



#### Planificateur

```bash

secretsonar scheduler \

    --interval 24 \

    --queries queries.txt \

    --output reports/

```



---



## 📊 Sorties et Rapports



### Format des Résultats



```

✅ Scan complete. 42 validated, 12 confirmed, 5 high-impact.



+-------------+----------+--------------------+--------------------+-------+-------------------+

| Status      | Impact   | Pattern            | Value              | Risk  | Blast Radius       |

+-------------+----------+--------------------+--------------------+-------+-------------------+

| confirmed   | CRITICAL | aws_access_key     | ************ABC    | 0.95  | s3:my-bucket      |

| confirmed   | HIGH     | github_token       | ************XYZ    | 0.82  | api:github.com    |

| rejected    | -        | generic_api_key    | ************123    | 0.25  | -                 |

+-------------+----------+--------------------+--------------------+-------+-------------------+

```



### Rapports JSON



```json

{

  "scan_id": "a1b2c3d4",

  "timestamp": "2026-07-18T10:00:00Z",

  "target": "https://example.com",

  "config": {

    "deep_scan": true,

    "min_confidence": 0.7,

    "min_impact": "low",

    "honeypot_threshold": 0.5

  },

  "summary": {

    "total_evidences": 42,

    "validated": 12,

    "confirmed": 8,

    "high_impact": 5,

    "honeypots_detected": 2,

    "exploits_attempted": 3,

    "exploits_successful": 2

  },

  "results": []

}

```



---



## 📜 Licence



Distribué sous la licence **MIT**.



---



**Phantom BXP** - 2026

