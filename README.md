BXP-SecretSonar
Framework avancé de découverte, validation et exploitation contrôlée de secrets exposés.

Python 3.11+ License: MIT Code Style: Ruff

🎯 Objectif
BXP-SecretSonar est un outil professionnel conçu pour les audits de sécurité autorisés. Il permet de:

✅ Découvrir des cibles potentielles via de multiples providers
✅ Collecter des données HTTP approfondies (headers, JS, CSS, etc.)
✅ Analyser le contenu pour détecter des secrets exposés
✅ Valider les secrets détectés via des API spécifiques
✅ Évaluer le risque et l'impact (honeypots, blast radius)
✅ Exploiter de manière contrôlée (si autorisée)
✅ Gérer des sessions post-exploitation via une console interactive
⚠️ ATTENTION: Cet outil est conçu pour un usage légal et autorisé uniquement. Chaque utilisateur est responsable de ses actes. Une utilisation non autorisée peut violer les lois locales et internationales.

🧩 Fonctionnalités
🔎 Découverte de Cibles
Provider	Clé API Requise	Description
crt.sh	❌ Non	Certificates SSL historiques
CertSpotter	❌ Non	Surveillance des certificates
Wayback Machine	❌ Non	Archives web
AlienVault OTX	❌ Non	Threat intelligence
URLScan	❌ Non	Scans publics
HackerTarget	❌ Non	Recherche DNS
S3 Scanner	❌ Non	Buckets S3 publics
GitHub Search	❌ Non	Recherche dans GitHub
Shodan	✅ Oui	Moteur de recherche IoT
Censys	✅ Oui	Base de données Internet
SecurityTrails	✅ Oui	Historique DNS
BinaryEdge	✅ Oui	Threat intelligence
Exa	✅ Oui	Moteur de recherche AI
Firecrawl	✅ Oui	Crawling avancé
📡 Collecte & Analyse
Collecte HTTP standard: Contenu de base
Deep Scan (--deep):
Headers HTTP complets
Fichiers robots.txt et sitemap.xml
Fichiers JavaScript (max 5)
Fichiers CSS (max 5)
Détection de headers sensibles
Analyse par expressions régulières: 50+ patterns pour différents services
Analyse d'entropie: Détection des strings à haute entropie
Détection de honeypots:
Signatures passives (bannières, comportement)
Sondes actives (comportementales)
✅ Validation Multi-Niveaux
Validation spécifique pour 18+ services:

Service	Méthode de Validation	Confirmation
AWS	sts:GetCallerIdentity	✅ Active
Stripe	API Stripe	✅ Active
PayPal	API PayPal	✅ Active
GitHub	API GitHub	✅ Active
GitLab	API GitLab	✅ Active
GCP	API Google Cloud	✅ Active
Slack	API Slack	✅ Active
Discord	API Discord	✅ Active
OpenAI	API OpenAI	✅ Active
Anthropic	API Anthropic	✅ Active
Twilio	API Twilio	✅ Active
Revolut	API Revolut	✅ Active
Twitch	API Twitch	✅ Active
Heroku	API Heroku	✅ Active
SendGrid	API SendGrid	✅ Active
Mailgun	API Mailgun	✅ Active
Atlassian	API Atlassian	✅ Active
Shopify	API Shopify	✅ Active
🎯 Scoring Avancé
Risk Score (0.0-1.0):

Signaux passifs (bannières, headers)
Sondes actives (comportement)
Niveau: LOW → MEDIUM → HIGH → CRITICAL
Impact Score (0.0-1.0):

Type de secret
Vérification protocolaire
Blast radius (ressources affectées)
Niveau: LOW → MEDIUM → HIGH → CRITICAL
💥 Exploitation Modulaire
Plugins d'exploitation (requiert --authorized):

Plugin	Description	Protocoles
SSH Exec	Exécution de commandes SSH	SSH
SMB Exec	Exécution de commandes SMB	SMB
HTTP RCE	Remote Code Execution HTTP	HTTP/HTTPS
SQLi Exec	Exploitation SQL Injection	HTTP/HTTPS
Payloads disponibles:

Reverse Shell (Python, Bash, PowerShell)
Bind Shell
Commande système simple
Options d'exploitation:

--min-confidence: Score de confiance minimum (0.0-1.0, défaut: 0.7)
--min-impact: Niveau d'impact minimum (low/medium/high/critical, défaut: low)
--honeypot-threshold: Score honeypot maximum (0.0-1.0, défaut: 0.5)
--strategy: Stratégie (safe/aggressive)
🖥️ Console Interactive
Fonctionnalités post-exploitation:

🔄 Gestion de sessions persistantes
💻 Shell SSH interactif
▶️ Exécution de commandes (exec)
📤 Upload de fichiers via SFTP
📥 Download de fichiers via SFTP
🎯 Génération de payloads
📊 Affichage des sessions actives
🚀 Installation
Prérequis
Python 3.11 ou supérieur
pip (généralement inclus avec Python)
Système d'exploitation: Linux, macOS, Windows, Android (Termux)
Installation de Base
# Cloner le dépôt
git clone https://github.com/Phantom-BXP/BXP-SecretSonar.git
cd BXP-SecretSonar

# Installer en mode développement (recommandé)
pip install -e ".[dev]"

# Ou installer en production
pip install -e .
Installation des Dépendances d'Exploitation (Optionnel)
Pour les fonctionnalités d'exploitation avancées:

pip install paramiko    # Pour SSH Exec
pip install impacket    # Pour SMB Exec
Configuration
Variables d'Environnement
Créer un fichier .env:

# Copier le template
cp .env.example .env

# Ou créer manuellement
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
Clés API (Optionnel)
Pour les providers nécessitant une clé API, créer un fichier api_keys.json:

{
  "shodan": "VOTRE_CLE_SHODAN",
  "censys": "VOTRE_CLE_CENSYS",
  "securitytrails": "VOTRE_CLE_SECURITYTRAILS",
  "binaryedge": "VOTRE_CLE_BINARYEDGE",
  "exa": "VOTRE_CLE_EXA",
  "firecrawl": "VOTRE_CLE_FIRECRAWL"
}
🎯 Utilisation
Commandes de Base
Commande	Description
secretsonar scan -t URL	Scan simple d'une URL
secretsonar scan -t URL --deep	Scan profond (JS, CSS, etc.)
secretsonar scan -t URL --exploit --authorized	Scan avec exploitation
secretsonar discover -q "domaine.com" -p crtsh	Découverte via CRT.sh
secretsonar console --authorized	Lancer la console interactive
secretsonar scheduler --interval 24	Planificateur (toutes les 24h)
Exemples Complets
1. Scan Simple
secretsonar scan -t https://example.com
2. Scan Profond avec Validation
secretsonar scan -t https://example.com \
    --deep \
    --min-confidence 0.8 \
    --min-impact medium
3. Découverte + Scan Automatique
secretsonar discover -q "example.com" \
    -p crtsh \
    --limit 20 \
    --scan
4. Exploitation Automatique (⚠️ Requiert autorisation)
secretsonar scan -t https://cible.com \
    --deep \
    --exploit \
    --authorized \
    --min-confidence 0.9 \
    --min-impact high \
    --honeypot-threshold 0.3 \
    --strategy safe \
    --console-after
5. Console Interactive
# Lancer la console
secretsonar console --authorized

# Avec chargement de sessions sauvegardées
secretsonar console --authorized --load-sessions sessions.pkl
6. Planificateur
# Découverte + scan toutes les 24 heures
secretsonar scheduler \
    --interval 24 \
    --queries queries.txt \
    --output reports/
Fichier queries.txt:

example.com
another-domain.com
192.168.1.0/24
Options Avancées
Options de Scan
Option	Description	Défaut
-t, --target	URL ou domaine cible	requis
--deep	Active le DeepScan	False
--inject	Active l'injection de paramètres	False
--min-confidence	Score de confiance minimum	0.7
--min-impact	Niveau d'impact minimum	low
--honeypot-threshold	Score honeypot maximum	0.5
Options d'Exploitation
Option	Description	Défaut
--exploit	Active l'exploitation	False
--authorized	REQUIS pour l'exploitation	False
--strategy	Stratégie (safe/aggressive)	safe
--console-after	Lancer la console après scan	False
Options de Découverte
Option	Description	Défaut
-q, --query	Requête de recherche	requis
-p, --provider	Provider à utiliser	tous
-l, --limit	Nombre max de résultats	10
--scan	Scanner les cibles découvertes	False
📊 Sorties et Rapports
Format des Résultats
Les résultats sont affichés sous forme de tableau:

✅ Scan complete. 42 validated, 12 confirmed, 5 high-impact.

Validated Secrets + Impact
┏━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Status      ┃ Impact   ┃ Pattern          ┃ Value               ┃ Risk   ┃ Blast Radius          ┃
┡━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ confirmed   │ CRITICAL │ aws_access_key   │ ****************ABC │ 0.95  │ s3:my-bucket         │
│ confirmed   │ HIGH     │ github_token     │ ****************XYZ │ 0.82  │ api:github.com       │
│ rejected    │ -        │ generic_api_key  │ ****************123 │ 0.25  │ -                     │
└─────────────┴──────────┴──────────────────┴────────────────────┴────────┴──────────────────────┘
Rapports JSON
Les rapports sont sauvegardés au format JSON:

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
  "results": [
    {
      "status": "confirmed",
      "pattern": "aws_access_key",
      "impact": "critical",
      "risk_score": 0.95,
      "secret_hash": "a1b2c3d4e5f6g7h8",
      "context": "Found in /config/prod.env",
      "validation_proof": "GetCallerIdentity succeeded"
    }
  ]
}
🛡️ Sécurité
⚠️ Avertissements Importants
Utilisation Légale: Cet outil doit être utilisé uniquement sur des systèmes pour lesquels vous avez une autorisation explicite écrite.

Exposition de Secrets: Les secrets détectés sont masqués dans les affichages, mais les données brutes peuvent être présentes dans les fichiers de log. Assurez-vous de:

Utiliser le mode --authorized uniquement quand approprié
Protéger vos fichiers de log
Nettoyer les données après utilisation
Responsabilité: Les auteurs ne sont pas responsables de toute utilisation abusive de cet outil.

🔒 Bonnes Pratiques
✅ Toujours utiliser --authorized quand vous avez l'autorisation
✅ Vérifier les lois locales avant utilisation
✅ Ne pas scanner des infrastructures critiques
✅ Respecter les robots.txt et les politiques de sécurité
✅ Utiliser des networks isolés pour les tests
✅ Sauvegarder les sessions de manière sécurisée
BXP-SecretSonar est un projet de BriadeXPhantom de Phantom-BXP - 18 juillet 2026*
