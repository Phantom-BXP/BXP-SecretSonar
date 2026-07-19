Architecture
============

Le projet suit une architecture modulaire :

.. code-block:: text

    src/bxp_secretsonar/
    ├── collectors/         # Collecte HTTP profonde (HttpCollector, DeepCollector)
    ├── analyzers/          # Analyse par expressions régulières et entropie
    ├── validators/         # 21+ validateurs spécialisés
    ├── detectors/          # Détection de honeypots, scoring
    ├── discovery/          # 16+ providers de découverte
    ├── exploit/            # Orchestrateur d'exploitation
    ├── console/            # Console interactive post‑exploitation
    ├── plugins/
    │   ├── exploits/       # SSH, SMB, HTTP RCE, SQLi, WinRM, Docker, RDP, K8s
    │   ├── payloads/       # Reverse shells, DNS tunneling
    │   ├── post_exploit/   # Persistance, pivoting, bypass 2FA
    │   └── analyzers/      # Impact, blast radius
    ├── daemon.py           # Mode daemon avec planification
    └── cli.py              # Interface Click
