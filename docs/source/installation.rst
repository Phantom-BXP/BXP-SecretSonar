Installation
============

Prérequis
---------
- Python 3.11 ou supérieur
- pip

Installation de base
--------------------

.. code-block:: bash

    git clone https://github.com/Phantom-BXP/BXP-SecretSonar.git
    cd BXP-SecretSonar
    pip install -e ".[dev]"

Dépendances optionnelles
------------------------

.. code-block:: bash

    pip install paramiko          # SSH
    pip install impacket          # SMB / RDP
    pip install tls_client        # TLS mimicry
    pip install apscheduler       # Daemon
    pip install winrm             # WinRM (pywinrm)
    pip install docker            # Docker API

Configuration
-------------
Le fichier ``.env`` permet de personnaliser les paramètres par défaut :

.. code-block:: bash

    MAX_CONCURRENCY=10
    TIMEOUT=5.0
    SSL_VERIFY=true
    MIN_CONFIDENCE=0.7
    MIN_IMPACT=low
    HONEYPOT_THRESHOLD=0.5
    EXPLOIT_ENABLED=false
    AUTHORIZED=false
    LOG_LEVEL=INFO
