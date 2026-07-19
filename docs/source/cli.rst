Interface en ligne de commande
==============================

Commandes principales
---------------------

.. code-block:: bash

    secretsonar scan -t URL [--deep] [--exploit --authorized]
    secretsonar discover -q "domaine.com" -p crtsh --limit 10 --scan
    secretsonar daemon --interval 24 --queries queries.txt
    secretsonar console --authorized
    secretsonar stealth list / use / healthcheck
    secretsonar setup --offline
    secretsonar autonomy 3

Options de scan
---------------

.. code-block:: text

    --deep              Scan profond (JS, CSS, headers)
    --inject            Injection active de paramètres debug
    --exploit           Active l'exploitation (nécessite --authorized)
    --authorized        Confirmation d'autorisation écrite
    --allow-private     Désactive la protection SSRF
    --proxy             URL du proxy SOCKS5/HTTP
    --min-confidence    Score de confiance minimum (0.0-1.0)
    --min-impact        Niveau d'impact minimum (low/medium/high/critical)
    --honeypot-threshold Score honeypot maximum (0.0-1.0)
    --autonomy          Niveau d'autonomie (0-5)
