API Interne
===========

Les modules principaux exposent une API asynchrone.

Exemple : utiliser le moteur de scan
------------------------------------
.. code-block:: python

    from bxp_secretsonar.core.engine import SecretSonarEngine
    engine = SecretSonarEngine()
    await engine.run(["https://example.com"])

Exemple : utiliser le DiscoveryManager
--------------------------------------
.. code-block:: python

    from bxp_secretsonar.discovery.manager import DiscoveryManager
    manager = DiscoveryManager()
    urls = await manager.run(query="example.com", limit=10)
