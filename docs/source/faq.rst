FAQ
===

Le projet fonctionne-t-il sur Android ?
---------------------------------------
Oui, via Termux. Utilisez ``tls_client`` pour le TLS mimicry.

Comment ajouter un nouveau validateur ?
----------------------------------------
Créez une classe héritant de ``GenericHttpValidator`` dans le dossier ``validators/``.
Implémentez la méthode ``validate(self, candidate) -> Validated``.
Le validateur sera automatiquement routé selon le pattern du secret.

Comment entraîner le modèle ML ?
---------------------------------
.. code-block:: bash

    python train_model.py --dataset dataset.csv
