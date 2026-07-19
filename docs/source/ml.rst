Module Machine Learning
=======================

Entraînement
------------
.. code-block:: bash

    python train_model.py --dataset dataset.csv

Le script génère un modèle ONNX, un rapport JSON, et un fallback codé en dur.

Inférence
---------
Le modèle est chargé automatiquement par le ``RiskScorer`` s'il est présent dans le dossier ``models/``.

La fusion avec le score heuristique est explicite : en cas de désaccord majeur (>0.5), l'heuristique prime.

Détection de drift
------------------
Si les features d'une cible s'éloignent de plus de 2 écarts‑types de la moyenne d'entraînement, le score ML est atténué et un avertissement est émis.
