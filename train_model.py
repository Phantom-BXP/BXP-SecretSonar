#!/usr/bin/env python3
"""
Script d'entraînement du modèle ML de détection de honeypots pour BXP-SecretSonar.
Utilise un RandomForestClassifier avec export ONNX et coefficients JSON.
"""
import os, sys, json, logging, warnings
import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Paramètres par défaut (écrasés par train_config.yaml si présent)
DEFAULT_CONFIG = {
    "model": {
        "n_estimators": 100,
        "max_depth": 8,
        "test_size": 0.2,
        "random_state": 42,
    },
    "output": {
        "model_dir": "models/",
        "model_name": "honeypot_rf",
    },
}

def load_config(config_path: str = "train_config.yaml") -> dict:
    try:
        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f)
        return {**DEFAULT_CONFIG, **config}
    except ImportError:
        logger.warning("pyyaml non installé, utilisation des paramètres par défaut.")
        return DEFAULT_CONFIG
    except FileNotFoundError:
        logger.warning(f"{config_path} introuvable, utilisation des paramètres par défaut.")
        return DEFAULT_CONFIG

def main():
    import argparse
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report

    parser = argparse.ArgumentParser(description="Entraîne un modèle de détection de honeypots.")
    parser.add_argument("--dataset", required=True, help="Chemin vers le CSV d'entraînement.")
    parser.add_argument("--config", default="train_config.yaml", help="Fichier de configuration YAML.")
    args = parser.parse_args()

    config = load_config(args.config)
    model_dir = config["output"]["model_dir"]
    model_name = config["output"]["model_name"]
    os.makedirs(model_dir, exist_ok=True)

    # Chargement des données
    logger.info(f"Chargement de {args.dataset}...")
    df = pd.read_csv(args.dataset)
    if 'label' not in df.columns:
        logger.error("Le CSV doit contenir une colonne 'label' (0=légitime, 1=honeypot).")
        sys.exit(1)

    # Features et labels
    feature_cols = [
        "response_time_ms", "content_length", "num_forms", "num_inputs",
        "num_scripts", "has_honeypot_keywords", "has_fake_error",
        "timing_variance", "missing_standard_headers", "incompatible_headers"
    ]
    # Vérifier que toutes les colonnes de features existent
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        logger.error(f"Colonnes manquantes dans le CSV : {missing}")
        sys.exit(1)

    X = df[feature_cols].values
    y = df['label'].values

    # Préprocessing
    numeric_features = ["response_time_ms", "content_length", "num_forms", "num_inputs",
                        "num_scripts", "timing_variance"]
    numeric_indices = [feature_cols.index(c) for c in numeric_features if c in feature_cols]
    bool_features = ["has_honeypot_keywords", "has_fake_error", "missing_standard_headers",
                     "incompatible_headers"]
    bool_indices = [feature_cols.index(c) for c in bool_features if c in feature_cols]

    # Pipeline avec imputation et scaling
    preprocessor = Pipeline([
        ("imputer_num", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler(with_mean=False))  # with_mean=False pour les sparse matrices
    ])

    # Imputation séparée pour les booléens (most_frequent)
    if bool_indices:
        imputer_bool = SimpleImputer(strategy="most_frequent")
        X[:, bool_indices] = imputer_bool.fit_transform(X[:, bool_indices])

    # Appliquer le scaling seulement sur les numériques
    if numeric_indices:
        X_num = X[:, numeric_indices]
        X_num = preprocessor.fit_transform(X_num)
        X[:, numeric_indices] = X_num

    # Split stratifié
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=config["model"]["test_size"],
        random_state=config["model"]["random_state"], stratify=y
    )
    logger.info(f"Train: {X_train.shape[0]}, Test: {X_test.shape[0]}")

    # Entraînement
    logger.info("Entraînement du RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=config["model"]["n_estimators"],
        max_depth=config["model"]["max_depth"],
        class_weight='balanced',
        random_state=config["model"]["random_state"],
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    # Évaluation
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred),
        "f1_score": f1_score(y_test, y_pred),
        "auc_roc": roc_auc_score(y_test, y_proba),
    }
    logger.info(f"Métriques : {json.dumps(metrics, indent=2)}")

    feature_importance = dict(zip(feature_cols, model.feature_importances_.tolist()))
    report = {
        **metrics,
        "feature_importance": feature_importance,
        "config": config["model"],
    }

    # Sauvegarde du rapport
    report_path = os.path.join(model_dir, f"{model_name}_report.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    logger.info(f"Rapport sauvegardé : {report_path}")

    # Export ONNX
    try:
        import skl2onnx
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType

        # Forcer float32 pour ONNX
        X_sample = X_train[:1].astype(np.float32)
        initial_type = [('float_input', FloatTensorType([None, X_train.shape[1]]))]
        onnx_model = convert_sklearn(model, initial_types=initial_type)

        onnx_path = os.path.join(model_dir, f"{model_name}.onnx")
        with open(onnx_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        logger.info(f"Modèle ONNX exporté : {onnx_path}")
    except ImportError:
        logger.warning("skl2onnx non installé, export ONNX ignoré.")
    except Exception as e:
        logger.warning(f"Échec de l'export ONNX : {e}")

    # Export coefficients JSON (fallback Python pur)
    coefficients = {
        "feature_order": feature_cols,
        "n_classes": model.n_classes_,
        "classes_": model.classes_.tolist(),
        "n_estimators": len(model.estimators_),
        "max_depth": model.max_depth,
        "estimators": []
    }
    for tree in model.estimators_:
        # Exporter chaque arbre sous forme de structure simple
        n_nodes = tree.tree_.node_count
        children_left = tree.tree_.children_left.tolist()
        children_right = tree.tree_.children_right.tolist()
        feature = tree.tree_.feature.tolist()
        threshold = tree.tree_.threshold.tolist()
        value = tree.tree_.value.tolist()  # shape (n_nodes, 1, n_classes)
        coefficients["estimators"].append({
            "children_left": children_left,
            "children_right": children_right,
            "feature": feature,
            "threshold": threshold,
            "value": [v[0] for v in value]  # aplatir la dimension 1
        })

    coeff_path = os.path.join(model_dir, f"{model_name}_coefficients.json")
    with open(coeff_path, 'w') as f:
        json.dump(coefficients, f, indent=2)
    logger.info(f"Coefficients exportés : {coeff_path}")

    # Génération du fallback codé en dur (Python)
    fallback_code = f'''"""
Modèle de détection honeypot (fallback codé en dur).
Généré automatiquement par train_model.py – Ne pas modifier manuellement.
"""
import json, os

_MODEL_COEFFICIENTS = None

def _load_coefficients():
    global _MODEL_COEFFICIENTS
    if _MODEL_COEFFICIENTS is None:
        coeff_file = os.path.join(os.path.dirname(__file__), "..", "..", "..", "models", "{model_name}_coefficients.json")
        with open(coeff_file) as f:
            _MODEL_COEFFICIENTS = json.load(f)
    return _MODEL_COEFFICIENTS

def predict_proba(features):
    """Retourne la probabilité honeypot (shape [n_samples, 2])."""
    import numpy as np
    coeffs = _load_coefficients()
    features = np.array(features, dtype=np.float32)
    n_classes = coeffs["n_classes"]
    all_proba = np.zeros((features.shape[0], n_classes), dtype=np.float64)

    for tree in coeffs["estimators"]:
        node_indices = np.zeros(features.shape[0], dtype=int)
        while True:
            left = np.array(tree["children_left"])
            right = np.array(tree["children_right"])
            feature_idx = np.array(tree["feature"])
            threshold = np.array(tree["threshold"])

            current_features = features[np.arange(len(features)), feature_idx[node_indices]]
            go_left = current_features <= threshold[node_indices]
            go_right = ~go_left

            node_indices[go_left] = left[node_indices[go_left]]
            node_indices[go_right] = right[node_indices[go_right]]

            # Si tous les nœuds sont feuilles, on arrête
            if np.all(left[node_indices] == -1):
                break

        # Agrégation des valeurs des feuilles
        for i, leaf_idx in enumerate(node_indices):
            all_proba[i] += tree["value"][leaf_idx]

    # Normalisation
    all_proba /= len(coeffs["estimators"])
    return all_proba

def predict(features):
    proba = predict_proba(features)
    return np.argmax(proba, axis=1)
'''
    fallback_path = os.path.join("src", "bxp_secretsonar", "detectors", "fallback_model.py")
    os.makedirs(os.path.dirname(fallback_path), exist_ok=True)
    with open(fallback_path, 'w') as f:
        f.write(fallback_code)
    logger.info(f"Fallback codé en dur généré : {fallback_path}")

    print("\n✅ Entraînement terminé. Modèles sauvegardés dans", model_dir)
    print(f"   ONNX : {model_name}.onnx")
    print(f"   Coefficients JSON : {model_name}_coefficients.json")
    print(f"   Fallback Python : src/bxp_secretsonar/detectors/fallback_model.py")

if __name__ == "__main__":
    main()
