#!/usr/bin/env python3
"""
Script d'entraînement du modèle ML de détection de honeypots (v2).
Ajoute : calibration, validation croisée, permutation importance, feature engineering.
"""
import os, sys, json, logging, hashlib
from datetime import datetime
import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# ---------- Feature engineering ----------
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Ajoute des features dérivées au DataFrame."""
    df = df.copy()
    df['scripts_per_form'] = df['num_scripts'] / df['num_forms'].clip(lower=1)
    df['input_per_form'] = df['num_inputs'] / df['num_forms'].clip(lower=1)
    df['response_time_ratio'] = df['response_time_ms'] / df['timing_variance'].clip(lower=0.001)
    # header_entropy sera calculée plus tard si nécessaire (placeholder)
    df['header_entropy'] = 0.0  # placeholder, à remplacer par un vrai calcul
    return df

# ---------- Data augmentation ----------
def augment_minority(X, y, minority_class=1, n_synthetic=100):
    """Génère des échantillons synthétiques pour la classe minoritaire."""
    from sklearn.neighbors import NearestNeighbors
    X_min = X[y == minority_class]
    if len(X_min) < 5:
        logger.warning("Pas assez d'échantillons minoritaires pour l'augmentation.")
        return X, y
    neigh = NearestNeighbors(n_neighbors=min(5, len(X_min)))
    neigh.fit(X_min)
    synthetic = []
    for _ in range(n_synthetic):
        idx = np.random.randint(0, len(X_min))
        sample = X_min[idx].reshape(1, -1)
        neighbors = neigh.kneighbors(sample, return_distance=False)
        neighbor_idx = np.random.choice(neighbors[0][1:])
        neighbor = X_min[neighbor_idx].reshape(1, -1)
        new_sample = sample + np.random.random() * (neighbor - sample)
        synthetic.append(new_sample[0])
    X_aug = np.vstack([X, np.array(synthetic)])
    y_aug = np.hstack([y, np.full(n_synthetic, minority_class)])
    return X_aug, y_aug

# ---------- Modèle avec calibration ----------
def train_with_cv(X, y, config):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.model_selection import StratifiedKFold, cross_validate
    from sklearn.inspection import permutation_importance
    from sklearn.metrics import roc_auc_score

    # Données d'entraînement et hold-out pour permutation importance
    from sklearn.model_selection import train_test_split
    X_train, X_holdout, y_train, y_holdout = train_test_split(
        X, y, test_size=0.1, random_state=config["random_state"], stratify=y
    )

    # Validation croisée stratifiée
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=config["random_state"])
    rf = RandomForestClassifier(
        n_estimators=config.get("n_estimators", 50),
        max_depth=config.get("max_depth", 5),
        min_samples_leaf=config.get("min_samples_leaf", 10),
        class_weight='balanced',
        random_state=config["random_state"],
        n_jobs=-1
    )

    scores = cross_validate(rf, X_train, y_train, cv=cv,
                            scoring=['accuracy', 'precision', 'recall', 'f1', 'roc_auc'],
                            return_train_score=False)

    # Moyennes et écarts-types
    metrics = {}
    for metric in ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']:
        key = f'test_{metric}'
        metrics[metric] = {
            "mean": float(scores[key].mean()),
            "std": float(scores[key].std())
        }
    logger.info(f"Métriques (CV 5-fold) : {json.dumps(metrics, indent=2)}")

    # Entraînement final sur toutes les données d'entraînement
    rf.fit(X_train, y_train)

    # Calibration
    calibrated = CalibratedClassifierCV(rf, method='isotonic', cv=3)
    calibrated.fit(X_train, y_train)
    logger.info("Modèle calibré (isotonic).")

    # Permutation importance sur le hold-out set
    perm_importance = permutation_importance(
        calibrated, X_holdout, y_holdout,
        n_repeats=20, random_state=config["random_state"],
        scoring='f1'
    )

    # Noms des features (incluant les features dérivées)
    feature_names = config.get("feature_names", [f"f{i}" for i in range(X.shape[1])])
    importance_dict = {
        name: float(perm_importance.importances_mean[i])
        for i, name in enumerate(feature_names)
    }

    return calibrated, metrics, importance_dict, cv

# ---------- Main ----------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Entraîne un modèle de détection de honeypots (v2).")
    parser.add_argument("--dataset", required=True, help="Chemin vers le CSV d'entraînement.")
    parser.add_argument("--config", default="train_config.yaml", help="Fichier de configuration YAML.")
    parser.add_argument("--output", default="models/", help="Dossier de sortie des modèles.")
    args = parser.parse_args()

    # Chargement config
    config = {
        "n_estimators": 50,
        "max_depth": 5,
        "min_samples_leaf": 10,
        "random_state": 42,
        "test_size": 0.2,
        "feature_names": [
            "response_time_ms", "content_length", "num_forms", "num_inputs",
            "num_scripts", "has_honeypot_keywords", "has_fake_error",
            "timing_variance", "missing_standard_headers", "incompatible_headers",
            "scripts_per_form", "input_per_form", "response_time_ratio", "header_entropy"
        ]
    }
    if os.path.exists(args.config):
        import yaml
        with open(args.config) as f:
            config.update(yaml.safe_load(f).get("model", {}))

    # Chargement données
    logger.info(f"Chargement de {args.dataset}...")
    df = pd.read_csv(args.dataset)
    if 'label' not in df.columns:
        logger.error("Le CSV doit contenir une colonne 'label'.")
        sys.exit(1)

    # Feature engineering
    df = engineer_features(df)
    feature_cols = config["feature_names"]
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        logger.error(f"Colonnes manquantes : {missing}")
        sys.exit(1)

    X = df[feature_cols].values
    y = df['label'].values

    # Prétraitement : imputation (si valeurs manquantes)
    from sklearn.impute import SimpleImputer
    imputer = SimpleImputer(strategy="median")
    X = imputer.fit_transform(X)

    # Augmentation si déséquilibre
    unique, counts = np.unique(y, return_counts=True)
    class_counts = dict(zip(unique, counts))
    if class_counts.get(1, 0) < 100:
        logger.info(f"Augmentation de la classe honeypot (n={class_counts.get(1, 0)})...")
        X, y = augment_minority(X, y, minority_class=1, n_synthetic=100)

    # Entraînement avec CV
    model, metrics, importance, cv = train_with_cv(X, y, config)

    # Sauvegarde
    os.makedirs(args.output, exist_ok=True)
    model_name = f"honeypot_rf_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Rapport JSON
    report = {
        "metrics": metrics,
        "feature_importance": importance,
        "config": config,
        "cv_folds": cv.get_n_splits(),
    }
    with open(os.path.join(args.output, f"{model_name}_report.json"), 'w') as f:
        json.dump(report, f, indent=2)

    # Modèle ONNX
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
        X_sample = X[:1].astype(np.float32)
        initial_type = [('float_input', FloatTensorType([None, X.shape[1]]))]
        onnx_model = convert_sklearn(model, initial_types=initial_type)
        onnx_path = os.path.join(args.output, f"{model_name}.onnx")
        with open(onnx_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        logger.info(f"ONNX exporté : {onnx_path}")
    except ImportError:
        logger.warning("skl2onnx non installé, export ONNX ignoré.")
    except Exception as e:
        logger.warning(f"Échec export ONNX : {e}")

    # Coefficients JSON (fallback Python pur)
    coefficients = {
        "feature_order": feature_cols,
        "n_classes": model.n_classes_,
        "classes_": model.classes_.tolist(),
        "n_estimators": len(model.estimators_),
        "max_depth": model.max_depth,
        "estimators": []
    }
    for tree in model.estimators_:
        n_nodes = tree.tree_.node_count
        coefficients["estimators"].append({
            "children_left": tree.tree_.children_left.tolist(),
            "children_right": tree.tree_.children_right.tolist(),
            "feature": tree.tree_.feature.tolist(),
            "threshold": tree.tree_.threshold.tolist(),
            "value": [v[0] for v in tree.tree_.value.tolist()]
        })
    coeff_path = os.path.join(args.output, f"{model_name}_coefficients.json")
    with open(coeff_path, 'w') as f:
        json.dump(coefficients, f, indent=2)
    logger.info(f"Coefficients exportés : {coeff_path}")

    print(f"\n✅ Entraînement terminé. Modèle : {model_name}")

if __name__ == "__main__":
    main()
