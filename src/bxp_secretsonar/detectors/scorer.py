import os, logging
from typing import Optional
from bxp_secretsonar.core.models import RiskScore, RiskLevel

logger = logging.getLogger(__name__)

# Poids des signaux heuristiques (conservés)
SIGNAL_WEIGHTS = {
    # Passifs
    "cowrie_ssh_banner": 0.9,
    "dionaea_default_page": 0.85,
    "generic_honeypot_form": 0.6,
    "fake_error_page": 0.3,
    "default_credentials_hint": 0.5,
    "canary_token_marker": 0.95,
    # Actifs
    "ultra_fast_response": 0.7,
    "uniform_timing": 0.65,
    "incompatible_headers_nginx_express": 0.8,
    "incompatible_headers_apache_flask": 0.8,
    "incompatible_headers_iis_php": 0.75,
    "incompatible_headers_cloudflare_tomcat": 0.8,
    "missing_standard_headers": 0.4,
    "unexpected_status_200": 0.5,
    "probe_connection_error": 0.2,
}

# Variable globale pour le modèle ML (chargé au premier appel)
_ML_MODEL = None

def _load_ml_model():
    """Charge le modèle ML au format ONNX ou fallback coefficients."""
    global _ML_MODEL
    if _ML_MODEL is not None:
        return _ML_MODEL

    # Essayer ONNX d'abord
    try:
        import onnxruntime as ort
        model_path = os.path.join("models", "honeypot_rf.onnx")
        if os.path.exists(model_path):
            sess = ort.InferenceSession(model_path)
            _ML_MODEL = {"type": "onnx", "session": sess}
            logger.info("Modèle ONNX chargé.")
            return _ML_MODEL
    except ImportError:
        logger.debug("onnxruntime non installé.")
    except Exception as e:
        logger.warning(f"Échec chargement ONNX : {e}")

    # Fallback coefficients JSON
    try:
        from bxp_secretsonar.detectors.fallback_model import predict_proba
        _ML_MODEL = {"type": "fallback", "predict_proba": predict_proba}
        logger.info("Modèle fallback (coefficients JSON) chargé.")
        return _ML_MODEL
    except ImportError:
        logger.warning("Fallback model introuvable.")
    except Exception as e:
        logger.warning(f"Échec chargement fallback : {e}")

    _ML_MODEL = {"type": "none"}
    return _ML_MODEL

def compute_ml_score(target_url: str, features: dict) -> Optional[float]:
    """Calcule la probabilité honeypot à partir du modèle ML."""
    model = _load_ml_model()
    if model["type"] == "none":
        return None

    try:
        import numpy as np
    except ImportError:
        logger.warning("numpy non installé, impossible d'utiliser le ML.")
        return None

    # Construire le vecteur de features dans l'ordre attendu
    feature_order = [
        "response_time_ms", "content_length", "num_forms", "num_inputs",
        "num_scripts", "has_honeypot_keywords", "has_fake_error",
        "timing_variance", "missing_standard_headers", "incompatible_headers"
    ]
    x = np.array([[features.get(k, 0) for k in feature_order]], dtype=np.float32)

    try:
        if model["type"] == "onnx":
            input_name = model["session"].get_inputs()[0].name
            proba = model["session"].run(None, {input_name: x})[0]
            return float(proba[0][1])  # probabilité classe 1 (honeypot)
        elif model["type"] == "fallback":
            proba = model["predict_proba"](x)
            return float(proba[0][1])
    except Exception as e:
        logger.warning(f"Erreur inférence ML : {e}")
        return None

def compute_risk_score(target_url: str, passive_signals: list[str], active_signals: list[str],
                      features: dict = None) -> RiskScore:
    """Calcule un score composite pondéré et détermine le niveau de risque."""
    all_signals = passive_signals + active_signals
    if not all_signals:
        return RiskScore(target_url=target_url, composite_score=0.0, risk_level=RiskLevel.LOW)

    # Score heuristique classique
    weighted_sum = sum(SIGNAL_WEIGHTS.get(s, 0.3) for s in all_signals)
    heuristic_score = min(1.0, weighted_sum / max(len(all_signals), 1) * (1 + 0.3 * len(all_signals)))
    heuristic_score = round(min(1.0, heuristic_score), 3)

    # Score ML si disponible
    ml_score = None
    if features:
        ml_score = compute_ml_score(target_url, features)

    # Fusion (moyenne pondérée)
    if ml_score is not None:
        composite = round(0.5 * heuristic_score + 0.5 * ml_score, 3)
    else:
        composite = heuristic_score

    # Niveau de risque
    if composite >= 0.85:
        level = RiskLevel.CRITICAL
    elif composite >= 0.6:
        level = RiskLevel.HIGH
    elif composite >= 0.35:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    return RiskScore(
        target_url=target_url,
        passive_signals=passive_signals,
        active_signals=active_signals,
        composite_score=composite,
        risk_level=level,
    )
