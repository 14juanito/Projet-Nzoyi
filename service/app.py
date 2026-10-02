"""API Flask IDS-ML — sert n'importe lequel des 5 modèles du benchmark.

Déployée sur la VM cible (port 5000, voir ``docs/LAB_SETUP.md``). Le modèle
servi est sélectionné via la variable d'environnement ``NZOYI_IDS_MODEL``
(défaut ``'rf'``) parmi les alias de ``benchmark.models.MODEL_ALIASES`` —
substituer un détecteur pour une campagne de transférabilité Q-Learning ne
nécessite donc de changer qu'une variable d'environnement, sans toucher au
reste du pipeline attaquant.

Contrat de l'endpoint ``POST /predict`` (INCHANGÉ — celui déjà consommé par
``nzoyi.tools.rf_client.RFClient`` et couvert par les tests existants) :

    Entrée  : objet JSON ``{nom_feature: valeur, ...}`` — les colonnes brutes
              UNSW-NB15 attendues par le préprocesseur (voir
              ``nzoyi.tools.rf_features.UNSW_FEATURE_NAMES``).
    Sortie  : ``{"prediction": 0|1, "score": float, "model": str}``.

Lancement local (dev) ::

    NZOYI_IDS_MODEL=xgboost python -m service.app

Déploiement (production, sur la VM cible) ::

    NZOYI_IDS_MODEL=rf gunicorn --bind 0.0.0.0:5000 "service.app:create_app()"
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import pandas as pd
from flask import Flask, jsonify, request

from benchmark.models import resolve_model_name
from benchmark.preprocessing import load_preprocessor

logger = logging.getLogger("nzoyi.service.app")

DEFAULT_MODEL_ALIAS = "rf"
DEFAULT_MODELS_DIR = "models"


def _load_model(models_dir: Path, canonical_name: str) -> Any:
    """Charge ``<models_dir>/<canonical_name>.joblib`` (mêmes erreurs que le préprocesseur)."""
    import joblib

    model_path = models_dir / f"{canonical_name}.joblib"
    if not model_path.is_file():
        raise FileNotFoundError(
            f"Modèle introuvable: '{model_path}'. Lance d'abord "
            "`python -m benchmark.run_benchmark` pour entraîner et sérialiser "
            f"les modèles, ou vérifie NZOYI_IDS_MODEL='{canonical_name}'."
        )
    return joblib.load(model_path)


def create_app(models_dir: str | None = None, model_alias: str | None = None) -> Flask:
    """Application factory — charge préprocesseur + modèle une seule fois au démarrage.

    Args:
        models_dir: Répertoire contenant ``preprocessor.joblib`` et
            ``<modèle>.joblib`` (défaut: env ``NZOYI_MODELS_DIR`` ou ``'models'``).
        model_alias: Alias de modèle à servir (défaut: env ``NZOYI_IDS_MODEL``
            ou ``'rf'``). Voir ``benchmark.models.MODEL_ALIASES``.

    Raises:
        FileNotFoundError: Si le préprocesseur ou le modèle sont absents.
        ValueError: Si ``model_alias`` n'est pas reconnu.
    """
    resolved_dir = Path(models_dir or os.environ.get("NZOYI_MODELS_DIR", DEFAULT_MODELS_DIR))
    resolved_alias = model_alias or os.environ.get("NZOYI_IDS_MODEL", DEFAULT_MODEL_ALIAS)
    canonical_name = resolve_model_name(resolved_alias)

    preprocessor = load_preprocessor(resolved_dir / "preprocessor.joblib")
    model = _load_model(resolved_dir, canonical_name)
    expected_columns: list[str] = list(preprocessor.feature_names_in_)

    logger.info(
        "IDS-ML prêt — modèle='%s' (alias='%s'), %d features attendues",
        canonical_name, resolved_alias, len(expected_columns),
    )

    app = Flask(__name__)
    app.config["MODEL_NAME"] = canonical_name

    @app.route("/health", methods=["GET"])
    def health() -> Any:
        return jsonify({"status": "ok", "model": canonical_name})

    @app.route("/predict", methods=["POST"])
    def predict() -> Any:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON attendu: objet {feature: valeur, ...}"}), 400

        missing = [c for c in expected_columns if c not in payload]
        if missing:
            return jsonify({"error": "Colonnes manquantes", "missing": missing}), 400

        unexpected = [c for c in payload if c not in expected_columns]
        if unexpected:
            return jsonify({"error": "Colonnes inattendues", "unexpected": unexpected}), 400

        try:
            row = pd.DataFrame([[payload[c] for c in expected_columns]], columns=expected_columns)
            X = preprocessor.transform(row)
            proba = model.predict_proba(X)[0]
            prediction = int(proba[1] >= 0.5)
        except Exception as exc:  # défensif : entrée valide en forme mais invalide en valeur
            logger.warning("Échec de prédiction: %s", exc)
            return jsonify({"error": f"Échec de la prédiction: {exc}"}), 400

        return jsonify({"prediction": prediction, "score": float(proba[1]), "model": canonical_name})

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = create_app()
    app.run(host="0.0.0.0", port=5000)


if __name__ == "__main__":
    main()
