"""Factory des 5 classifieurs du benchmark IDS, sur le même espace de features.

Tous les modèles consomment exactement la même sortie du
``ColumnTransformer`` partagé (voir ``benchmark/preprocessing.py``). Les
hyperparamètres sont fixés par le protocole expérimental (pas de recherche
d'hyperparamètres sur le test set) et ``random_state=42`` est utilisé partout
où applicable pour la reproductibilité.
"""

from __future__ import annotations

from typing import Any

from sklearn.base import BaseEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier

try:
    from xgboost import XGBClassifier
except ImportError as _exc:  # pragma: no cover - dependency guard
    XGBClassifier = None
    _XGBOOST_IMPORT_ERROR = _exc
else:
    _XGBOOST_IMPORT_ERROR = None

#: Noms canoniques des 5 modèles, dans l'ordre où ils sont entraînés/reportés.
MODEL_NAMES: tuple[str, ...] = (
    "random_forest",
    "xgboost",
    "mlp",
    "logistic_regression",
    "knn",
)

#: Alias acceptés (CLI, variable d'environnement NZOYI_IDS_MODEL) -> nom canonique.
MODEL_ALIASES: dict[str, str] = {
    "rf": "random_forest",
    "random_forest": "random_forest",
    "randomforest": "random_forest",
    "xgb": "xgboost",
    "xgboost": "xgboost",
    "mlp": "mlp",
    "neural_net": "mlp",
    "logreg": "logistic_regression",
    "logistic_regression": "logistic_regression",
    "knn": "knn",
    "kneighbors": "knn",
}

RANDOM_STATE = 42


def resolve_model_name(alias: str) -> str:
    """Résout un alias (ex: ``'rf'``, ``'xgb'``) vers un nom canonique.

    Args:
        alias: Nom ou alias de modèle (insensible à la casse).

    Returns:
        Le nom canonique, membre de :data:`MODEL_NAMES`.

    Raises:
        ValueError: Si l'alias n'est pas reconnu.
    """
    key = alias.strip().lower()
    try:
        return MODEL_ALIASES[key]
    except KeyError as exc:
        available = ", ".join(sorted(MODEL_ALIASES))
        raise ValueError(
            f"Modèle inconnu: '{alias}'. Alias disponibles: {available}"
        ) from exc


def get_models(scale_pos_weight: float) -> dict[str, BaseEstimator]:
    """Instancie les 5 estimateurs configurés selon le protocole du benchmark.

    Args:
        scale_pos_weight: ``n_negatifs / n_positifs`` calculé sur le TRAIN
            uniquement, transmis à XGBoost pour compenser le déséquilibre de
            classes (les autres modèles utilisent ``class_weight='balanced'``
            ou une pondération par distance selon leur propre mécanisme).

    Returns:
        Un dict ``{nom_canonique: estimateur_non_entraîné}``.

    Raises:
        RuntimeError: Si xgboost n'est pas installé.
    """
    if XGBClassifier is None:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "xgboost est requis pour le benchmark multi-modèles. "
            "Installe-le via `pip install xgboost`."
        ) from _XGBOOST_IMPORT_ERROR

    models: dict[str, Any] = {
        "random_forest": RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
        "xgboost": XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            tree_method="hist",
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
        "mlp": MLPClassifier(
            hidden_layer_sizes=(128, 64),
            activation="relu",
            solver="adam",
            alpha=1e-4,
            batch_size=256,
            max_iter=200,
            early_stopping=True,
            random_state=RANDOM_STATE,
        ),
        "logistic_regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            C=1.0,
            solver="lbfgs",
            random_state=RANDOM_STATE,
        ),
        "knn": KNeighborsClassifier(
            n_neighbors=5,
            weights="distance",
            n_jobs=-1,
        ),
    }
    return {name: models[name] for name in MODEL_NAMES}
