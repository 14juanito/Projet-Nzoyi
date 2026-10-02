"""Pipeline de prétraitement UNIQUE, partagé par les 5 modèles du benchmark.

Un seul :class:`~sklearn.compose.ColumnTransformer` est fitté sur le train
UNSW-NB15 et réutilisé tel quel (jamais refitté) pour transformer le test et
pour servir les prédictions en production (API Flask). Cela garantit que les
5 modèles consomment exactement la même représentation numérique et qu'aucune
fuite du test ne peut se produire.

- Catégorielles (``proto``, ``service``, ``state``) -> imputation par mode
  puis ``OneHotEncoder(handle_unknown="ignore")`` (catégories inédites au
  test/en production sont encodées à zéro plutôt que de lever une erreur).
- Numériques -> imputation par médiane puis ``StandardScaler`` (le dataset
  UNSW-NB15 officiel contient quelques valeurs manquantes/mal typées après
  coercition ; l'imputation est un filet de sécurité, la normalisation finale
  reste bien un ``StandardScaler`` comme spécifié).
"""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from benchmark.data import CATEGORICAL_COLS


def build_preprocessor(numeric_cols: list[str], categorical_cols: list[str] | None = None) -> ColumnTransformer:
    """Construit (sans fitter) le ``ColumnTransformer`` partagé.

    Args:
        numeric_cols: Colonnes numériques à standardiser.
        categorical_cols: Colonnes catégorielles à one-hot encoder (défaut:
            ``benchmark.data.CATEGORICAL_COLS``).

    Returns:
        Un ``ColumnTransformer`` non fitté.
    """
    categorical_cols = list(categorical_cols) if categorical_cols is not None else list(CATEGORICAL_COLS)

    numeric_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )
    categorical_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    return ColumnTransformer(
        transformers=[
            ("num", numeric_pipeline, numeric_cols),
            ("cat", categorical_pipeline, categorical_cols),
        ]
    )


def fit_preprocessor(X_train: pd.DataFrame, categorical_cols: list[str] | None = None) -> ColumnTransformer:
    """Construit et fitte le préprocesseur UNIQUEMENT sur le train.

    Args:
        X_train: Features d'entraînement (issues de
            ``benchmark.data.split_features_target``).
        categorical_cols: Voir :func:`build_preprocessor`.

    Returns:
        Le ``ColumnTransformer`` fitté, prêt à transformer train/test/prod.
    """
    categorical_cols = list(categorical_cols) if categorical_cols is not None else list(CATEGORICAL_COLS)
    numeric_cols = [c for c in X_train.columns if c not in categorical_cols]
    preprocessor = build_preprocessor(numeric_cols, categorical_cols)
    preprocessor.fit(X_train)
    return preprocessor


def save_preprocessor(preprocessor: ColumnTransformer, path: str | Path) -> None:
    """Sérialise le préprocesseur fitté via joblib."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(preprocessor, path)


def load_preprocessor(path: str | Path) -> ColumnTransformer:
    """Charge un préprocesseur préalablement fitté et sérialisé.

    Raises:
        FileNotFoundError: Si ``path`` n'existe pas.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(
            f"Préprocesseur introuvable: '{path}'. Lance d'abord "
            "`python -m benchmark.run_benchmark` pour l'entraîner et le "
            "sérialiser."
        )
    return joblib.load(path)
