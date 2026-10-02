"""Chargement du split officiel UNSW-NB15 (train/test), sans re-split.

Contrainte méthodologique non négociable : ``UNSW_NB15_training-set.csv`` et
``UNSW_NB15_testing-set.csv`` sont chargés SÉPARÉMENT et ne doivent JAMAIS
être recombinés ni re-splittés. La cible est la colonne binaire ``label``
(0=benign, 1=malicious) ; ``id`` (identifiant de ligne) et ``attack_cat``
(catégorie d'attaque, dérivée de la cible → fuite) sont retirés des features.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

#: Colonnes catégorielles UNSW-NB15 encodées via OneHotEncoder.
CATEGORICAL_COLS: tuple[str, ...] = ("proto", "service", "state")

#: Colonne identifiant de ligne — aucune valeur prédictive, à exclure.
ID_COL = "id"

#: Colonne catégorie d'attaque — dérivée de la cible, fuite si conservée.
LEAKAGE_COL = "attack_cat"

#: Colonne cible binaire (0=benign, 1=malicious).
TARGET_COL = "label"

DEFAULT_TRAIN_FILENAME = "UNSW_NB15_training-set.csv"
DEFAULT_TEST_FILENAME = "UNSW_NB15_testing-set.csv"


def _read_csv(path: Path) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(
            f"Fichier UNSW-NB15 introuvable: '{path}'. Télécharge le split "
            "officiel (training-set / testing-set) depuis "
            "https://research.unsw.edu.au/projects/unsw-nb15-dataset et "
            f"place-le à cet emplacement (ou passe --data-dir)."
        )
    return pd.read_csv(path, low_memory=False)


def load_official_split(
    data_dir: str | Path,
    train_filename: str = DEFAULT_TRAIN_FILENAME,
    test_filename: str = DEFAULT_TEST_FILENAME,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Charge séparément les CSV officiels d'entraînement et de test UNSW-NB15.

    Args:
        data_dir: Répertoire contenant les deux fichiers CSV.
        train_filename: Nom du fichier d'entraînement officiel.
        test_filename: Nom du fichier de test officiel.

    Returns:
        ``(train_df, test_df)`` — deux DataFrames indépendants, jamais
        recombinés ni re-splittés en aval.

    Raises:
        FileNotFoundError: Si l'un des deux fichiers est absent.
    """
    base = Path(data_dir)
    train_df = _read_csv(base / train_filename)
    test_df = _read_csv(base / test_filename)
    return train_df, test_df


def _validate_columns(df: pd.DataFrame, *, source: str) -> None:
    if TARGET_COL not in df.columns:
        raise ValueError(
            f"Colonne cible '{TARGET_COL}' absente de {source}. "
            f"Colonnes trouvées: {sorted(df.columns)}"
        )
    missing_categorical = [c for c in CATEGORICAL_COLS if c not in df.columns]
    if missing_categorical:
        raise ValueError(
            f"Colonnes catégorielles attendues absentes de {source}: "
            f"{missing_categorical}. Colonnes trouvées: {sorted(df.columns)}"
        )


def split_features_target(df: pd.DataFrame, *, source: str = "dataframe") -> tuple[pd.DataFrame, pd.Series]:
    """Sépare features (X) et cible (y), en retirant les colonnes de fuite.

    Retire ``id`` (identifiant, non prédictif) et ``attack_cat`` (dérivée de
    la cible → fuite) des features. Les colonnes numériques restantes sont
    coercées via ``pd.to_numeric`` (le dataset UNSW-NB15 officiel contient des
    valeurs mal typées dans quelques colonnes) ; les valeurs non convertibles
    deviennent NaN et sont gérées par l'imputer du pipeline de prétraitement.

    Args:
        df: DataFrame brut chargé depuis un CSV UNSW-NB15.
        source: Nom du fichier/source, pour des messages d'erreur clairs.

    Returns:
        ``(X, y)`` où ``y`` est la colonne ``label`` castée en ``int``.

    Raises:
        ValueError: Si ``label`` ou une colonne catégorielle attendue manque.
    """
    _validate_columns(df, source=source)

    y = df[TARGET_COL].astype(int)
    drop_cols = [c for c in (ID_COL, LEAKAGE_COL, TARGET_COL) if c in df.columns]
    X = df.drop(columns=drop_cols).copy()

    numeric_cols = [c for c in X.columns if c not in CATEGORICAL_COLS]
    for col in numeric_cols:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    return X, y
