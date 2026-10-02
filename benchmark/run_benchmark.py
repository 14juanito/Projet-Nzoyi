"""CLI — benchmark multi-modèles de l'IDS anomalie sur le split officiel UNSW-NB15.

Charge séparément ``UNSW_NB15_training-set.csv`` / ``UNSW_NB15_testing-set.csv``,
fitte UN SEUL préprocesseur sur le train, entraîne les 5 modèles de
``benchmark.models``, les évalue sur le test (jamais sur le train), puis
sérialise préprocesseur + modèles + métriques.

Usage::

    python -m benchmark.run_benchmark --data-dir data/ \\
        --models-dir models/ --results-dir results/

Sorties :
    models/preprocessor.joblib
    models/<nom_canonique>.joblib   (un par modèle)
    results/benchmark.json          (métriques complètes + config)
    results/benchmark.csv           (table comparative)
    results/benchmark.md            (table comparative, format mémoire)
    results/config.json             (seeds, hyperparamètres, versions de libs)
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import sklearn
import joblib
import xgboost

from benchmark.data import load_official_split, split_features_target
from benchmark.metrics import evaluate_predictions, timed_fit, timed_predict
from benchmark.models import RANDOM_STATE, get_models
from benchmark.preprocessing import fit_preprocessor, save_preprocessor
from benchmark.report import write_csv, write_json, write_markdown

logger = logging.getLogger("nzoyi.benchmark")

#: Plafond structurel documenté du split officiel UNSW-NB15 — dépassement
#: sensiblement supérieur à surveiller (signe probable de fuite/re-split).
EXPECTED_F1_CEILING = 0.89


def _library_versions() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scikit-learn": sklearn.__version__,
        "xgboost": xgboost.__version__,
        "joblib": joblib.__version__,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir", default="data", help="Répertoire des CSV UNSW-NB15 officiels (défaut: data/)"
    )
    parser.add_argument(
        "--train-filename", default="UNSW_NB15_training-set.csv",
    )
    parser.add_argument(
        "--test-filename", default="UNSW_NB15_testing-set.csv",
    )
    parser.add_argument("--models-dir", default="models", help="Répertoire de sortie des .joblib")
    parser.add_argument("--results-dir", default="results", help="Répertoire de sortie des rapports")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def run(
    data_dir: str,
    train_filename: str,
    test_filename: str,
    models_dir: str,
    results_dir: str,
) -> dict[str, dict[str, Any]]:
    """Exécute le benchmark complet et retourne les résultats par modèle."""
    train_df, test_df = load_official_split(data_dir, train_filename, test_filename)
    logger.info("Train: %d lignes — Test: %d lignes (split officiel, non recombinés)", len(train_df), len(test_df))

    X_train, y_train = split_features_target(train_df, source=train_filename)
    X_test, y_test = split_features_target(test_df, source=test_filename)

    # Préprocesseur UNIQUE, fitté uniquement sur le train.
    preprocessor = fit_preprocessor(X_train)
    X_train_t = preprocessor.transform(X_train)
    X_test_t = preprocessor.transform(X_test)

    models_path = Path(models_dir)
    save_preprocessor(preprocessor, models_path / "preprocessor.joblib")

    n_pos = int((y_train == 1).sum())
    n_neg = int((y_train == 0).sum())
    if n_pos == 0:
        raise ValueError("Aucun échantillon positif (label=1) dans le train — vérifie le CSV.")
    scale_pos_weight = n_neg / n_pos
    logger.info("scale_pos_weight (train) = %.4f (n_neg=%d, n_pos=%d)", scale_pos_weight, n_neg, n_pos)

    models = get_models(scale_pos_weight)
    results: dict[str, dict[str, Any]] = {}
    hyperparams: dict[str, dict[str, Any]] = {}

    for name, model in models.items():
        logger.info("Entraînement %s ...", name)
        training_time_s = timed_fit(model, X_train_t, y_train)

        y_pred, y_proba, latency_ms, throughput = timed_predict(model, X_test_t)
        metrics = evaluate_predictions(y_test.to_numpy(), y_pred, y_proba)
        metrics["training_time_s"] = round(training_time_s, 4)
        metrics["inference_latency_ms_per_sample"] = round(latency_ms, 6)
        metrics["throughput_samples_per_s"] = round(throughput, 2)
        results[name] = metrics
        hyperparams[name] = {k: repr(v) for k, v in model.get_params().items()}

        logger.info(
            "%s — f1=%.4f roc_auc=%.4f fpr=%.4f fnr=%.4f (train=%.2fs, %.4fms/échantillon)",
            name, metrics["f1"], metrics["roc_auc"], metrics["fpr"], metrics["fnr"],
            training_time_s, latency_ms,
        )
        if metrics["f1"] > EXPECTED_F1_CEILING + 0.02:
            logger.warning(
                "%s: F1=%.4f dépasse nettement le plafond structurel attendu "
                "(~%.2f) du split officiel — vérifier l'absence de fuite/re-split.",
                name, metrics["f1"], EXPECTED_F1_CEILING,
            )

        joblib.dump(model, models_path / f"{name}.joblib")

    results_path = Path(results_dir)
    config = {
        "random_state": RANDOM_STATE,
        "data_dir": str(data_dir),
        "train_filename": train_filename,
        "test_filename": test_filename,
        "n_train": len(train_df),
        "n_test": len(test_df),
        "scale_pos_weight": scale_pos_weight,
        "expected_f1_ceiling": EXPECTED_F1_CEILING,
        "hyperparameters": hyperparams,
        "library_versions": _library_versions(),
    }
    write_json(results, config, results_path / "benchmark.json")
    write_csv(results, results_path / "benchmark.csv")
    write_markdown(results, results_path / "benchmark.md")

    results_path.mkdir(parents=True, exist_ok=True)
    with open(results_path / "config.json", "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2, ensure_ascii=False)

    logger.info("Benchmark terminé — résultats dans %s/", results_path)
    return results


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        run(
            data_dir=args.data_dir,
            train_filename=args.train_filename,
            test_filename=args.test_filename,
            models_dir=args.models_dir,
            results_dir=args.results_dir,
        )
    except (FileNotFoundError, ValueError) as exc:
        logger.error(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
