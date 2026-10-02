"""Calcul des métriques de détection, timing inclus, pour un modèle évalué.

``malicious`` (label=1) est la classe positive partout. Toutes les métriques
sont calculées sur le split de test officiel UNSW-NB15, jamais sur le train.
"""

from __future__ import annotations

import time
from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def timed_fit(model: Any, X_train: Any, y_train: Any) -> float:
    """Entraîne ``model`` en place et retourne le temps écoulé en secondes."""
    start = time.perf_counter()
    model.fit(X_train, y_train)
    return time.perf_counter() - start


def timed_predict(model: Any, X_test: Any) -> tuple[np.ndarray, np.ndarray, float, float]:
    """Prédit sur ``X_test`` en mesurant latence/débit d'inférence.

    Returns:
        ``(y_pred, y_proba, latency_ms_per_sample, throughput_samples_per_s)``
        où ``y_proba`` est la probabilité de la classe positive (malicious).
    """
    n_samples = X_test.shape[0]

    start = time.perf_counter()
    y_pred = model.predict(X_test)
    proba_matrix = model.predict_proba(X_test)
    elapsed = time.perf_counter() - start

    y_proba = proba_matrix[:, 1]
    latency_ms_per_sample = (elapsed / n_samples) * 1000.0 if n_samples else 0.0
    throughput = n_samples / elapsed if elapsed > 0 else float("inf")
    return y_pred, y_proba, latency_ms_per_sample, throughput


def evaluate_predictions(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
) -> dict[str, Any]:
    """Calcule toutes les métriques de détection (malicious=1=positif).

    Args:
        y_true: Labels réels (0/1).
        y_pred: Labels prédits (0/1).
        y_proba: Probabilité prédite de la classe positive.

    Returns:
        Dict avec accuracy, precision, recall, f1, roc_auc, fpr, fnr et la
        matrice de confusion (tn, fp, fn, tp).
    """
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_proba)),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }
