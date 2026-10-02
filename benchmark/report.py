"""Sérialisation des résultats du benchmark (JSON / CSV / Markdown)."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

#: Colonnes du tableau comparatif, dans l'ordre d'affichage.
REPORT_COLUMNS: tuple[str, ...] = (
    "model",
    "accuracy",
    "precision",
    "recall",
    "f1",
    "roc_auc",
    "fpr",
    "fnr",
    "training_time_s",
    "inference_latency_ms_per_sample",
    "throughput_samples_per_s",
)


def _row_for(name: str, metrics: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {"model": name}
    for col in REPORT_COLUMNS[1:]:
        value = metrics.get(col)
        row[col] = round(value, 6) if isinstance(value, float) else value
    return row


def write_json(results: dict[str, dict[str, Any]], config: dict[str, Any], path: str | Path) -> None:
    """Écrit ``results/benchmark.json`` (toutes les métriques + config)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"config": config, "results": results}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def write_csv(results: dict[str, dict[str, Any]], path: str | Path) -> None:
    """Écrit ``results/benchmark.csv`` — une ligne par modèle."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(REPORT_COLUMNS))
        writer.writeheader()
        for name, metrics in results.items():
            writer.writerow(_row_for(name, metrics))


def write_markdown(results: dict[str, dict[str, Any]], path: str | Path) -> None:
    """Écrit ``results/benchmark.md`` — table comparative prête pour le mémoire."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    header = "| " + " | ".join(REPORT_COLUMNS) + " |"
    separator = "| " + " | ".join("---" for _ in REPORT_COLUMNS) + " |"
    lines = [
        "# Benchmark IDS multi-modèles — UNSW-NB15 (split officiel)",
        "",
        header,
        separator,
    ]
    for name, metrics in results.items():
        row = _row_for(name, metrics)
        cells = [str(row[col]) for col in REPORT_COLUMNS]
        lines.append("| " + " | ".join(cells) + " |")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
