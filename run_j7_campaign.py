#!/usr/bin/env python3
"""CLI — comparatif J7 du panel LLM stratégique (Ollama local vs OpenRouter vs Claude).

Même scénario NZOYI complet (même cible, mêmes ports/CVE découverts), rejoué
une fois par backend du panel. Le panel est découvert dynamiquement (jamais
de nom de modèle codé en dur) via :mod:`nzoyi.llm.panel_discovery` : les
modèles Ollama locaux via ``ollama list``/``/api/tags``, Claude et
OpenRouter uniquement si leur clé API respective est présente dans
l'environnement — un backend absent ne bloque jamais la campagne.

Réutilise le pipeline NZOYI existant tel quel (``main.py::_build_orchestrator``
+ :class:`~nzoyi.ui.interactive.LearningRunner`) : le panel pilote les 4
rôles LLM (stratégique/triage/raffinement/rationale) via les variables
d'environnement que lit déjà :func:`~nzoyi.llm.backend_resolver.resolve_backend`
(J1/J2/J5/J6) — zéro duplication de cette logique, zéro modification de
``nzoyi/agents/evasion.py`` ni ``nzoyi/rl/qlearning.py``.

Usage::

    python run_j7_campaign.py --target 192.168.100.14 --profile stealth --cycles 8

Sorties :
    results/j7_llm_panel_comparison.json
    results/j7_llm_panel_comparison.csv
    results/j7_llm_panel_comparison.md
    docs/evidence/j7/ptt/<label>.ptt.json   (un par backend)
    docs/evidence/j7/smoke_test.json
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from main import _build_orchestrator, _load_dotenv, _require_ids_log
from nzoyi.llm.panel_discovery import PanelEntry, build_backend, discover_panel, env_overrides_for
from nzoyi.llm.vuln_triage_llm import VulnTriageLLM
from nzoyi.ui.interactive import LearningRunner

logger = logging.getLogger("nzoyi.run_j7_campaign")

RESULTS_DIR = Path("results")
EVIDENCE_DIR = Path("docs/evidence/j7")

#: Findings synthétiques pour le smoke test (Task 2) — jamais utilisés pour
#: la campagne réelle (Task 3), uniquement pour vérifier qu'un backend
#: répond et que sa sortie passe `_sanitize()` avant d'investir un run complet.
_SMOKE_FINDINGS = [
    {
        "cve_id": "CVE-TEST-0001",
        "severity": "high",
        "type": "smoke_test",
        "port": 9999,
        "service": "smoke",
    }
]


def _safe_filename(label: str) -> str:
    """Nom de fichier sûr à partir d'un label de panel (ex. ``ollama:hf.co/...``)."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_")


def smoke_test(entry: PanelEntry) -> dict[str, Any]:
    """Task 2 — appel minimal confirmant qu'un backend répond et que sa
    sortie passe le parsing JSON réel (``VulnTriageLLM._sanitize``), avant
    d'investir un run complet contre la cible.

    N'utilise jamais `entry.api_key` dans le résultat retourné (seul le
    label/provider/model, jamais le secret, atteignent le rapport).
    """
    backend = build_backend(entry)
    if backend is None:
        return {
            "label": entry.label,
            "provider": entry.provider,
            "model": entry.model,
            "ok": False,
            "latency_s": None,
            "fallback_reason": "backend_construction_failed",
        }

    triage = VulnTriageLLM(enabled=True, backend=backend)
    triage.decide(list(_SMOKE_FINDINGS))  # decide() ne lève jamais (repli interne).
    return {
        "label": entry.label,
        "provider": entry.provider,
        "model": entry.model,
        "ok": triage.last_fallback_reason is None,
        "latency_s": (
            round(triage.last_latency_s, 3) if triage.last_latency_s is not None else None
        ),
        "fallback_reason": triage.last_fallback_reason,
    }


def _set_panel_env(entry: PanelEntry) -> dict[str, str | None]:
    """Positionne les variables d'environnement pour que le panel entier
    (stratégique/triage/raffinement/rationale) résolve CETTE entrée pour la
    durée d'un run. Retourne les valeurs précédentes, pour restauration
    systématique (même en cas d'exception) — jamais d'environnement laissé
    incohérent entre deux backends de la campagne."""
    overrides = env_overrides_for(entry)
    previous = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    return previous


def _restore_env(previous: dict[str, str | None]) -> None:
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _llm_role_stats(ptt, kind: str) -> dict[str, Any]:
    """Agrège latence/fallback pour tous les appels d'un rôle LLM (un kind de
    noeud PTT) sur l'ensemble d'un run — jamais d'exclusion silencieuse d'un
    échec : un appel sans noeud du tout (backend jamais même tenté avant la
    boucle, ex. aucun finding à trier) est distingué d'un appel tenté et
    retombé en fallback."""
    nodes = ptt.find(kind=kind)
    latencies = [n.data.get("latency_s") for n in nodes if n.data.get("latency_s") is not None]
    fallbacks = [n.data.get("fallback_reason") for n in nodes if n.data.get("fallback_reason")]
    return {
        "calls": len(nodes),
        "fallback_count": len(fallbacks),
        "fallback_reasons": sorted(set(fallbacks)),
        "latency_avg_s": round(sum(latencies) / len(latencies), 3) if latencies else None,
        "latency_max_s": round(max(latencies), 3) if latencies else None,
    }


def run_one_backend(
    entry: PanelEntry,
    target: str,
    profile_name: str,
    eve_log: str,
    cycles: int,
    use_rf_online: bool,
) -> dict[str, Any]:
    """Task 3 — rejoue le scénario NZOYI complet pour UN backend du panel.

    Retourne un dict de métriques jamais partiel en cas d'échec : un run qui
    plante est rapporté avec ``"error"`` rempli plutôt qu'absent du
    comparatif final (contrainte : ne jamais exclure silencieusement un
    backend en échec de la moyenne/du rapport)."""
    previous_env = _set_panel_env(entry)
    t0 = time.time()
    try:
        profile, ptt, orchestrator = _build_orchestrator(
            target,
            profile_name,
            eve_log,
            use_llm=True,
            use_rf_online=use_rf_online,
            ids_backend="suricata",
        )
        runner = LearningRunner()
        learn_results = runner.run(orchestrator, cycles=cycles, dry_run=False, eve_log=eve_log)
        duration_s = time.time() - t0

        safe_label = _safe_filename(entry.label)
        EVIDENCE_DIR.joinpath("ptt").mkdir(parents=True, exist_ok=True)
        ptt_dest = EVIDENCE_DIR / "ptt" / f"{safe_label}.ptt.json"
        if RESULTS_DIR.joinpath("ptt.json").is_file():
            shutil.copy(RESULTS_DIR / "ptt.json", ptt_dest)

        return {
            "label": entry.label,
            "provider": entry.provider,
            "model": entry.model,
            "error": None,
            "aborted": bool(learn_results.get("aborted", False)),
            "duration_s": round(duration_s, 2),
            "cycles": cycles,
            "final_detection_rate": learn_results.get("final_detection_rate"),
            "recon_open_ports": [p.get("port") for p in ptt.get_recon_results()],
            "vuln_triage": _llm_role_stats(ptt, "llm_raw_response_vuln"),
            "attack_priority": _llm_role_stats(ptt, "llm_raw_response_attack"),
            "evaluation_rationale": _llm_role_stats(ptt, "llm_raw_response_evaluation"),
            "ptt_evidence_path": str(ptt_dest),
        }
    except Exception as exc:  # noqa: BLE001 - un backend qui plante doit rester dans le rapport.
        logger.error("Run complet échoué pour %s", entry.label, exc_info=True)
        return {
            "label": entry.label,
            "provider": entry.provider,
            "model": entry.model,
            "error": f"{type(exc).__name__}: {exc}",
            "duration_s": round(time.time() - t0, 2),
        }
    finally:
        _restore_env(previous_env)


def write_reports(results: list[dict[str, Any]]) -> None:
    RESULTS_DIR.mkdir(exist_ok=True)

    json_path = RESULTS_DIR / "j7_llm_panel_comparison.json"
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, ensure_ascii=False, default=str)

    csv_path = RESULTS_DIR / "j7_llm_panel_comparison.csv"
    fieldnames = [
        "label", "provider", "model", "error", "aborted", "duration_s", "cycles",
        "final_detection_rate",
        "vuln_triage_fallback_rate", "attack_priority_fallback_rate",
        "evaluation_rationale_fallback_rate",
        "vuln_triage_latency_avg_s", "attack_priority_latency_avg_s",
        "evaluation_rationale_latency_avg_s",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            def _rate(role: str) -> float | None:
                stats = r.get(role)
                if not stats or not stats.get("calls"):
                    return None
                return round(stats["fallback_count"] / stats["calls"], 3)

            def _lat(role: str) -> float | None:
                stats = r.get(role)
                return stats.get("latency_avg_s") if stats else None

            writer.writerow({
                "label": r["label"],
                "provider": r.get("provider"),
                "model": r.get("model"),
                "error": r.get("error") or r.get("absent_reason"),
                "aborted": r.get("aborted"),
                "duration_s": r.get("duration_s"),
                "cycles": r.get("cycles"),
                "final_detection_rate": r.get("final_detection_rate"),
                "vuln_triage_fallback_rate": _rate("vuln_triage"),
                "attack_priority_fallback_rate": _rate("attack_priority"),
                "evaluation_rationale_fallback_rate": _rate("evaluation_rationale"),
                "vuln_triage_latency_avg_s": _lat("vuln_triage"),
                "attack_priority_latency_avg_s": _lat("attack_priority"),
                "evaluation_rationale_latency_avg_s": _lat("evaluation_rationale"),
            })

    md_path = RESULTS_DIR / "j7_llm_panel_comparison.md"
    lines = [
        "# J7 — Comparatif panel LLM stratégique",
        "",
        "| Modèle | Statut | Durée | Détection finale | Fallback triage | "
        "Fallback attack | Fallback rationale |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        if r.get("status") == "absent":
            lines.append(
                f"| {r['label']} | ⬜ absent ({r.get('absent_reason')}) | — | — | — | — | — |"
            )
            continue
        if r.get("error"):
            lines.append(f"| {r['label']} | ❌ erreur: {r['error']} | — | — | — | — | — |")
            continue
        status = "⚠️ recon vide (abort)" if r.get("aborted") else "✅"

        def _fmt_rate(role: str) -> str:
            stats = r.get(role)
            if not stats or not stats.get("calls"):
                return "n/a"
            return f"{stats['fallback_count']}/{stats['calls']}"

        rate = r.get("final_detection_rate")
        cycles = r.get("cycles")
        # Toujours le nombre d'épisodes à côté du taux (contrainte J7) : un
        # écart entre backends sur 8 cycles peut n'être que du bruit
        # d'exploration ε-greedy, jamais à sur-interpréter sans ce contexte.
        if isinstance(rate, (int, float)) and cycles:
            n_detected = round(rate * cycles)
            rate_str = f"{rate:.1%} ({n_detected}/{cycles})"
        else:
            rate_str = "n/a"
        lines.append(
            f"| {r['label']} | {status} | {r.get('duration_s')}s | {rate_str} | "
            f"{_fmt_rate('vuln_triage')} | {_fmt_rate('attack_priority')} | "
            f"{_fmt_rate('evaluation_rationale')} |"
        )

    uncensored_labels = {"ollama:hf.co/mradermacher/Dolphin3.0-Llama3.1-8B-GGUF:latest"}
    testable_results = [r for r in results if r.get("status") != "absent"]
    uncensored_rows = [
        r for r in testable_results if r["label"] in uncensored_labels and not r.get("error")
    ]
    other_rows = [
        r for r in testable_results
        if r["label"] not in uncensored_labels and not r.get("error") and not r.get("aborted")
    ]
    if uncensored_rows and other_rows:
        lines.append("")
        lines.append("## Observation — modèles non censurés")
        for r in uncensored_rows:
            total_calls = sum(
                r[role]["calls"] for role in ("vuln_triage", "attack_priority", "evaluation_rationale")
            )
            total_fallbacks = sum(
                r[role]["fallback_count"]
                for role in ("vuln_triage", "attack_priority", "evaluation_rationale")
            )
            own_rate = (total_fallbacks / total_calls) if total_calls else None
            other_calls = sum(
                o[role]["calls"]
                for o in other_rows
                for role in ("vuln_triage", "attack_priority", "evaluation_rationale")
            )
            other_fallbacks = sum(
                o[role]["fallback_count"]
                for o in other_rows
                for role in ("vuln_triage", "attack_priority", "evaluation_rationale")
            )
            other_rate = (other_fallbacks / other_calls) if other_calls else None
            if own_rate is not None and other_rate is not None:
                lines.append(
                    f"- `{r['label']}` : taux de fallback global "
                    f"{own_rate:.1%} vs {other_rate:.1%} pour le reste du panel "
                    f"({'écart notable' if abs(own_rate - other_rate) > 0.15 else 'comparable'}, "
                    "jamais traité comme un échec en soi)."
                )

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Rapports écrits: %s, %s, %s", json_path, csv_path, md_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NZOYI J7 — comparatif panel LLM")
    parser.add_argument("--target", required=True, help="IP de la cible Suricata vérifiée")
    parser.add_argument("--profile", default="stealth", choices=["default", "stealth", "aggressive"])
    parser.add_argument("--cycles", type=int, default=8)
    parser.add_argument("--eve-log", required=True, help="Chemin du mirror local de eve.json")
    parser.add_argument(
        "--no-rf-online", action="store_true",
        help="Désactive le signal RF online (cible J7 sans endpoint Flask).",
    )
    parser.add_argument(
        "--skip-smoke-test", action="store_true",
        help="Ne pas exécuter le smoke test (Task 2) avant la campagne (Task 3).",
    )
    parser.add_argument(
        "--exclude-label", action="append", default=[],
        metavar="LABEL",
        help=(
            "Label de panel (voir discover_panel()) à retirer de ce run, rapporté "
            "comme 'absent' plutôt que testé — pour un backend découvert dont la "
            "clé API présente dans l'environnement est connue non fonctionnelle "
            "(placeholder), jamais pour masquer un échec réel. Répétable."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    _load_dotenv(".env")

    parser = build_parser()
    args = parser.parse_args(argv)

    if not _require_ids_log(args.eve_log, "suricata"):
        return 1

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    panel = discover_panel()
    if not panel:
        print("Aucun backend LLM disponible (ni Ollama local, ni OpenRouter, ni Claude) — abandon.")
        return 1

    print(f"Panel découvert ({len(panel)} backend(s)) : {[e.label for e in panel]}")

    results: list[dict[str, Any]] = []
    # Claude n'est jamais "en échec" quand sa clé est absente — il n'a jamais
    # été tenté. Explicitement signalé "absent" plutôt que simplement omis du
    # rapport, même s'il n'a pas été découvert par discover_panel().
    if not any(e.provider == "anthropic" for e in panel):
        print("  ⬜ claude absent (ANTHROPIC_API_KEY non présente) — rapporté 'absent'.")
        results.append({
            "label": "claude",
            "provider": "anthropic",
            "model": None,
            "status": "absent",
            "absent_reason": "ANTHROPIC_API_KEY absente de l'environnement (pas de crédits)",
        })

    excluded_labels = set(args.exclude_label)
    if excluded_labels:
        kept: list[PanelEntry] = []
        for entry in panel:
            if entry.label in excluded_labels:
                print(f"  ⬜ {entry.label} exclu explicitement (--exclude-label) — rapporté 'absent'.")
                results.append({
                    "label": entry.label,
                    "provider": entry.provider,
                    "model": entry.model,
                    "status": "absent",
                    "absent_reason": "exclu explicitement (--exclude-label) — clé API connue non fonctionnelle",
                })
            else:
                kept.append(entry)
        panel = kept

    # Task 2 (smoke test) puis Task 3 (campagne) sont entrelacés PAR backend,
    # jamais en deux passes séparées sur tout le panel : un modèle Ollama
    # local est déchargé de la RAM après `OLLAMA_KEEP_ALIVE` (5 min par
    # défaut) — tester tout le panel d'abord, puis le rejouer en entier,
    # forcerait un second rechargement à froid de chaque modèle. Entrelacer
    # garantit que la campagne réelle d'un backend profite du modèle encore
    # chaud juste après son propre smoke test.
    smoke_results: list[dict[str, Any]] = []
    for entry in panel:
        if not args.skip_smoke_test:
            smoke = smoke_test(entry)
            smoke_results.append(smoke)
            status = "OK" if smoke["ok"] else f"ÉCHEC ({smoke['fallback_reason']})"
            print(f"  smoke [{entry.label}]: {status} — {smoke['latency_s']}s")
            if not smoke["ok"]:
                print(f"  ⚠ smoke test échoué pour {entry.label} — campagne réelle tentée quand même.")

        print(f"\n=== Campagne réelle — {entry.label} ===")
        result = run_one_backend(
            entry,
            target=args.target,
            profile_name=args.profile,
            eve_log=args.eve_log,
            cycles=args.cycles,
            use_rf_online=not args.no_rf_online,
        )
        results.append(result)
        if result.get("error"):
            print(f"  ❌ échec: {result['error']}")
        else:
            print(
                f"  ✅ détection finale {result.get('final_detection_rate')}, "
                f"{result.get('duration_s')}s"
            )

    if smoke_results:
        (EVIDENCE_DIR / "smoke_test.json").write_text(
            json.dumps(smoke_results, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    write_reports(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
