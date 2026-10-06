#!/usr/bin/env python3
"""
NZOYI — Multi-Agent IDS Resilience Testing Framework

Usage:
    python main.py                          # Mode interactif (réel, eve.json requis)
    python main.py --target 192.168.100.11  # Mode direct (autonome)
    python main.py --target X --mode learn  # Boucle RL directe
    python main.py --test                   # Validation des fondations
    python main.py --dashboard              # Dashboard Streamlit
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import requests

from nzoyi import __version__
from nzoyi.agents.orchestrator import OrchestratorAgent
from nzoyi.core.config import load_profile
from nzoyi.core.ptt import PentestTree
from nzoyi.llm.orchestrator_llm import DEFAULT_PROVIDER, VALID_PROVIDERS
from nzoyi.ui.banner import (
    Color,
    print_banner,
    print_config_box,
    print_result_box,
    print_test_result,
    setup_logging,
)
from nzoyi.ui.interactive import (
    AutonomousRunner,
    DEFAULT_EVE_LOG,
    GuidedRunner,
    InteractiveSession,
    LearningRunner,
    print_section,
    require_eve_log,
)


def _load_dotenv(path: str = ".env") -> None:
    """Load KEY=VALUE pairs from a local .env into os.environ.

    Secrets (e.g. ANTHROPIC_API_KEY) stay in this git-ignored file and never
    touch the source tree. Existing environment variables win over the file so
    an explicit `export` always takes precedence.
    """
    env_file = Path(path)
    if not env_file.is_file():
        return
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"


def _active_llm_provider() -> str:
    """Résout le provider LLM actif depuis l'environnement courant.

    Même repli que :class:`~nzoyi.llm.orchestrator_llm.LLMOrchestrator`
    (défaut/valeur invalide -> ``DEFAULT_PROVIDER``), sans dupliquer la liste
    des providers valides ici — on importe celle de `nzoyi.llm`.
    """
    provider = os.environ.get("NZOYI_LLM_PROVIDER", DEFAULT_PROVIDER)
    return provider if provider in VALID_PROVIDERS else DEFAULT_PROVIDER


def _set_llm_model_override(model: str) -> None:
    """Écrit `model` dans `os.environ` pour ce process, jamais dans `.env`.

    Cible la variable du provider actuellement configuré
    (`NZOYI_OPENAI_COMPAT_MODEL` si `NZOYI_LLM_PROVIDER=openai_compatible`,
    `NZOYI_ANTHROPIC_MODEL` sinon). Si le provider actif est "anthropic", ce
    flag ne bascule JAMAIS vers `openai_compatible` — il écrase seulement le
    modèle Anthropic, ce qui n'a de sens que si `model` est bien un identifiant
    Anthropic valide. On avertit explicitement plutôt que de deviner une
    intention de changement de provider (ça reste le rôle de
    `NZOYI_LLM_PROVIDER` dans `.env`).
    """
    provider = _active_llm_provider()
    if provider == "anthropic":
        print(
            f"  {Color.YELLOW}⚠ --llm-model s'applique au provider actif "
            f"('anthropic') — il ne bascule PAS vers openai_compatible. Pour "
            f"cibler Ollama/OpenRouter, mets NZOYI_LLM_PROVIDER=openai_compatible "
            f"dans .env.{Color.RESET}\n"
        )
        os.environ["NZOYI_ANTHROPIC_MODEL"] = model
    else:
        os.environ["NZOYI_OPENAI_COMPAT_MODEL"] = model


def _prompt_llm_model_menu() -> None:
    """Menu interactif listant les modèles Ollama locaux, pour choisir un run.

    N'est appelé que depuis `main()`, jamais en mode `--test` (aucun test
    automatisé ne doit attendre une saisie). Interroge l'endpoint natif Ollama
    `GET /api/tags` (pas besoin du SDK `openai` pour une simple liste). Si
    Ollama n'est pas lancé, ou qu'aucun modèle n'est installé, ou que la
    saisie est invalide/vide : affiche un message clair et continue avec la
    configuration `.env` par défaut — ne bloque et ne fait jamais échouer le
    run. N'écrit le choix que dans `os.environ` (via `_set_llm_model_override`),
    jamais dans `.env`.
    """
    try:
        response = requests.get(OLLAMA_TAGS_URL, timeout=3)
        response.raise_for_status()
        models = [m["name"] for m in response.json().get("models", [])]
    except requests.RequestException:
        print(
            f"  {Color.DIM}Ollama inatteignable sur {OLLAMA_TAGS_URL} — "
            f"poursuite avec la configuration .env par défaut.{Color.RESET}\n"
        )
        return

    if not models:
        print(
            f"  {Color.DIM}Aucun modèle Ollama local (voir `ollama list`) — "
            f"poursuite avec la configuration .env par défaut.{Color.RESET}\n"
        )
        return

    print(f"\n  {Color.GOLD}Modèles Ollama disponibles :{Color.RESET}")
    for idx, name in enumerate(models, start=1):
        print(f"    {idx}. {name}")

    try:
        choice = input(f"\n  Choix (Entrée pour garder la config .env) : ").strip()
    except (EOFError, KeyboardInterrupt):
        print(f"\n  {Color.DIM}Pas de saisie — configuration .env conservée.{Color.RESET}\n")
        return
    if not choice:
        return

    try:
        selected = models[int(choice) - 1]
    except (ValueError, IndexError):
        print(f"  {Color.DIM}Choix invalide — configuration .env conservée.{Color.RESET}\n")
        return

    print(f"  {Color.GREEN}✓ Modèle sélectionné : {selected}{Color.RESET}\n")
    _set_llm_model_override(selected)


def _save_convergence(convergence: list) -> str:
    os.makedirs("results", exist_ok=True)
    conv_path = "results/convergence.json"
    with open(conv_path, "w", encoding="utf-8") as handle:
        json.dump(convergence, handle, indent=2)
    return conv_path


def run_validation_tests() -> int:
    from tests.test_validation import run_all_tests

    print_banner(__version__)
    print("  Running foundation tests...\n")

    results = run_all_tests()
    passed = sum(1 for ok in results.values() if ok)
    total = len(results)

    for name, ok in results.items():
        print_test_result(name, ok)

    print_result_box("Test Results", {
        "Passed": f"{passed}/{total}",
        "Status": "ALL PASS ✓" if passed == total else "SOME FAILED",
    })
    return 0 if passed == total else 1


def _python_exe() -> str:
    """Prefer project venv Python when available."""
    venv_python = Path(__file__).parent / "venv" / "bin" / "python"
    if venv_python.is_file():
        return str(venv_python)
    return sys.executable


def run_dashboard() -> int:
    app_path = Path(__file__).parent / "nzoyi" / "dashboard" / "app.py"
    subprocess.run(
        [_python_exe(), "-m", "streamlit", "run", str(app_path)],
        check=False,
    )
    return 0


def _build_orchestrator(
    target: str,
    profile_name: str,
    eve_log: str | None,
    use_llm: bool = True,
    use_rf_online: bool = True,
):
    profile = load_profile(profile_name)
    ptt = PentestTree(target=target)
    orchestrator = OrchestratorAgent(
        ptt, profile, eve_log=eve_log, use_llm=use_llm, use_rf_online=use_rf_online
    )
    return profile, ptt, orchestrator


def run_train_offline(model_path: str, cycles: int) -> int:
    """Offline pre-training phase against the RF oracle (network-free)."""
    from nzoyi.training.offline import pretrain

    print_banner(__version__)
    setup_logging()
    print(f"  🧠 Pré-entraînement offline (oracle RF) — modèle: {model_path}\n")
    try:
        learner = pretrain(model_path, episodes=cycles)
    except FileNotFoundError as exc:
        print(f"  {Color.RED}✗ {exc}{Color.RESET}\n")
        return 1
    print_result_box("Pré-entraînement terminé", {
        "Épisodes": cycles,
        "Itérations Q": learner.iterations,
        "Epsilon final": f"{learner.epsilon:.4f}",
        "Q-table": "results/qtable_offline.json",
    })
    return 0


def run_finetune(
    qtable_path: str,
    target: str,
    profile_name: str,
    eve_log: str | None,
    cycles: int,
    use_llm: bool,
    use_rf_online: bool = True,
) -> int:
    """Online fine-tuning phase against a real Suricata IDS."""
    _, _, orchestrator = _build_orchestrator(
        target, profile_name, eve_log, use_llm, use_rf_online=use_rf_online
    )

    print_banner(__version__)
    setup_logging()
    print(f"  🎯 Affinage online (Suricata réel) — warm Q-table: {qtable_path}\n")
    try:
        result = orchestrator.finetune_online(qtable_path, cycles=cycles)
    except FileNotFoundError as exc:
        print(f"  {Color.RED}✗ Q-table introuvable: {exc}{Color.RESET}\n")
        return 1
    print_result_box("Affinage online terminé", {
        "Cycles": result["cycles"],
        "Détection online": f"{result['online_final_detection_rate']:.1%}",
        "Détection offline": (
            f"{result['offline_final_detection_rate']:.1%}"
            if result["offline_final_detection_rate"] is not None else "N/A"
        ),
        "Sim-to-real gap": (
            f"{result['sim_to_real_gap']:+.4f}"
            if result["sim_to_real_gap"] is not None else "N/A"
        ),
    })
    return 0


def run_interactive(use_llm: bool = True, use_rf_online: bool = True) -> int:
    """Interactive mode — the default user experience."""
    session = InteractiveSession(version=__version__)
    params = session.start()
    if not params:
        return 0

    profile, ptt, orchestrator = _build_orchestrator(
        params["target"], params["profile"], params.get("eve_log"),
        use_llm=use_llm, use_rf_online=use_rf_online,
    )
    setup_logging()
    print_section("EXÉCUTION")

    mode = params["mode"]

    if mode == "guided":
        runner = GuidedRunner()
        runner.bind_evaluation(orchestrator.evaluation)
        executed = 0
        for agent in orchestrator.pipeline:
            result = runner.run_agent_guided(
                agent, dry_run=False, eve_log=params.get("eve_log")
            )
            if result is None:
                break
            if not result.get("skipped"):
                executed += 1
        summary = ptt.summary()
        print_result_box("Résumé du pipeline", {
            "Cible": params["target"],
            "Nœuds PTT": summary["node_count"],
            "Agents exécutés": executed,
        })

    elif mode == "autonomous":
        runner = AutonomousRunner()
        runner.run_pipeline(
            orchestrator, dry_run=False, eve_log=params.get("eve_log")
        )
        summary = ptt.summary()
        orchestrator.ptt.add(orchestrator.name, "pipeline_complete", summary)
        print_result_box("Pipeline autonome terminé", {
            "Cible": params["target"],
            "Nœuds PTT": summary["node_count"],
            "Agents": len(summary["agents"]),
            "Profil": params["profile"],
        })

    elif mode == "learning":
        runner = LearningRunner()
        learn_results = runner.run(
            orchestrator,
            cycles=params["cycles"],
            dry_run=False,
            eve_log=params.get("eve_log"),
        )
        conv_path = _save_convergence(learn_results["convergence"])
        print(f"  📊 Données de convergence sauvées → {conv_path}\n")

    return 0


def run_direct(
    target: str,
    profile_name: str,
    eve_log: str | None,
    mode: str,
    cycles: int,
    use_llm: bool = True,
    use_rf_online: bool = True,
) -> int:
    """Direct CLI mode (non-interactive) — réel uniquement."""
    eve_path = eve_log or DEFAULT_EVE_LOG
    if not require_eve_log(eve_path):
        return 1

    profile, ptt, orchestrator = _build_orchestrator(
        target, profile_name, eve_path, use_llm=use_llm, use_rf_online=use_rf_online
    )

    print_banner(__version__)
    setup_logging()
    print_config_box(
        target=target,
        profile=f"{profile.name} — {profile.description}",
        mode=mode if mode != "pipeline" else "live",
        cycles=cycles if mode == "learn" else None,
        eve_log=eve_path,
    )

    if mode == "learn":
        runner = LearningRunner()
        learn_results = runner.run(
            orchestrator, cycles=cycles, dry_run=False, eve_log=eve_path
        )
        conv_path = _save_convergence(learn_results["convergence"])
        print(f"  📊 Données de convergence sauvées → {conv_path}\n")
        return 0

    runner = AutonomousRunner()
    runner.run_pipeline(orchestrator, dry_run=False, eve_log=eve_path)
    summary = ptt.summary()
    orchestrator.ptt.add(orchestrator.name, "pipeline_complete", summary)
    print_result_box("Pipeline terminé", {
        "Cible": target,
        "Nœuds PTT": summary["node_count"],
        "Agents": len(summary["agents"]),
    })
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NZOYI — adaptive multi-agent IDS evasion framework",
    )
    parser.add_argument("--test", action="store_true", help="Run validation tests")
    parser.add_argument("--dashboard", action="store_true", help="Launch Streamlit dashboard")
    parser.add_argument("--target", default=None, help="Target IP (skips interactive setup)")
    parser.add_argument(
        "--profile",
        default="stealth",
        choices=["default", "stealth", "aggressive"],
    )
    parser.add_argument(
        "--mode",
        default="pipeline",
        choices=["pipeline", "learn"],
        help="Direct-mode execution: single pipeline or RL learning loop",
    )
    parser.add_argument("--cycles", type=int, default=100, help="Learning loop iterations")
    parser.add_argument(
        "--eve-log",
        default=DEFAULT_EVE_LOG,
        help=f"Chemin vers eve.json (passerelle locale, défaut: {DEFAULT_EVE_LOG})",
    )
    parser.add_argument(
        "--train-offline",
        metavar="MODEL_PATH",
        default=None,
        help="Pré-entraîne le Q-Learner offline avec un modèle RF (joblib)",
    )
    parser.add_argument(
        "--finetune",
        metavar="QTABLE_PATH",
        default=None,
        help="Affine online une Q-table offline contre Suricata réel",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Force le fallback heuristique (reproductibilité hors-ligne)",
    )
    parser.add_argument(
        "--llm-model",
        default=None,
        help="Surcharge le modèle LLM pour ce run (ex: deepseek-r1:8b) sans modifier .env",
    )
    parser.add_argument(
        "--no-rf-online",
        action="store_true",
        help="Désactive le signal RF online (endpoint Flask) — évaluation Suricata seule",
    )
    parser.add_argument("--version", action="version", version=f"NZOYI {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    _load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dashboard:
        return run_dashboard()

    if args.test:
        return run_validation_tests()

    if args.llm_model:
        _set_llm_model_override(args.llm_model)
    elif not args.no_llm:
        _prompt_llm_model_menu()

    try:
        if args.train_offline:
            return run_train_offline(args.train_offline, cycles=args.cycles)

        if args.finetune:
            eve_path = args.eve_log or DEFAULT_EVE_LOG
            if not require_eve_log(eve_path):
                return 1
            return run_finetune(
                qtable_path=args.finetune,
                target=args.target or "192.168.100.11",
                profile_name=args.profile,
                eve_log=eve_path,
                cycles=args.cycles,
                use_llm=not args.no_llm,
                use_rf_online=not args.no_rf_online,
            )

        if args.target:
            return run_direct(
                target=args.target,
                profile_name=args.profile,
                eve_log=args.eve_log,
                mode=args.mode,
                cycles=args.cycles,
                use_llm=not args.no_llm,
                use_rf_online=not args.no_rf_online,
            )
        return run_interactive(use_llm=not args.no_llm, use_rf_online=not args.no_rf_online)
    except KeyboardInterrupt:
        print(f"\n\n  {Color.DIM}Interrompu. À bientôt.{Color.RESET}\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
