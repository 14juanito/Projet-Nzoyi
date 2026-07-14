#!/usr/bin/env python3
"""
NZOYI — Multi-Agent IDS Resilience Testing Framework

Usage:
    python main.py                          # Mode interactif (par défaut)
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

from nzoyi import __version__
from nzoyi.agents.orchestrator import OrchestratorAgent
from nzoyi.core.config import load_profile
from nzoyi.core.ptt import PentestTree
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
    GuidedRunner,
    InteractiveSession,
    LearningRunner,
    print_section,
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
):
    profile = load_profile(profile_name)
    ptt = PentestTree(target=target)
    orchestrator = OrchestratorAgent(ptt, profile, eve_log=eve_log, use_llm=use_llm)
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
) -> int:
    """Online fine-tuning phase against a real Suricata IDS."""
    _, _, orchestrator = _build_orchestrator(target, profile_name, eve_log, use_llm)

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


def run_interactive(use_llm: bool = True) -> int:
    """Interactive mode — the default user experience."""
    session = InteractiveSession(version=__version__)
    params = session.start()
    if not params:
        return 0

    profile, ptt, orchestrator = _build_orchestrator(
        params["target"], params["profile"], params.get("eve_log"), use_llm=use_llm
    )
    setup_logging()
    print_section("EXÉCUTION")

    mode = params["mode"]

    if mode == "guided":
        runner = GuidedRunner()
        executed = 0
        for agent in orchestrator.pipeline:
            result = runner.run_agent_guided(
                agent, dry_run=params["dry_run"], eve_log=params.get("eve_log")
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
            orchestrator, dry_run=params["dry_run"], eve_log=params.get("eve_log")
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
            dry_run=params["dry_run"],
            eve_log=params.get("eve_log"),
        )
        conv_path = _save_convergence(learn_results["convergence"])
        print(f"  📊 Données de convergence sauvées → {conv_path}\n")

    return 0


def run_direct(
    target: str,
    profile_name: str,
    dry_run: bool,
    eve_log: str | None,
    mode: str,
    cycles: int,
    use_llm: bool = True,
) -> int:
    """Direct CLI mode (non-interactive)."""
    profile, ptt, orchestrator = _build_orchestrator(
        target, profile_name, eve_log, use_llm=use_llm
    )

    print_banner(__version__)
    setup_logging()
    print_config_box(
        target=target,
        profile=f"{profile.name} — {profile.description}",
        mode=mode if mode != "pipeline" else ("dry-run" if dry_run else "live"),
        cycles=cycles if mode == "learn" else None,
        eve_log=eve_log,
    )

    if mode == "learn":
        runner = LearningRunner()
        learn_results = runner.run(
            orchestrator, cycles=cycles, dry_run=dry_run, eve_log=eve_log
        )
        conv_path = _save_convergence(learn_results["convergence"])
        print(f"  📊 Données de convergence sauvées → {conv_path}\n")
        return 0

    runner = AutonomousRunner()
    runner.run_pipeline(orchestrator, dry_run=dry_run, eve_log=eve_log)
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
    parser.add_argument("--dry-run", action="store_true", help="Simulate without network")
    parser.add_argument("--eve-log", default=None, help="Path to Suricata eve.json")
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

    try:
        if args.train_offline:
            return run_train_offline(args.train_offline, cycles=args.cycles)

        if args.finetune:
            return run_finetune(
                qtable_path=args.finetune,
                target=args.target or "192.168.100.11",
                profile_name=args.profile,
                eve_log=args.eve_log,
                cycles=args.cycles,
                use_llm=not args.no_llm,
            )

        if args.target:
            return run_direct(
                target=args.target,
                profile_name=args.profile,
                dry_run=args.dry_run,
                eve_log=args.eve_log,
                mode=args.mode,
                cycles=args.cycles,
                use_llm=not args.no_llm,
            )
        return run_interactive(use_llm=not args.no_llm)
    except KeyboardInterrupt:
        print(f"\n\n  {Color.DIM}Interrompu. À bientôt.{Color.RESET}\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
