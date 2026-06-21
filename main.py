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


def run_dashboard() -> int:
    app_path = Path(__file__).parent / "nzoyi" / "dashboard" / "app.py"
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(app_path)],
        check=False,
    )
    return 0


def _build_orchestrator(target: str, profile_name: str, eve_log: str | None):
    profile = load_profile(profile_name)
    ptt = PentestTree(target=target)
    orchestrator = OrchestratorAgent(ptt, profile, eve_log=eve_log)
    return profile, ptt, orchestrator


def run_interactive() -> int:
    """Interactive mode — the default user experience."""
    session = InteractiveSession(version=__version__)
    params = session.start()
    if not params:
        return 0

    profile, ptt, orchestrator = _build_orchestrator(
        params["target"], params["profile"], params.get("eve_log")
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
) -> int:
    """Direct CLI mode (non-interactive)."""
    profile, ptt, orchestrator = _build_orchestrator(target, profile_name, eve_log)

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
    parser.add_argument("--version", action="version", version=f"NZOYI {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dashboard:
        return run_dashboard()

    if args.test:
        return run_validation_tests()

    try:
        if args.target:
            return run_direct(
                target=args.target,
                profile_name=args.profile,
                dry_run=args.dry_run,
                eve_log=args.eve_log,
                mode=args.mode,
                cycles=args.cycles,
            )
        return run_interactive()
    except KeyboardInterrupt:
        print(f"\n\n  {Color.DIM}Interrompu. À bientôt.{Color.RESET}\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
