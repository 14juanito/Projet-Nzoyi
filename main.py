#!/usr/bin/env python3
"""NZOYI entry point — multi-agent IDS evasion lab framework."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from nzoyi import __version__
from nzoyi.agents.orchestrator import OrchestratorAgent
from nzoyi.core.config import load_profile
from nzoyi.core.ptt import PentestTree
from nzoyi.ui import (
    print_agent_status,
    print_banner,
    print_config_box,
    print_result_box,
    print_test_result,
    setup_logging,
)


def run_validation_tests() -> int:
    """Run the built-in validation checks."""
    from tests.test_validation import run_all_tests

    print_banner(__version__)
    setup_logging("WARNING")

    results = run_all_tests()
    passed = sum(1 for ok in results.values() if ok)
    total = len(results)

    print("NZOYI validation tests")
    print("=" * 40)
    for name, ok in results.items():
        print_test_result(name, ok)
    print("=" * 40)
    print(f"Result: {passed}/{total} tests passed")

    return 0 if passed == total else 1


def run_campaign(
    target: str,
    profile_name: str,
    dry_run: bool,
    eve_log: str | None,
    mode: str,
    cycles: int,
) -> int:
    logger = setup_logging()
    profile = load_profile(profile_name)
    ptt = PentestTree(target=target)

    print_banner(__version__)
    print_config_box(target, profile.name, mode, cycles, eve_log)

    orchestrator = OrchestratorAgent(
        ptt,
        profile,
        eve_log=eve_log,
        on_agent_status=print_agent_status,
    )

    if mode == "learn":
        logger.info("Starting learning loop (%d cycles)", cycles)
        report = orchestrator.learning_loop(cycles=cycles, dry_run=dry_run)
        print_result_box("Learning Loop Complete", {
            "cycles": report["cycles"],
            "final_detection_rate": report["final_detection_rate"],
            "qtable": report["qtable_path"],
            "convergence": report["convergence_path"],
        })
    else:
        report = orchestrator.run(dry_run=dry_run)
        print_result_box("Pipeline Results", report["ptt"])

    return 0


def run_dashboard() -> int:
    app_path = Path(__file__).parent / "nzoyi" / "dashboard" / "app.py"
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(app_path)],
        check=False,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NZOYI — adaptive multi-agent IDS evasion framework",
    )
    parser.add_argument("--test", action="store_true", help="Run validation tests")
    parser.add_argument("--target", default="192.168.100.11", help="Target IP address")
    parser.add_argument(
        "--profile",
        default="stealth",
        choices=["default", "stealth", "aggressive"],
        help="Attack timing profile",
    )
    parser.add_argument(
        "--mode",
        default="pipeline",
        choices=["pipeline", "learn"],
        help="Execution mode: single pipeline or RL learning loop",
    )
    parser.add_argument("--cycles", type=int, default=100, help="Learning loop iterations")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the pipeline without live network actions",
    )
    parser.add_argument(
        "--eve-log",
        default=None,
        help="Path to Suricata eve.json for IDS feedback (PC 2)",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch Streamlit supervision dashboard",
    )
    parser.add_argument("--version", action="version", version=f"NZOYI {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dashboard:
        return run_dashboard()

    if args.test:
        return run_validation_tests()

    return run_campaign(
        target=args.target,
        profile_name=args.profile,
        dry_run=args.dry_run,
        eve_log=args.eve_log,
        mode=args.mode,
        cycles=args.cycles,
    )


if __name__ == "__main__":
    sys.exit(main())
