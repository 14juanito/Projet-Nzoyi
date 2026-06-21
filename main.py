#!/usr/bin/env python3
"""NZOYI entry point — multi-agent IDS evasion lab framework."""

from __future__ import annotations

import argparse
import json
import sys

from nzoyi import __version__
from nzoyi.agents.orchestrator import OrchestratorAgent
from nzoyi.core.config import load_profile
from nzoyi.core.ptt import PentestTree


def run_validation_tests() -> int:
    """Run the four built-in validation checks expected by the lab guide."""
    from tests.test_validation import run_all_tests

    results = run_all_tests()
    passed = sum(1 for ok in results.values() if ok)
    total = len(results)

    print("NZOYI validation tests")
    print("=" * 40)
    for name, ok in results.items():
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}")
    print("=" * 40)
    print(f"Result: {passed}/{total} tests passed")

    return 0 if passed == total else 1


def run_campaign(target: str, profile_name: str, dry_run: bool, eve_log: str | None) -> int:
    profile = load_profile(profile_name)
    ptt = PentestTree(target=target)
    orchestrator = OrchestratorAgent(ptt, profile, eve_log=eve_log)

    print(f"NZOYI v{__version__}")
    print(f"Target : {target}")
    print(f"Profile: {profile.name} ({profile.description})")
    print("-" * 40)

    report = orchestrator.run(dry_run=dry_run)
    print(json.dumps(report, indent=2, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NZOYI — adaptive multi-agent IDS evasion framework",
    )
    parser.add_argument("--test", action="store_true", help="Run validation tests (4/4 expected)")
    parser.add_argument("--target", default="192.168.100.11", help="Target IP address")
    parser.add_argument(
        "--profile",
        default="stealth",
        choices=["default", "stealth", "aggressive"],
        help="Attack timing profile",
    )
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
    parser.add_argument("--version", action="version", version=f"NZOYI {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.test:
        return run_validation_tests()

    return run_campaign(
        target=args.target,
        profile_name=args.profile,
        dry_run=args.dry_run,
        eve_log=args.eve_log,
    )


if __name__ == "__main__":
    sys.exit(main())
