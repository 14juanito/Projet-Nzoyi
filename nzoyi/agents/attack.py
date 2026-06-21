"""Attack execution agent."""

from __future__ import annotations

from typing import Any

from nzoyi.agents.base import BaseAgent


class AttackAgent(BaseAgent):
    name = "attack"

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        result = {
            "actions": ["ssh_bruteforce_probe", "ftp_anonymous_check"],
            "executed": not dry_run,
            "dry_run": dry_run,
        }
        self.ptt.add(self.name, "attack_plan", result)
        return result
