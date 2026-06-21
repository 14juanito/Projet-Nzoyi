"""Evasion agent — Q-Learning parameter adaptation."""

from __future__ import annotations

import random
from typing import Any

from nzoyi.agents.base import BaseAgent
from nzoyi.rl.qlearning import EvasionQLearner, EvasionState


class EvasionAgent(BaseAgent):
    name = "evasion"

    def __init__(self, ptt, profile, learner: EvasionQLearner | None = None) -> None:
        super().__init__(ptt, profile)
        self.learner = learner or EvasionQLearner()

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        rng = random.Random(42)
        state = EvasionState(
            timing=3 if self.profile.nmap_timing == "T3" else 2,
            delay_bucket=min(5, self.profile.scan_delay_ms // 100),
            fragment=int(self.profile.packet_fragment),
        )
        action = self.learner.choose_action(state, rng)
        next_state = self.learner.apply_action(state, action)

        # Simulated IDS feedback: slower + fragmented scans reduce detection.
        detected = (
            next_state.timing >= 4
            and next_state.delay_bucket <= 1
            and next_state.fragment == 0
        )
        reward = 1.0 if not detected else -1.0
        self.learner.update(state, action, reward, next_state)

        result = {
            "action": action.name,
            "state": state.as_key(),
            "next_state": next_state.as_key(),
            "detected": detected,
            "reward": reward,
            "dry_run": dry_run,
        }
        self.ptt.add(self.name, "evasion_step", result)
        return result
