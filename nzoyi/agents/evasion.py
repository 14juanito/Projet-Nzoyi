"""Evasion agent — Q-Learning parameter adaptation."""

from __future__ import annotations

import logging
import random
from typing import Any

from nzoyi.agents.base import BaseAgent
from nzoyi.rl.qlearning import EvasionQLearner, EvasionState

logger = logging.getLogger("nzoyi.agents.evasion")


class EvasionAgent(BaseAgent):
    name = "evasion"

    def __init__(self, ptt, profile, learner: EvasionQLearner | None = None) -> None:
        super().__init__(ptt, profile)
        self.learner = learner or EvasionQLearner()
        self._last_state: EvasionState | None = None
        self._last_action = None

    def _initial_state(self) -> EvasionState:
        timing_map = {"T2": 2, "T3": 3, "T4": 4}
        return EvasionState(
            timing=timing_map.get(self.profile.nmap_timing, 3),
            delay_bucket=min(5, self.profile.scan_delay_ms // 100),
            fragment=int(self.profile.packet_fragment),
        )

    def run(self, dry_run: bool = False, detected: bool | None = None) -> dict[str, Any]:
        rng = random.Random(42 + self.learner.iterations)
        state = self._initial_state()
        if self._last_state is not None:
            state = self._last_state

        action = self.learner.choose_action(state, rng)
        next_state = self.learner.apply_action(state, action)
        self._last_state = next_state
        self._last_action = action

        if detected is None:
            detected = (
                next_state.timing >= 4
                and next_state.delay_bucket <= 1
                and next_state.fragment == 0
            )

        reward = -1.0 if detected else 1.0

        result = {
            "action": action.name,
            "state": state.as_key(),
            "next_state": next_state.as_key(),
            "detected": detected,
            "reward": reward,
            "epsilon": round(self.learner.epsilon, 4),
            "dry_run": dry_run,
        }
        self.ptt.update_evasion_strategy(
            {"state": next_state.as_key(), "action": action.name, "epsilon": self.learner.epsilon}
        )
        self.ptt.add(self.name, "evasion_step", result, allow_duplicate=True)
        return result

    def learn(self, detected: bool) -> dict[str, Any]:
        """Apply Q-Learning update from IDS feedback."""
        if self._last_state is None or self._last_action is None:
            state = self._initial_state()
            action = self.learner.choose_action(state, random.Random())
            next_state = self.learner.apply_action(state, action)
        else:
            state = self._last_state
            action = self._last_action
            next_state = state

        reward = -1.0 if detected else 1.0
        self.learner.update(state, action, reward, next_state)

        result = {
            "learned": True,
            "detected": detected,
            "reward": reward,
            "epsilon": round(self.learner.epsilon, 4),
            "iterations": self.learner.iterations,
        }
        logger.debug("Q-Learning update: reward=%.1f epsilon=%.4f", reward, self.learner.epsilon)
        return result
