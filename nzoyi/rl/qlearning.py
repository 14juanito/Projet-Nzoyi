"""Tabular Q-Learning for the Evasion Agent."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Hashable


@dataclass(frozen=True)
class EvasionState:
    """Discretized scan parameters observed by the evasion agent."""

    timing: int
    delay_bucket: int
    fragment: int

    def as_key(self) -> Hashable:
        return (self.timing, self.delay_bucket, self.fragment)


@dataclass
class EvasionAction:
    """Single evasion adjustment the agent can apply."""

    name: str
    timing_delta: int = 0
    delay_delta: int = 0
    toggle_fragment: bool = False


DEFAULT_ACTIONS: tuple[EvasionAction, ...] = (
    EvasionAction("slow_down", timing_delta=-1, delay_delta=1),
    EvasionAction("speed_up", timing_delta=1, delay_delta=-1),
    EvasionAction("enable_fragment", toggle_fragment=True),
    EvasionAction("hold", timing_delta=0, delay_delta=0),
)


class EvasionQLearner:
    """Model-free Q-Learning for IDS evasion parameter tuning."""

    def __init__(
        self,
        alpha: float = 0.1,
        gamma: float = 0.9,
        epsilon: float = 0.2,
        actions: tuple[EvasionAction, ...] = DEFAULT_ACTIONS,
    ) -> None:
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        self.actions = actions
        self.q_table: dict[tuple[Hashable, str], float] = {}
        self._step = 0

    def _q(self, state: EvasionState, action_name: str) -> float:
        return self.q_table.get((state.as_key(), action_name), 0.0)

    def choose_action(self, state: EvasionState, rng) -> EvasionAction:
        if rng.random() < self.epsilon:
            return rng.choice(self.actions)

        best = max(self.actions, key=lambda action: self._q(state, action.name))
        return best

    def update(self, state: EvasionState, action: EvasionAction, reward: float, next_state: EvasionState) -> None:
        current = self._q(state, action.name)
        next_best = max(self._q(next_state, a.name) for a in self.actions)
        updated = current + self.alpha * (reward + self.gamma * next_best - current)
        self.q_table[(state.as_key(), action.name)] = updated
        self._step += 1

    def apply_action(self, state: EvasionState, action: EvasionAction) -> EvasionState:
        timing = max(0, min(5, state.timing + action.timing_delta))
        delay_bucket = max(0, min(5, state.delay_bucket + action.delay_delta))
        fragment = state.fragment
        if action.toggle_fragment:
            fragment = 1 - fragment
        return EvasionState(timing=timing, delay_bucket=delay_bucket, fragment=fragment)

    @property
    def iterations(self) -> int:
        return self._step
