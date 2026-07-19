"""Agent d'évasion — adaptation des paramètres réseau par Q-Learning."""

from __future__ import annotations

import logging
import random
from typing import Any

from nzoyi.agents.base import BaseAgent
from nzoyi.core import config
from nzoyi.rl.oracle import RFOracle
from nzoyi.rl.qlearning import EvasionAction, EvasionQLearner, EvasionState
from nzoyi.rl.reward import compute_reward

logger = logging.getLogger("nzoyi.agents.evasion")


class EvasionAgent(BaseAgent):
    name = "evasion"

    def __init__(
        self,
        ptt,
        profile,
        learner: EvasionQLearner | None = None,
        oracle: RFOracle | None = None,
    ) -> None:
        super().__init__(ptt, profile)
        self.learner = learner or EvasionQLearner()
        self.oracle = oracle if oracle is not None else self._load_oracle()
        # RL bookkeeping for a single transition s --a--> s':
        #   _last_prev_state  = s   (state the agent acted from)
        #   _last_action      = a   (action chosen in s)
        #   _last_state       = s'  (observed next state, also the start of the
        #                            next run() so the episode keeps progressing)
        self._last_prev_state: EvasionState | None = None
        self._last_action: EvasionAction | None = None
        self._last_state: EvasionState | None = None

    @staticmethod
    def _load_oracle() -> RFOracle | None:
        """Charge l'oracle RF une seule fois (chemin: config.rf_model_path).

        Renvoie ``None`` (avec un warning) si le modèle est introuvable ou si
        les dépendances (joblib/scikit-learn) manquent, plutôt que de fabriquer
        une prédiction.
        """
        try:
            return RFOracle(config.rf_model_path)
        except (FileNotFoundError, RuntimeError) as exc:
            logger.warning(
                "Oracle RF indisponible (%s) — p_detect neutre (0.0) utilisé.", exc
            )
            return None

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
        # Remember the full transition AFTER choosing the action so learn() can
        # perform a correct update(s, a, r, s'). _last_state becomes s' so the
        # next run() continues the episode from the observed next state.
        self._last_prev_state = state
        self._last_action = action
        self._last_state = next_state

        if detected is None:
            if self.oracle is not None:
                p_detect = self.oracle.predict_p_detect(next_state)
            else:
                p_detect = 0.0
            detected = p_detect >= config.rf_threshold
        else:
            p_detect = 1.0 if detected else 0.0

        reward = compute_reward(next_state, p_detect)

        result = {
            "action": action.name,
            "state": state.as_key(),
            "next_state": next_state.as_key(),
            "detected": detected,
            "p_detect": p_detect,
            "reward": reward,
            "epsilon": round(self.learner.epsilon, 4),
            "dry_run": dry_run,
        }
        self.ptt.update_evasion_strategy(
            {"state": next_state.as_key(), "action": action.name, "epsilon": self.learner.epsilon}
        )
        self.ptt.add(self.name, "evasion_step", result, allow_duplicate=True)
        return result

    def learn(
        self, observed_detected: bool, p_detect: float | None = None
    ) -> dict[str, Any]:
        """Apply a Q-Learning update from the observed IDS feedback.

        Uses the *real* transition recorded during :meth:`run` — the action
        was chosen in ``s`` (``self._last_prev_state``) and led to the observed
        next state ``s'`` (``self._last_state``). The reward is shaped by
        :func:`compute_reward` from the detection probability.

        Args:
            observed_detected: Whether the IDS raised an alert for the step.
            p_detect: Detection probability in ``[0, 1]``. When ``None`` it is
                derived from ``observed_detected`` (1.0 if detected else 0.0)
                for backward compatibility with the binary simulation.

        Returns:
            A summary dict with the applied reward and learner state.
        """
        if p_detect is None:
            p_detect = 1.0 if observed_detected else 0.0

        if self._last_prev_state is None or self._last_action is None:
            # No transition recorded yet: bootstrap one from the initial state.
            state = self._initial_state()
            action = self.learner.choose_action(state, random.Random())
            next_state = self.learner.apply_action(state, action)
        else:
            state = self._last_prev_state
            action = self._last_action
            next_state = self._last_state if self._last_state is not None else state

        reward = compute_reward(next_state, p_detect)
        self.learner.update(state, action, reward, next_state)

        result = {
            "learned": True,
            "detected": observed_detected,
            "p_detect": p_detect,
            "reward": reward,
            "epsilon": round(self.learner.epsilon, 4),
            "iterations": self.learner.iterations,
        }
        logger.debug(
            "Q-Learning update: p_detect=%.3f reward=%.3f epsilon=%.4f",
            p_detect, reward, self.learner.epsilon,
        )
        return result
