"""Offline pre-training of the evasion Q-Learner against the RF oracle.

This phase is deliberately network-free: it drives the tabular Q-Learner with
detection probabilities served by :class:`~nzoyi.rl.oracle.RFOracle` (a Random
Forest trained on UNSW-NB15). Because the whole 72-state space is precomputed
once, thousands of episodes run in seconds and produce a warm Q-table that is
later fine-tuned online against a real Suricata instance.
"""

from __future__ import annotations

import json
import logging
import random
from pathlib import Path
from typing import Any

from nzoyi.rl.oracle import RFOracle
from nzoyi.rl.qlearning import EvasionQLearner, EvasionState
from nzoyi.rl.reward import compute_reward

logger = logging.getLogger("nzoyi.training.offline")

RESULTS_DIR = Path("results")


def _random_state(rng: random.Random) -> EvasionState:
    """Sample a uniformly random starting state from the discretized space."""
    return EvasionState(
        timing=rng.randint(0, 5),
        delay_bucket=rng.randint(0, 5),
        fragment=rng.randint(0, 1),
    )


def pretrain(
    model_path: str,
    episodes: int = 3000,
    steps_per_ep: int = 20,
    alpha: float = 0.1,
    gamma: float = 0.9,
    epsilon: float = 0.3,
    seed: int = 42,
) -> EvasionQLearner:
    """Pre-train the evasion Q-Learner offline using the RF oracle.

    Args:
        model_path: Path to the joblib RF model consumed by :class:`RFOracle`.
        episodes: Number of training episodes.
        steps_per_ep: Steps (transitions) per episode.
        alpha: Q-Learning learning rate.
        gamma: Discount factor.
        epsilon: Initial exploration rate.
        seed: RNG seed for reproducibility.

    Returns:
        The trained :class:`EvasionQLearner` (also persisted to disk).
    """
    rng = random.Random(seed)
    oracle = RFOracle(model_path)
    # Precompute the full state space once; the hot loop only does dict lookups.
    lookup = oracle.precompute_all()

    learner = EvasionQLearner(alpha=alpha, gamma=gamma, epsilon=epsilon)

    convergence: list[dict[str, Any]] = []

    for episode in range(1, episodes + 1):
        state = _random_state(rng)
        rewards: list[float] = []
        detections = 0
        last_p_detect = 0.0

        for _ in range(steps_per_ep):
            action = learner.choose_action(state, rng)
            next_state = learner.apply_action(state, action)
            p_detect = lookup[next_state.as_key()]
            reward = compute_reward(next_state, p_detect)
            learner.update(state, action, reward, next_state)

            rewards.append(reward)
            last_p_detect = p_detect
            if p_detect >= 0.5:
                detections += 1
            state = next_state

        avg_reward = sum(rewards) / len(rewards) if rewards else 0.0
        detection_rate = detections / steps_per_ep if steps_per_ep else 0.0
        entry = {
            "episode": episode,
            "avg_reward": round(avg_reward, 4),
            "final_p_detect": round(last_p_detect, 4),
            "detection_rate": round(detection_rate, 4),
            "epsilon": round(learner.epsilon, 4),
            "final_state": list(state.as_key()),
        }

        if episode % 100 == 0 or episode == episodes:
            convergence.append(entry)
            logger.info(
                "Episode %d/%d — avg_reward=%.3f P(detect)_final=%.3f "
                "epsilon=%.4f final_state=%s",
                episode, episodes, avg_reward, last_p_detect,
                learner.epsilon, state.as_key(),
            )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    qtable_path = RESULTS_DIR / "qtable_offline.json"
    convergence_path = RESULTS_DIR / "convergence_offline.json"
    learner.save(qtable_path)
    with open(convergence_path, "w", encoding="utf-8") as handle:
        json.dump(convergence, handle, indent=2)

    logger.info(
        "Pré-entraînement terminé: %d épisodes → %s", episodes, qtable_path
    )
    return learner
