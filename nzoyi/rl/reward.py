"""Reward shaping for the Evasion Agent's Q-Learning loop.

This module encodes the core hypothesis of the NZOYI evasion agent:

    H3 — Il existe un compromis discrétion / vitesse.
    Rester furtif (délais élevés, cadence lente, fragmentation) réduit la
    probabilité de détection par l'IDS mais coûte du temps. Aller vite réduit
    le coût temporel mais augmente le risque d'alerte. Le signal de récompense
    doit donc pénaliser À LA FOIS la détection (p_detect) ET la lenteur
    (time_cost) tout en récompensant le succès de l'attaque, de sorte que la
    politique apprise trouve le point d'équilibre plutôt qu'un extrême.
"""

from __future__ import annotations

from nzoyi.rl.qlearning import EvasionState


def compute_reward(
    state: EvasionState,
    p_detect: float,
    success: bool = False,
    w_detect: float = 1.5,
    w_time: float = 0.5,
    w_success: float = 1.0,
) -> float:
    """Compute the scalar reward for a single evasion transition.

    The reward balances the discretion/speed trade-off (hypothesis H3):

        r = w_success * success - w_detect * p_detect - w_time * time_cost

    where the temporal cost grows with the added delay and with how far the
    scan cadence is throttled below the fastest timing template::

        time_cost = (state.delay_bucket + (5 - state.timing)) / 10.0

    A stealthy state (large ``delay_bucket``, low ``timing``) drives
    ``time_cost`` up but is expected to drive ``p_detect`` down, so the agent
    is pushed toward the equilibrium between staying undetected and finishing
    quickly instead of collapsing to either extreme.

    Args:
        state: Discretized evasion parameters that produced this transition.
        p_detect: Estimated probability of IDS detection in ``[0, 1]``.
        success: Whether the underlying attack step succeeded.
        w_detect: Weight of the detection penalty.
        w_time: Weight of the temporal (speed) penalty.
        w_success: Weight of the success bonus.

    Returns:
        The scalar reward (higher is better).
    """
    time_cost = (state.delay_bucket + (5 - state.timing)) / 10.0
    return (
        w_success * float(success)
        - w_detect * float(p_detect)
        - w_time * time_cost
    )
