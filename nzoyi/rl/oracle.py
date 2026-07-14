"""Random-Forest oracle simulating the IDS during offline RL training.

During offline pre-training we cannot query a real Suricata instance for every
Q-Learning step (far too slow). Instead we use a Random Forest classifier
previously trained on the UNSW-NB15 dataset as a fast surrogate that maps an
evasion state to a detection probability ``P(detect)``.

The mapping from the discretized :class:`~nzoyi.rl.qlearning.EvasionState` to
the feature vector expected by the RF (function ``φ``) is configurable via a
JSON calibration file so the exact feature names/order used at training time
can be reproduced without hard-coding them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nzoyi.rl.qlearning import EvasionState

DEFAULT_FEATURES: tuple[str, ...] = ("rate", "delay", "frag")
DEFAULT_RATE_SCALE = 20.0    # timing bucket -> packets/s
DEFAULT_DELAY_SCALE = 100.0  # delay bucket -> milliseconds


class RFOracle:
    """Fast IDS surrogate backed by a scikit-learn Random Forest."""

    def __init__(self, model_path: str, phi_config_path: str | None = None) -> None:
        """Load the trained model and the optional φ calibration.

        Args:
            model_path: Path to a joblib-serialized scikit-learn model exposing
                ``predict_proba``.
            phi_config_path: Optional path to a JSON file overriding the feature
                mapping. Recognised keys: ``features`` (ordered list among
                ``rate``/``delay``/``frag``), ``rate_scale`` and ``delay_scale``.

        Raises:
            FileNotFoundError: If ``model_path`` (or a provided config path)
                does not exist.
            RuntimeError: If joblib/scikit-learn are unavailable.
        """
        model_file = Path(model_path)
        if not model_file.is_file():
            raise FileNotFoundError(
                f"RF model introuvable: '{model_path}'. Fournis le chemin vers "
                "un modèle scikit-learn sérialisé avec joblib (joblib.dump)."
            )

        try:
            import joblib
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise RuntimeError(
                "joblib est requis pour charger l'oracle RF. "
                "Installe-le via `pip install joblib scikit-learn`."
            ) from exc

        self.model_path = str(model_file)
        self.model = joblib.load(self.model_path)

        self.feature_names: list[str] = list(DEFAULT_FEATURES)
        self.rate_scale: float = DEFAULT_RATE_SCALE
        self.delay_scale: float = DEFAULT_DELAY_SCALE
        if phi_config_path is not None:
            self._load_config(phi_config_path)

    def _load_config(self, phi_config_path: str) -> None:
        config_file = Path(phi_config_path)
        if not config_file.is_file():
            raise FileNotFoundError(
                f"Fichier de calibration φ introuvable: '{phi_config_path}'."
            )
        with open(config_file, encoding="utf-8") as handle:
            config: dict[str, Any] = json.load(handle)

        features = config.get("features")
        if features:
            self.feature_names = list(features)
        if "rate_scale" in config:
            self.rate_scale = float(config["rate_scale"])
        if "delay_scale" in config:
            self.delay_scale = float(config["delay_scale"])

    def phi(self, state: EvasionState) -> list[float]:
        """Map an evasion state to the RF feature vector.

        Default mapping (overridable via the calibration JSON)::

            rate  = timing * rate_scale       # paquets/s (defaut scale 20.0)
            delay = delay_bucket * delay_scale # ms        (defaut scale 100)
            frag  = float(fragment)

        The returned list follows ``self.feature_names`` order EXACTLY so it
        matches the column ordering used to train the Random Forest. Adjust the
        calibration file if the training pipeline used a different order.

        Args:
            state: The evasion state to encode.

        Returns:
            The ordered feature vector as a list of floats.
        """
        values: dict[str, float] = {
            "rate": state.timing * self.rate_scale,
            "delay": state.delay_bucket * self.delay_scale,
            "frag": float(state.fragment),
        }
        try:
            return [values[name] for name in self.feature_names]
        except KeyError as exc:
            raise KeyError(
                f"Feature inconnue {exc} dans la calibration φ. "
                f"Features disponibles: {sorted(values)}."
            ) from exc

    def predict_p_detect(self, state: EvasionState) -> float:
        """Return ``P(detect)`` for a state via the RF ``predict_proba``.

        Args:
            state: The evasion state to evaluate.

        Returns:
            The probability of detection in ``[0, 1]`` (positive class).
        """
        proba = self.model.predict_proba([self.phi(state)])
        return float(proba[0][1])

    def precompute_all(self) -> dict[tuple[int, int, int], float]:
        """Precompute ``P(detect)`` for the full discretized state space.

        The state space has 6 timing buckets (0-5) × 6 delay buckets (0-5) ×
        2 fragment values (0-1) = 72 states. Precomputing avoids calling the RF
        inside the hot training loop.

        Returns:
            A dict mapping ``state.as_key()`` tuples to detection probabilities.
        """
        table: dict[tuple[int, int, int], float] = {}
        for timing in range(6):
            for delay_bucket in range(6):
                for fragment in range(2):
                    state = EvasionState(
                        timing=timing,
                        delay_bucket=delay_bucket,
                        fragment=fragment,
                    )
                    table[state.as_key()] = self.predict_p_detect(state)
        return table
