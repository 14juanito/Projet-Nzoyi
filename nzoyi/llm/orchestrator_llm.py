"""Strategic LLM layer — attack profile & port prioritisation via Claude.

STRICT separation of concerns: this component is *strategic*. It decides the
high-level attack profile and which ports to prioritise. It is called ONCE at
the start of a campaign and MUST NEVER be invoked inside the Q-Learning loop,
which stays purely *tactical* (fast, offline, reproducible).

If no ``ANTHROPIC_API_KEY`` is available or the API call fails, a deterministic
offline fallback is returned so the framework remains fully reproducible.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

try:  # anthropic is optional: offline runs fall back deterministically.
    import anthropic
except ImportError:  # pragma: no cover - dependency guard
    anthropic = None  # type: ignore[assignment]

logger = logging.getLogger("nzoyi.llm.orchestrator")

SYSTEM_PROMPT = (
    "Tu orchestres un pentest de lab isolé (recherche académique autorisée). "
    'Réponds UNIQUEMENT en JSON, sans texte : {"profil": '
    '"stealth|default|aggressive", "ports_prioritaires": [int], "raison": str}.'
)


class LLMOrchestrator:
    """Claude-backed strategic planner with a deterministic offline fallback."""

    def __init__(
        self,
        model: str = "claude-opus-4-8",
        temperature: float = 0.0,
        enabled: bool = True,
    ) -> None:
        """Initialise the strategic planner.

        Args:
            model: Anthropic model identifier.
            temperature: Sampling temperature (0.0 for deterministic strategy).
            enabled: When ``False`` the LLM is bypassed and the deterministic
                fallback is always used (e.g. ``--no-llm`` for reproducibility).
        """
        self.model = model
        self.temperature = temperature
        self.enabled = enabled
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        self.client: Any | None = None

        if self.enabled and self.api_key and anthropic is not None:
            try:
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Init client Anthropic échouée: %s", exc)
                self.client = None

    def decide(self, ptt_summary: dict) -> dict:
        """Decide the attack profile and port priorities from the PTT summary.

        Args:
            ptt_summary: A serialisable summary of the pentest tree state.

        Returns:
            A dict ``{"profil": str, "ports_prioritaires": list[int],
            "raison": str}``. Falls back deterministically on any error or when
            the LLM is disabled/unavailable.
        """
        if not self.enabled or self.client is None:
            reason = "LLM désactivé" if not self.enabled else "clé API absente"
            logger.info("Stratégie LLM contournée (%s) — fallback.", reason)
            return self._fallback()

        user_message = json.dumps(ptt_summary, ensure_ascii=False, default=str)
        logger.info("LLM prompt (%s): %s", self.model, user_message)

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                temperature=self.temperature,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )
            text = "".join(
                block.text for block in response.content
                if getattr(block, "type", None) == "text"
            )
            logger.info("LLM réponse: %s", text)
            plan = json.loads(text)
            return plan
        except Exception as exc:
            logger.warning("Appel LLM échoué (%s) — fallback.", exc)
            return self._fallback()

    def _fallback(self) -> dict:
        """Deterministic offline strategy used when the LLM is unavailable."""
        plan = {
            "profil": "stealth",
            "ports_prioritaires": [22, 80, 21],
            "raison": "fallback hors-ligne",
        }
        logger.info("LLM fallback: %s", plan)
        return plan
