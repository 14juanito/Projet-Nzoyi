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

VALID_PROFILES = {"stealth", "default", "aggressive"}
MIN_CYCLES = 10
MAX_CYCLES = 500
DEFAULT_CYCLES = 100
DEFAULT_PORTS = [22, 80, 21]

SYSTEM_PROMPT = (
    "Tu orchestres un pentest de lab isolé (recherche académique autorisée). "
    "Tu es la couche STRATÉGIQUE : tu choisis le profil d'attaque et les cibles "
    "prioritaires, tu ne calcules jamais de récompense ni d'action d'évasion "
    "(cela reste au Q-Learning). Réponds UNIQUEMENT en JSON, sans texte, avec "
    'exactement ce schéma : {"profil": "stealth|default|aggressive", '
    '"ports_cibles": [int], "services_focus": [str], '
    '"lancer_boucle_evasion": bool, "cycles": int, "raison": str}.'
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
            Un plan validé au schéma ``{"profil": str, "ports_cibles": list[int],
            "services_focus": list[str], "lancer_boucle_evasion": bool,
            "cycles": int, "raison": str}``. Repli déterministe sur toute erreur
            ou quand la couche LLM est désactivée/indisponible.
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
            plan = self._sanitize(json.loads(text))
            return plan
        except Exception as exc:
            logger.warning("Appel LLM échoué (%s) — fallback.", exc)
            return self._fallback()

    @staticmethod
    def _sanitize(plan: dict) -> dict:
        """Valide et normalise un plan brut (venant du LLM ou d'ailleurs).

        Garantit que le plan renvoyé respecte toujours le schéma attendu par
        :class:`~nzoyi.agents.orchestrator.OrchestratorAgent`, même si la
        réponse du LLM est incomplète ou malformée.
        """
        raw = plan if isinstance(plan, dict) else {}

        profil = raw.get("profil")
        if profil not in VALID_PROFILES:
            profil = "stealth"

        ports_cibles_raw = raw.get("ports_cibles")
        if isinstance(ports_cibles_raw, list) and ports_cibles_raw:
            try:
                ports_cibles = [int(p) for p in ports_cibles_raw]
            except (TypeError, ValueError):
                ports_cibles = list(DEFAULT_PORTS)
        else:
            ports_cibles = list(DEFAULT_PORTS)

        services_focus_raw = raw.get("services_focus")
        if isinstance(services_focus_raw, list) and all(
            isinstance(s, str) for s in services_focus_raw
        ):
            services_focus = list(services_focus_raw)
        else:
            services_focus = []

        lancer_boucle_evasion = raw.get("lancer_boucle_evasion")
        if not isinstance(lancer_boucle_evasion, bool):
            lancer_boucle_evasion = True

        try:
            cycles = int(raw.get("cycles", DEFAULT_CYCLES))
        except (TypeError, ValueError):
            cycles = DEFAULT_CYCLES
        cycles = max(MIN_CYCLES, min(MAX_CYCLES, cycles))

        raison = str(raw.get("raison", ""))

        return {
            "profil": profil,
            "ports_cibles": ports_cibles,
            "services_focus": services_focus,
            "lancer_boucle_evasion": lancer_boucle_evasion,
            "cycles": cycles,
            "raison": raison,
        }

    def _fallback(self) -> dict:
        """Stratégie déterministe hors-ligne utilisée quand le LLM est indisponible."""
        plan = self._sanitize({
            "profil": "stealth",
            "ports_cibles": DEFAULT_PORTS,
            "services_focus": [],
            "lancer_boucle_evasion": True,
            "cycles": DEFAULT_CYCLES,
            "raison": "fallback hors-ligne",
        })
        logger.info("LLM fallback: %s", plan)
        return plan
